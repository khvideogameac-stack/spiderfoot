# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         monitor
# Purpose:      Continuous attack-surface monitoring for SpiderFoot.
#
#               Compares the results of successive scans of the same target and
#               surfaces how the target's externally-visible attack surface has
#               changed over time (new/removed hosts, open ports, services,
#               certificates, vulnerabilities and malicious/blacklist hits).
#
#               This is the "detect what changed" half of continuous attack
#               surface management (ASM); pair it with a scheduled re-scan
#               (e.g. cron running sf.py) for the "continuous" half.
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import typing


class SpiderFootMonitor():
    """Attack-surface change detection across SpiderFoot scans.

    Given a target that has been scanned more than once, this compares the two
    most recent completed scans and reports what has been added to or removed
    from the target's attack surface.
    """

    # Externally-visible attack-surface event types grouped by theme. These are
    # the elements that represent exposure and that a purple team cares about
    # tracking drift on over time.
    ATTACK_SURFACE_EVENTS = {
        # Hosts, names and network ranges
        "INTERNET_NAME", "DOMAIN_NAME", "IP_ADDRESS", "IPV6_ADDRESS",
        "NETBLOCK_OWNER", "NETBLOCKV6_OWNER", "CO_HOSTED_SITE",
        # Services / open ports
        "TCP_PORT_OPEN", "UDP_PORT_OPEN", "TCP_PORT_OPEN_BANNER",
        # Web / software exposure
        "WEBSERVER_BANNER", "WEBSERVER_TECHNOLOGY", "WEBSERVER_HTTPHEADERS",
        "URL_WEB_FRAMEWORK", "SOFTWARE_USED", "OPERATING_SYSTEM", "DEVICE_TYPE",
        # TLS
        "SSL_CERTIFICATE_ISSUED", "SSL_CERTIFICATE_EXPIRED",
        # Cloud storage exposure
        "CLOUD_STORAGE_BUCKET", "CLOUD_STORAGE_BUCKET_OPEN", "AMAZON_S3_BUCKET",
    }

    # Prefixes for event types that are inherently attack-surface relevant and
    # high-risk. Matched by prefix so new/variant event types are still caught.
    HIGH_RISK_PREFIXES = (
        "VULNERABILITY_",
        "MALICIOUS_",
        "BLACKLISTED_",
    )

    # Individual event types that are considered high-risk when newly appearing.
    HIGH_RISK_EVENTS = {
        "TCP_PORT_OPEN", "UDP_PORT_OPEN",
        "CLOUD_STORAGE_BUCKET_OPEN",
        "SSL_CERTIFICATE_EXPIRED",
    }

    def __init__(self, dbh) -> None:
        """Initialize the monitor.

        Args:
            dbh (SpiderFootDb): an initialised SpiderFoot database handle
        """
        self.dbh = dbh

    @classmethod
    def isAttackSurface(cls, eventType: str) -> bool:
        """Whether an event type represents externally-visible attack surface.

        Args:
            eventType (str): event type name

        Returns:
            bool: True if the event type is attack-surface relevant
        """
        if eventType in cls.ATTACK_SURFACE_EVENTS:
            return True
        return eventType.startswith(cls.HIGH_RISK_PREFIXES)

    @classmethod
    def isHighRisk(cls, eventType: str) -> bool:
        """Whether a newly-appearing event type warrants an alert.

        Args:
            eventType (str): event type name

        Returns:
            bool: True if the event type is high-risk
        """
        if eventType in cls.HIGH_RISK_EVENTS:
            return True
        return eventType.startswith(cls.HIGH_RISK_PREFIXES)

    def scansForTarget(self, target: str, finishedOnly: bool = True) -> typing.List[dict]:
        """List scans for a target, most recent first.

        Args:
            target (str): scan seed target to match (case-insensitive)
            finishedOnly (bool): only include scans that completed successfully

        Returns:
            list: scan info dicts with id, name, target, created, started,
            ended and status keys, ordered newest-ended first.
        """
        if not isinstance(target, str):
            raise TypeError(f"target is {type(target)}; expected str()")

        if not target:
            raise ValueError("target value is blank")

        target = target.strip().lower()

        scans = list()
        for row in self.dbh.scanInstanceList():
            # row: guid, name, seed_target, created, started, ended, status, count
            if str(row[2]).strip().lower() != target:
                continue
            if finishedOnly and row[6] != "FINISHED":
                continue
            scans.append({
                'id': row[0],
                'name': row[1],
                'target': row[2],
                'created': row[3],
                'started': row[4],
                'ended': row[5],
                'status': row[6],
            })

        # Newest ended first; fall back to created when ended is missing.
        scans.sort(key=lambda s: (s['ended'] or 0, s['created'] or 0), reverse=True)
        return scans

    def scanSurface(
        self,
        scanId: str,
        eventTypes: typing.Optional[typing.Iterable[str]] = None,
        onlyAttackSurface: bool = True,
    ) -> typing.Set[typing.Tuple[str, str]]:
        """Return the set of (eventType, data) elements found in a scan.

        Args:
            scanId (str): scan instance ID
            eventTypes (iterable): if given, restrict to these event types
            onlyAttackSurface (bool): restrict to attack-surface event types

        Returns:
            set: set of (eventType, data) tuples
        """
        if not isinstance(scanId, str):
            raise TypeError(f"scanId is {type(scanId)}; expected str()")

        typeFilter = set(eventTypes) if eventTypes is not None else None

        surface: typing.Set[typing.Tuple[str, str]] = set()
        for row in self.dbh.scanResultEventUnique(scanId):
            # row: data, type, count
            data, eventType = row[0], row[1]
            if eventType == "ROOT":
                continue
            if typeFilter is not None and eventType not in typeFilter:
                continue
            if onlyAttackSurface and not self.isAttackSurface(eventType):
                continue
            surface.add((eventType, data))

        return surface

    def diffScans(
        self,
        oldScanId: str,
        newScanId: str,
        eventTypes: typing.Optional[typing.Iterable[str]] = None,
        onlyAttackSurface: bool = True,
    ) -> dict:
        """Diff the attack surface between two scans.

        Args:
            oldScanId (str): the earlier (baseline) scan instance ID
            newScanId (str): the later (current) scan instance ID
            eventTypes (iterable): if given, restrict to these event types
            onlyAttackSurface (bool): restrict to attack-surface event types

        Returns:
            dict: with 'added', 'removed' and 'high_risk_added' lists. Each
            entry is a dict with 'type' and 'data' keys; added entries also
            carry a 'high_risk' boolean.
        """
        oldSurface = self.scanSurface(oldScanId, eventTypes, onlyAttackSurface)
        newSurface = self.scanSurface(newScanId, eventTypes, onlyAttackSurface)

        added = newSurface - oldSurface
        removed = oldSurface - newSurface

        def sortKey(item):
            return (item[0], item[1])

        added_list = [
            {'type': t, 'data': d, 'high_risk': self.isHighRisk(t)}
            for t, d in sorted(added, key=sortKey)
        ]
        removed_list = [
            {'type': t, 'data': d}
            for t, d in sorted(removed, key=sortKey)
        ]
        high_risk_added = [e for e in added_list if e['high_risk']]

        return {
            'added': added_list,
            'removed': removed_list,
            'high_risk_added': high_risk_added,
        }

    def attackSurfaceDiff(
        self,
        target: str,
        onlyAttackSurface: bool = True,
    ) -> typing.Optional[dict]:
        """Diff the two most recent completed scans of a target.

        Args:
            target (str): scan seed target
            onlyAttackSurface (bool): restrict to attack-surface event types

        Returns:
            dict or None: diff report, or None if fewer than two completed
            scans exist for the target. The report contains 'target',
            'previous_scan', 'current_scan', 'added', 'removed' and
            'high_risk_added'.
        """
        scans = self.scansForTarget(target, finishedOnly=True)
        if len(scans) < 2:
            return None

        current = scans[0]
        previous = scans[1]

        diff = self.diffScans(
            previous['id'], current['id'], onlyAttackSurface=onlyAttackSurface
        )
        diff['target'] = target
        diff['previous_scan'] = previous
        diff['current_scan'] = current
        return diff

# end of SpiderFootMonitor class
