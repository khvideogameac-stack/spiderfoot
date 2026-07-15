#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfmonitor
# Purpose:      Continuous attack-surface monitoring for SpiderFoot.
#
#               Reports how a target's externally-visible attack surface has
#               changed between its two most recent completed scans (or between
#               two explicitly-specified scans). Designed to be run on a
#               schedule (e.g. from cron, after a fresh scan) so drift in the
#               attack surface - new hosts, open ports, services, certificates,
#               vulnerabilities and malicious/blacklist hits - is surfaced for a
#               purple team to action.
#
#               Exit codes:
#                 0  no high-risk additions to the attack surface
#                 1  new high-risk attack surface detected (alert!)
#                 2  usage / data error (e.g. not enough scans to compare)
#
# Licence:      MIT
# -------------------------------------------------------------------------------

import argparse
import json
import sys

from spiderfoot import SpiderFootDb, SpiderFootHelpers, SpiderFootMonitor


def buildConfig() -> dict:
    """Minimal config needed to open the SpiderFoot database."""
    return {
        '__database': f"{SpiderFootHelpers.dataPath()}/spiderfoot.db",
    }


def formatText(report: dict) -> str:
    """Render a diff report as human-readable text."""
    lines = list()
    prev = report['previous_scan']
    curr = report['current_scan']

    lines.append(f"Attack surface change report for: {report['target']}")
    lines.append(f"  Baseline scan: {prev['id']} (ended {prev['ended']})")
    lines.append(f"  Current scan:  {curr['id']} (ended {curr['ended']})")
    lines.append("")

    added = report['added']
    removed = report['removed']
    high = report['high_risk_added']

    lines.append(f"NEW attack surface ({len(added)}):")
    if added:
        for e in added:
            marker = "  [!] " if e['high_risk'] else "      "
            lines.append(f"{marker}{e['type']}: {e['data']}")
    else:
        lines.append("      (none)")
    lines.append("")

    lines.append(f"REMOVED attack surface ({len(removed)}):")
    if removed:
        for e in removed:
            lines.append(f"      {e['type']}: {e['data']}")
    else:
        lines.append("      (none)")
    lines.append("")

    if high:
        lines.append(f"*** {len(high)} HIGH-RISK addition(s) require attention ***")
    else:
        lines.append("No high-risk additions detected.")

    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(
        description="Continuous attack-surface monitoring: report what changed between SpiderFoot scans."
    )
    p.add_argument("-t", "--target", metavar="TARGET",
                   help="Target to monitor. Compares its two most recent completed scans.")
    p.add_argument("--scan1", metavar="SCAN_ID",
                   help="Baseline scan ID (use with --scan2 to diff two explicit scans).")
    p.add_argument("--scan2", metavar="SCAN_ID",
                   help="Current scan ID (use with --scan1 to diff two explicit scans).")
    p.add_argument("-o", "--output", choices=["text", "json"], default="text",
                   help="Output format. Default is text.")
    p.add_argument("-a", "--all-events", action="store_true",
                   help="Compare all event types, not just attack-surface event types.")
    p.add_argument("-l", "--list", action="store_true",
                   help="List completed scans for the target and exit.")
    args = p.parse_args()

    if not args.target and not (args.scan1 and args.scan2):
        p.error("Specify a target with -t, or two scans with --scan1 and --scan2.")

    try:
        dbh = SpiderFootDb(buildConfig())
    except Exception as e:
        print(f"[-] Could not open the SpiderFoot database: {e}", file=sys.stderr)
        sys.exit(2)

    monitor = SpiderFootMonitor(dbh)
    onlyAttackSurface = not args.all_events

    # List mode
    if args.list:
        if not args.target:
            p.error("-l/--list requires -t/--target.")
        scans = monitor.scansForTarget(args.target, finishedOnly=True)
        if not scans:
            print(f"No completed scans found for target: {args.target}")
            sys.exit(2)
        for s in scans:
            print(f"{s['id']}\t{s['status']}\tended={s['ended']}\t{s['name']}")
        sys.exit(0)

    # Explicit two-scan diff
    if args.scan1 and args.scan2:
        diff = monitor.diffScans(args.scan1, args.scan2, onlyAttackSurface=onlyAttackSurface)
        report = {
            'target': args.target or f"{args.scan1}..{args.scan2}",
            'previous_scan': {'id': args.scan1, 'ended': None},
            'current_scan': {'id': args.scan2, 'ended': None},
            'added': diff['added'],
            'removed': diff['removed'],
            'high_risk_added': diff['high_risk_added'],
        }
    else:
        report = monitor.attackSurfaceDiff(args.target, onlyAttackSurface=onlyAttackSurface)
        if report is None:
            print(
                f"[-] Need at least two completed scans of '{args.target}' to compare. "
                "Run another scan first.",
                file=sys.stderr,
            )
            sys.exit(2)

    if args.output == "json":
        print(json.dumps(report, indent=2, default=str))
    else:
        print(formatText(report))

    # Alerting: non-zero exit when new high-risk attack surface appears.
    sys.exit(1 if report['high_risk_added'] else 0)


if __name__ == "__main__":
    main()
