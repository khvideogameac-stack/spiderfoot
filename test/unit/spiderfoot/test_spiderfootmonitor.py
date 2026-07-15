import os
import tempfile
import time
import unittest

import pytest

from spiderfoot import SpiderFootDb, SpiderFootEvent, SpiderFootMonitor


@pytest.mark.usefixtures
class TestSpiderFootMonitor(unittest.TestCase):

    def setUp(self):
        # Use an isolated temporary database so test scans don't collide with
        # any other scans on disk.
        fd, self.dbpath = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        os.remove(self.dbpath)  # let SpiderFootDb create a fresh schema
        self.opts = dict(self.default_options)
        self.opts['__database'] = self.dbpath
        self.dbh = SpiderFootDb(self.opts, init=True)
        self.monitor = SpiderFootMonitor(self.dbh)

    def tearDown(self):
        try:
            self.dbh.close()
        except Exception:
            pass
        if os.path.exists(self.dbpath):
            os.remove(self.dbpath)

    def _create_scan(self, scan_id, target, events, ended):
        """Create a finished scan with the given (type, data) events."""
        self.dbh.scanInstanceCreate(scan_id, f"scan-{scan_id}", target)
        root = SpiderFootEvent("ROOT", target, "", None)
        self.dbh.scanEventStore(scan_id, root)
        for etype, edata in events:
            evt = SpiderFootEvent(etype, edata, "sfp_test", root)
            self.dbh.scanEventStore(scan_id, evt)
        self.dbh.scanInstanceSet(scan_id, started=str(ended - 10), ended=str(ended), status="FINISHED")

    # ----- classification helpers -----

    def test_isAttackSurface(self):
        self.assertTrue(SpiderFootMonitor.isAttackSurface("TCP_PORT_OPEN"))
        self.assertTrue(SpiderFootMonitor.isAttackSurface("VULNERABILITY_CVE_CRITICAL"))
        self.assertTrue(SpiderFootMonitor.isAttackSurface("MALICIOUS_IPADDR"))
        self.assertFalse(SpiderFootMonitor.isAttackSurface("RAW_RIR_DATA"))
        self.assertFalse(SpiderFootMonitor.isAttackSurface("ROOT"))

    def test_isHighRisk(self):
        self.assertTrue(SpiderFootMonitor.isHighRisk("TCP_PORT_OPEN"))
        self.assertTrue(SpiderFootMonitor.isHighRisk("VULNERABILITY_CVE_HIGH"))
        self.assertTrue(SpiderFootMonitor.isHighRisk("BLACKLISTED_IPADDR"))
        self.assertFalse(SpiderFootMonitor.isHighRisk("INTERNET_NAME"))

    # ----- scansForTarget -----

    def test_scansForTarget_returns_finished_scans_newest_first(self):
        now = int(time.time())
        self._create_scan("scanA", "example.com", [("IP_ADDRESS", "1.1.1.1")], ended=now - 100)
        self._create_scan("scanB", "example.com", [("IP_ADDRESS", "1.1.1.1")], ended=now)

        scans = self.monitor.scansForTarget("example.com")
        self.assertEqual(2, len(scans))
        self.assertEqual("scanB", scans[0]['id'])  # newest first
        self.assertEqual("scanA", scans[1]['id'])

    def test_scansForTarget_matches_case_insensitively(self):
        now = int(time.time())
        self._create_scan("scanA", "Example.COM", [("IP_ADDRESS", "1.1.1.1")], ended=now)
        scans = self.monitor.scansForTarget("example.com")
        self.assertEqual(1, len(scans))

    # ----- attackSurfaceDiff -----

    def test_attackSurfaceDiff_none_when_fewer_than_two_scans(self):
        now = int(time.time())
        self._create_scan("scanA", "example.com", [("IP_ADDRESS", "1.1.1.1")], ended=now)
        self.assertIsNone(self.monitor.attackSurfaceDiff("example.com"))

    def test_attackSurfaceDiff_detects_added_and_removed(self):
        now = int(time.time())
        baseline = [
            ("IP_ADDRESS", "1.1.1.1"),
            ("TCP_PORT_OPEN", "1.1.1.1:22"),
            ("INTERNET_NAME", "www.example.com"),
        ]
        current = [
            ("IP_ADDRESS", "1.1.1.1"),
            ("TCP_PORT_OPEN", "1.1.1.1:22"),
            ("TCP_PORT_OPEN", "1.1.1.1:3389"),          # NEW open port (high risk)
            ("INTERNET_NAME", "vpn.example.com"),        # NEW host
            # www.example.com removed
        ]
        self._create_scan("old", "example.com", baseline, ended=now - 100)
        self._create_scan("new", "example.com", current, ended=now)

        diff = self.monitor.attackSurfaceDiff("example.com")
        self.assertEqual("new", diff['current_scan']['id'])
        self.assertEqual("old", diff['previous_scan']['id'])

        added = {(e['type'], e['data']) for e in diff['added']}
        removed = {(e['type'], e['data']) for e in diff['removed']}
        self.assertIn(("TCP_PORT_OPEN", "1.1.1.1:3389"), added)
        self.assertIn(("INTERNET_NAME", "vpn.example.com"), added)
        self.assertIn(("INTERNET_NAME", "www.example.com"), removed)
        self.assertNotIn(("IP_ADDRESS", "1.1.1.1"), added)  # unchanged

        high = {(e['type'], e['data']) for e in diff['high_risk_added']}
        self.assertIn(("TCP_PORT_OPEN", "1.1.1.1:3389"), high)
        self.assertNotIn(("INTERNET_NAME", "vpn.example.com"), high)

    def test_attackSurfaceDiff_flags_new_vulnerability_as_high_risk(self):
        now = int(time.time())
        self._create_scan("old", "example.com", [("IP_ADDRESS", "1.1.1.1")], ended=now - 100)
        self._create_scan("new", "example.com", [
            ("IP_ADDRESS", "1.1.1.1"),
            ("VULNERABILITY_CVE_CRITICAL", "CVE-2024-0001 (1.1.1.1)"),
        ], ended=now)

        diff = self.monitor.attackSurfaceDiff("example.com")
        self.assertEqual(1, len(diff['high_risk_added']))
        self.assertEqual("VULNERABILITY_CVE_CRITICAL", diff['high_risk_added'][0]['type'])

    def test_diffScans_only_attack_surface_by_default(self):
        now = int(time.time())
        # RAW_RIR_DATA is not attack surface and should be ignored by default.
        self._create_scan("old", "example.com", [("IP_ADDRESS", "1.1.1.1")], ended=now - 100)
        self._create_scan("new", "example.com", [
            ("IP_ADDRESS", "1.1.1.1"),
            ("RAW_RIR_DATA", "some blob"),
        ], ended=now)

        diff = self.monitor.diffScans("old", "new")
        added = {(e['type'], e['data']) for e in diff['added']}
        self.assertNotIn(("RAW_RIR_DATA", "some blob"), added)

        diff_all = self.monitor.diffScans("old", "new", onlyAttackSurface=False)
        added_all = {(e['type'], e['data']) for e in diff_all['added']}
        self.assertIn(("RAW_RIR_DATA", "some blob"), added_all)
