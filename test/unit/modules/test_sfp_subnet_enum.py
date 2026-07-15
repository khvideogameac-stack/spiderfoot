import pytest
import unittest

from modules.sfp_subnet_enum import sfp_subnet_enum
from sflib import SpiderFoot
from spiderfoot import SpiderFootEvent, SpiderFootTarget


@pytest.mark.usefixtures
class TestModuleSubnetEnum(unittest.TestCase):

    def _capture_module(self, opts):
        """Create a configured module that captures emitted events."""
        sf = SpiderFoot(self.default_options)
        module = sfp_subnet_enum()
        # Pass a complete opts dict so behaviour is deterministic regardless
        # of test order (module opts are stored on the class).
        full_opts = {'netblocklookup': True, 'maxnetblock': 24, 'maxv6netblock': 120}
        full_opts.update(opts)
        module.setup(sf, full_opts)

        emitted = []
        module.notifyListeners = lambda evt: emitted.append((evt.eventType, evt.data))
        module.checkForStop = lambda: False
        return module, emitted

    def _netblock_event(self, event_type, value):
        root = SpiderFootEvent("ROOT", value, "", None)
        return SpiderFootEvent(event_type, value, "sfp_test", root)

    def test_opts(self):
        module = sfp_subnet_enum()
        self.assertEqual(len(module.opts), len(module.optdescs))

    def test_setup(self):
        sf = SpiderFoot(self.default_options)
        module = sfp_subnet_enum()
        module.setup(sf, dict())

    def test_watchedEvents_should_return_list(self):
        module = sfp_subnet_enum()
        self.assertIsInstance(module.watchedEvents(), list)
        self.assertIn("NETBLOCK_OWNER", module.watchedEvents())
        self.assertIn("NETBLOCKV6_OWNER", module.watchedEvents())

    def test_producedEvents_should_return_list(self):
        module = sfp_subnet_enum()
        self.assertIsInstance(module.producedEvents(), list)
        self.assertIn("IP_ADDRESS", module.producedEvents())
        self.assertIn("IPV6_ADDRESS", module.producedEvents())

    def test_handleEvent_ipv4_netblock_should_emit_host_ips(self):
        module, emitted = self._capture_module({'maxnetblock': 24})
        target = SpiderFootTarget("192.168.1.0/30", "NETBLOCK_OWNER")
        module.setTarget(target)

        module.handleEvent(self._netblock_event("NETBLOCK_OWNER", "192.168.1.0/30"))

        # .0 is the network address and must be skipped; usable hosts emitted.
        self.assertIn(("IP_ADDRESS", "192.168.1.1"), emitted)
        self.assertIn(("IP_ADDRESS", "192.168.1.2"), emitted)
        self.assertNotIn(("IP_ADDRESS", "192.168.1.0"), emitted)
        self.assertTrue(all(t == "IP_ADDRESS" for t, _ in emitted))

    def test_handleEvent_netblock_larger_than_max_should_be_skipped(self):
        module, emitted = self._capture_module({'maxnetblock': 24})
        module.handleEvent(self._netblock_event("NETBLOCK_OWNER", "10.0.0.0/16"))
        self.assertEqual([], emitted)

    def test_handleEvent_netblocklookup_disabled_should_emit_nothing(self):
        module, emitted = self._capture_module({'netblocklookup': False})
        module.handleEvent(self._netblock_event("NETBLOCK_OWNER", "192.168.1.0/30"))
        self.assertEqual([], emitted)

    def test_handleEvent_ipv6_netblock_should_emit_ipv6_addresses(self):
        module, emitted = self._capture_module({'maxv6netblock': 120})
        module.handleEvent(self._netblock_event("NETBLOCKV6_OWNER", "2001:db8::/126"))
        self.assertEqual(4, len(emitted))
        self.assertTrue(all(t == "IPV6_ADDRESS" for t, _ in emitted))
        self.assertIn(("IPV6_ADDRESS", "2001:db8::1"), emitted)

    def test_handleEvent_duplicate_netblock_should_only_enumerate_once(self):
        module, emitted = self._capture_module({'maxnetblock': 24})
        evt = self._netblock_event("NETBLOCK_OWNER", "192.168.1.0/30")
        module.handleEvent(evt)
        first = len(emitted)
        self.assertGreater(first, 0)
        module.handleEvent(evt)
        self.assertEqual(first, len(emitted))
