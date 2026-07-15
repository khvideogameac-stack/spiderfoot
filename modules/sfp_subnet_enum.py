# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_subnet_enum
# Purpose:      Enumerate every host in a target IP subnet (netblock) as
#               individual IP_ADDRESS / IPV6_ADDRESS events so that all
#               IP-based modules (reputation/threat-intel APIs such as SHODAN,
#               AlienVault OTX, Pulsedive, GreyNoise, AbuseIPDB, etc.) check
#               the whole subnet, not just the hosts that happen to have
#               reverse DNS records.
#
# Author:      SpiderFoot
#
# Created:     2026-07-15
# Copyright:   (c) SpiderFoot
# Licence:     MIT
# -------------------------------------------------------------------------------

from netaddr import IPNetwork

from spiderfoot import SpiderFootEvent, SpiderFootPlugin


class sfp_subnet_enum(SpiderFootPlugin):

    meta = {
        'name': "Subnet Enumerator",
        'summary': "Enumerate every IP address in a target subnet (netblock) so that all IP-based modules (reputation/threat-intel APIs) check the entire subnet, not only hosts with reverse DNS.",
        'flags': [],
        'useCases': ["Footprint", "Investigate", "Passive"],
        'categories': ["Crawling and Scanning"]
    }

    # Default options
    opts = {
        'netblocklookup': True,
        'maxnetblock': 24,
        'maxv6netblock': 120
    }

    # Option descriptions
    optdescs = {
        'netblocklookup': "Enumerate all IPs within netblocks deemed to be owned by your target so that every host is checked by IP-based modules?",
        'maxnetblock': "If enumerating netblocks, the maximum IPv4 netblock size to enumerate all IPs within (CIDR value, 24 = /24, 16 = /16, etc.)",
        'maxv6netblock': "If enumerating netblocks, the maximum IPv6 netblock size to enumerate all IPs within (CIDR value, 120 = /120, 112 = /112, etc.)"
    }

    results = None
    errorState = False

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["NETBLOCK_OWNER", "NETBLOCKV6_OWNER"]

    # What events this module produces
    def producedEvents(self):
        return ["IP_ADDRESS", "IPV6_ADDRESS"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if self.errorState:
            return

        self.debug(f"Received event, {eventName}, from {srcModuleName}")

        if eventData in self.results:
            self.debug(f"Skipping {eventData}, already enumerated.")
            return

        self.results[eventData] = True

        if not self.opts['netblocklookup']:
            return

        if eventName == 'NETBLOCKV6_OWNER':
            max_netblock = self.opts['maxv6netblock']
            childType = "IPV6_ADDRESS"
        else:
            max_netblock = self.opts['maxnetblock']
            childType = "IP_ADDRESS"

        net = IPNetwork(eventData)
        if net.prefixlen < max_netblock:
            self.debug(f"Network size ({net.prefixlen}) bigger than permitted: {max_netblock}")
            return

        self.info(f"Enumerating {net.size} host(s) in owned netblock: {eventData}")

        for ip in net:
            if self.checkForStop():
                return

            ipaddr = str(ip)

            # Skip the network and broadcast addresses for IPv4 subnets
            if childType == "IP_ADDRESS" and self.sf.validIP(ipaddr):
                octets = ipaddr.split(".")
                if octets[3] in ['0', '255']:
                    continue

            if ipaddr in self.results:
                continue
            self.results[ipaddr] = True

            evt = SpiderFootEvent(childType, ipaddr, self.__name__, event)
            self.notifyListeners(evt)

# End of sfp_subnet_enum class
