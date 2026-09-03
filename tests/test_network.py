"""
Tests for core/network_diagnostics.py
"""

import unittest
from core.network_diagnostics import (
    dns_lookup,
    get_network_adapters,
    get_primary_adapter,
    ping_target,
    traceroute_target,
)


class TestNetworkDiagnostics(unittest.TestCase):
    def test_get_network_adapters(self):
        adapters = get_network_adapters()
        self.assertIsInstance(adapters, list)
        self.assertGreater(len(adapters), 0)

        # Check fields on the first adapter
        adp = adapters[0]
        self.assertIsNotNone(adp.name)
        self.assertIsNotNone(adp.status)
        self.assertIsNotNone(adp.ipv4)
        self.assertIsNotNone(adp.subnet_mask)
        self.assertIsNotNone(adp.mac_address)
        self.assertIsInstance(adp.dns_servers, list)

    def test_get_primary_adapter(self):
        primary = get_primary_adapter()
        self.assertIsNotNone(primary)
        self.assertTrue(primary.is_up)
        self.assertNotEqual(primary.ipv4, "Not Assigned")

    def test_ping_localhost(self):
        result = ping_target("127.0.0.1", count=2, timeout_sec=2)
        self.assertTrue(result.success)
        self.assertEqual(result.sent, 2)
        self.assertEqual(result.received, 2)
        self.assertEqual(result.loss_percent, 0.0)
        self.assertIsNotNone(result.avg_rtt_ms)

    def test_ping_injection_rejection(self):
        result = ping_target("8.8.8.8; whoami", count=2)
        self.assertFalse(result.success)
        self.assertEqual(result.target_type, "invalid")

    def test_dns_lookup_valid(self):
        result = dns_lookup("google.com")
        self.assertTrue(result.success)
        self.assertGreater(len(result.addresses), 0)

    def test_dns_lookup_injection_rejection(self):
        result = dns_lookup("google.com | calc")
        self.assertFalse(result.success)


if __name__ == "__main__":
    unittest.main()
