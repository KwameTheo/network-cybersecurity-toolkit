"""
Tests for core/network_diagnostics.py
"""

import unittest
from core.network_diagnostics import (
    ARPEntry,
    ARPTableResult,
    dns_lookup,
    flush_arp_cache,
    get_arp_table,
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

    def test_get_arp_table_live(self):
        result = get_arp_table()
        self.assertIsInstance(result, ARPTableResult)
        self.assertTrue(result.success)
        self.assertIsInstance(result.entries, list)
        self.assertIsInstance(result.interfaces, list)
        self.assertEqual(result.total_entries, len(result.entries))
        self.assertEqual(result.dynamic_count + result.static_count, result.total_entries)

        if result.entries:
            entry = result.entries[0]
            self.assertIsInstance(entry, ARPEntry)
            self.assertIsNotNone(entry.ip_address)
            self.assertIsNotNone(entry.mac_address)
            self.assertIn(entry.entry_type, ["dynamic", "static"])
            self.assertIsNotNone(entry.vendor)
            self.assertIsInstance(entry.is_multicast_or_broadcast, bool)

    def test_get_arp_table_mock_parsing(self):
        mock_output = (
            "\nInterface: 192.168.1.50 --- 0x10\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           ac-5e-14-3f-f8-20     dynamic\n"
            "  192.168.1.15          00-1a-2b-44-55-66     dynamic\n"
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            "  224.0.0.22            01-00-5e-00-00-16     static\n"
            "\nInterface: 10.0.0.5 --- 0x15\n"
            "  Internet Address      Physical Address      Type\n"
            "  10.0.0.1              00-02-b3-01-02-03     dynamic\n"
            "  255.255.255.255       ff-ff-ff-ff-ff-ff     static\n"
        )
        from unittest.mock import patch
        from utils.subprocess_runner import CommandResult

        with patch("core.network_diagnostics.run_command") as mock_run:
            mock_run.return_value = CommandResult(
                command=["arp", "-a"],
                return_code=0,
                stdout=mock_output,
                stderr="",
                duration_ms=50.0,
                success=True
            )
            res = get_arp_table()
            self.assertTrue(res.success)
            self.assertEqual(res.total_entries, 6)
            self.assertEqual(res.dynamic_count, 3)
            self.assertEqual(res.static_count, 3)
            self.assertEqual(len(res.interfaces), 2)
            self.assertIn("192.168.1.50", res.interfaces)
            self.assertIn("10.0.0.5", res.interfaces)

            # Check Cisco vendor resolution
            cisco_entry = next((e for e in res.entries if e.ip_address == "192.168.1.15"), None)
            self.assertIsNotNone(cisco_entry)
            self.assertEqual(cisco_entry.vendor, "Cisco")
            self.assertEqual(cisco_entry.mac_address, "00:1A:2B:44:55:66")
            self.assertEqual(cisco_entry.entry_type, "dynamic")
            self.assertFalse(cisco_entry.is_multicast_or_broadcast)

            # Check Intel vendor resolution
            intel_entry = next((e for e in res.entries if e.ip_address == "10.0.0.1"), None)
            self.assertIsNotNone(intel_entry)
            self.assertEqual(intel_entry.vendor, "Intel")
            self.assertEqual(intel_entry.interface_ip, "10.0.0.5")

            # Check Broadcast entry
            bcast_entry = next((e for e in res.entries if e.ip_address == "192.168.1.255"), None)
            self.assertIsNotNone(bcast_entry)
            self.assertTrue(bcast_entry.is_multicast_or_broadcast)
            self.assertEqual(bcast_entry.vendor, "Multicast / Broadcast")

    def test_arp_dataclasses_to_dict(self):
        entry = ARPEntry(
            interface_ip="192.168.1.100",
            ip_address="192.168.1.1",
            mac_address="AC:5E:14:3F:F8:20",
            entry_type="dynamic",
            vendor="Huawei Technologies",
            is_multicast_or_broadcast=False
        )
        d = entry.to_dict()
        self.assertEqual(d["interface_ip"], "192.168.1.100")
        self.assertEqual(d["ip_address"], "192.168.1.1")
        self.assertEqual(d["vendor"], "Huawei Technologies")

        table_res = ARPTableResult(
            entries=[entry],
            raw_output="test",
            total_entries=1,
            dynamic_count=1,
            static_count=0,
            interfaces=["192.168.1.100"],
            success=True
        )
        td = table_res.to_dict()
        self.assertEqual(td["total_entries"], 1)
        self.assertEqual(len(td["entries"]), 1)


if __name__ == "__main__":
    unittest.main()
