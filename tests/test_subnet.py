"""
Tests for core/subnet_scanner.py
"""

import unittest
from core.subnet_scanner import (
    DiscoveredDevice,
    SubnetScanResult,
    detect_default_subnet,
    get_windows_arp_table,
    lookup_mac_vendor,
    resolve_lan_hostname,
)


class TestSubnetScanner(unittest.TestCase):
    def test_lookup_mac_vendor_known(self):
        # Apple test
        self.assertEqual(lookup_mac_vendor("F0:18:98:11:22:33"), "Apple")
        self.assertEqual(lookup_mac_vendor("f0-18-98-aa-bb-cc"), "Apple")

        # Cisco test
        self.assertEqual(lookup_mac_vendor("00:1A:2B:44:55:66"), "Cisco")

        # Intel test
        self.assertEqual(lookup_mac_vendor("00:02:B3:01:02:03"), "Intel")

        # Raspberry Pi test
        self.assertEqual(lookup_mac_vendor("B8:27:EB:AA:BB:CC"), "Raspberry Pi")

        # Randomized / Private MAC test (bit 1 set)
        self.assertEqual(lookup_mac_vendor("3E:58:B1:47:A1:5C"), "Private / Randomized MAC (Phone/Tablet)")

    def test_lookup_mac_vendor_unknown(self):
        self.assertEqual(lookup_mac_vendor("--"), "Unknown Device")
        self.assertEqual(lookup_mac_vendor(""), "Unknown Device")

    def test_get_windows_arp_table(self):
        arp_map = get_windows_arp_table()
        self.assertIsInstance(arp_map, dict)
        for ip, mac in arp_map.items():
            self.assertRegex(ip, r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            self.assertRegex(mac, r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")

    def test_detect_default_subnet(self):
        subnet, local_ip, gw = detect_default_subnet()
        self.assertIsInstance(subnet, str)
        self.assertIn("/", subnet)
        self.assertRegex(local_ip, r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    def test_discovered_device_dataclass(self):
        dev = DiscoveredDevice(
            ip="192.168.1.1",
            mac="00:1A:2B:3C:4D:5E",
            vendor="Cisco",
            hostname="gateway.local",
            latency_ms=2.5,
            status="Default Gateway",
            is_gateway=True,
            is_self=False
        )
        d = dev.to_dict()
        self.assertEqual(d["ip"], "192.168.1.1")
        self.assertEqual(d["vendor"], "Cisco")
        self.assertTrue(d["is_gateway"])


if __name__ == "__main__":
    unittest.main()
