"""
Tests for core/port_scanner.py
"""

import unittest
from core.port_scanner import (
    get_active_connections,
    get_listening_summary,
    get_service_tag,
)


class TestPortScanner(unittest.TestCase):
    def test_get_active_connections(self):
        conns = get_active_connections()
        self.assertIsInstance(conns, list)
        self.assertGreater(len(conns), 0)

        c = conns[0]
        self.assertIn(c.protocol, ["TCP", "UDP"])
        self.assertIsNotNone(c.local_address)
        self.assertIsInstance(c.local_port, int)
        self.assertIsNotNone(c.state)
        self.assertIsNotNone(c.process_name)

    def test_listening_summary(self):
        summary = get_listening_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("total_sockets", summary)
        self.assertIn("listening_tcp", summary)
        self.assertIn("established_sessions", summary)
        self.assertIn("udp_endpoints", summary)
        self.assertIn("active_processes", summary)
        self.assertGreater(summary["total_sockets"], 0)

    def test_service_tags(self):
        self.assertEqual(get_service_tag(80), "HTTP (Web)")
        self.assertEqual(get_service_tag(443), "HTTPS (Secure Web)")
        self.assertEqual(get_service_tag(445), "SMB / Windows File Sharing")
        self.assertEqual(get_service_tag(3389), "RDP (Remote Desktop)")
        self.assertEqual(get_service_tag(53), "DNS")
        self.assertEqual(get_service_tag(99999), "")

    def test_protocol_filters(self):
        tcp_conns = get_active_connections(protocol_filter="tcp")
        for c in tcp_conns:
            self.assertEqual(c.protocol, "TCP")

        udp_conns = get_active_connections(protocol_filter="udp")
        for c in udp_conns:
            self.assertEqual(c.protocol, "UDP")


if __name__ == "__main__":
    unittest.main()
