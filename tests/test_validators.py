"""
Tests for utils/validators.py (Input validation & injection prevention)
"""

import unittest
from utils.validators import (
    validate_domain_name,
    validate_ip_address,
    validate_port,
    validate_target
)


class TestValidators(unittest.TestCase):
    def test_valid_ipv4(self):
        valid, ip = validate_ip_address("192.168.1.1")
        self.assertTrue(valid)
        self.assertEqual(ip, "192.168.1.1")

        valid, ip = validate_ip_address("8.8.8.8")
        self.assertTrue(valid)
        self.assertEqual(ip, "8.8.8.8")

    def test_valid_ipv6(self):
        valid, ip = validate_ip_address("2001:4860:4860::8888")
        self.assertTrue(valid)
        self.assertEqual(ip, "2001:4860:4860::8888")

    def test_invalid_ips(self):
        valid, _ = validate_ip_address("999.999.999.999")
        self.assertFalse(valid)

        valid, _ = validate_ip_address("192.168.1")
        self.assertFalse(valid)

    def test_command_injection_rejection(self):
        # Malicious inputs with shell metacharacters
        injections = [
            "8.8.8.8; whoami",
            "127.0.0.1 && dir",
            "8.8.8.8 | netstat",
            "192.168.1.1 `calc`",
            "google.com & ping 127.0.0.1",
            "127.0.0.1 > file.txt",
            "8.8.8.8\nwhoami"
        ]
        for inj in injections:
            valid_ip, _ = validate_ip_address(inj)
            self.assertFalse(valid_ip, f"Failed to reject IP injection: {inj}")

            valid_dom, _ = validate_domain_name(inj)
            self.assertFalse(valid_dom, f"Failed to reject Domain injection: {inj}")

            valid_tgt, _, _ = validate_target(inj)
            self.assertFalse(valid_tgt, f"Failed to reject Target injection: {inj}")

    def test_valid_domains(self):
        valid, dom = validate_domain_name("google.com")
        self.assertTrue(valid)
        self.assertEqual(dom, "google.com")

        valid, dom = validate_domain_name("dns.google")
        self.assertTrue(valid)

        valid, dom = validate_domain_name("sub.domain.example.co.uk")
        self.assertTrue(valid)

    def test_validate_ports(self):
        valid, port, _ = validate_port(80)
        self.assertTrue(valid)
        self.assertEqual(port, 80)

        valid, port, _ = validate_port("443")
        self.assertTrue(valid)
        self.assertEqual(port, 443)

        valid, _, _ = validate_port(0)
        self.assertFalse(valid)

        valid, _, _ = validate_port(70000)
        self.assertFalse(valid)

        valid, _, _ = validate_port("invalid")
        self.assertFalse(valid)


if __name__ == "__main__":
    unittest.main()
