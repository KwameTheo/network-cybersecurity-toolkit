"""
Tests for core/dns_monitor.py
"""

import unittest
from core.dns_monitor import (
    DnsMonitorReport,
    DnsQueryRecord,
    calculate_shannon_entropy,
    evaluate_domain_anomaly,
    get_live_dns_cache,
    run_dns_monitor_audit,
)


class TestDnsMonitor(unittest.TestCase):
    def test_shannon_entropy(self):
        # Empty string
        self.assertEqual(calculate_shannon_entropy(""), 0.0)
        # Low entropy (repeated char)
        self.assertLess(calculate_shannon_entropy("aaaaaaa"), 1.0)
        # Normal domain
        normal_ent = calculate_shannon_entropy("google")
        self.assertGreater(normal_ent, 1.0)
        # High entropy random string (DGA simulation)
        dga_ent = calculate_shannon_entropy("qxz98vk4lp3w7m")
        self.assertGreater(dga_ent, 3.5)

    def test_evaluate_domain_anomaly_clean(self):
        flag, reason, ent = evaluate_domain_anomaly("google.com", 0)
        self.assertEqual(flag, "CLEAN")
        self.assertIsNone(reason)

    def test_evaluate_domain_anomaly_suspicious_tld(self):
        flag, reason, _ = evaluate_domain_anomaly("login-portal.xyz", 0)
        self.assertEqual(flag, "SUSPICIOUS_TLD")
        self.assertIsNotNone(reason)

    def test_evaluate_domain_anomaly_dns_tunneling(self):
        long_subdomain = "a" * 40 + ".attacker-c2.com"
        flag, reason, _ = evaluate_domain_anomaly(long_subdomain, 0)
        self.assertEqual(flag, "DNS_TUNNELING")
        self.assertIsNotNone(reason)

    def test_evaluate_domain_anomaly_dga(self):
        # High entropy + very low vowels (DGA)
        dga_domain = "qxz98vk4lp3w7m.com"
        flag, reason, _ = evaluate_domain_anomaly(dga_domain, 0)
        self.assertEqual(flag, "DGA_ENTROPY")
        self.assertIsNotNone(reason)

    def test_evaluate_domain_anomaly_nxdomain(self):
        flag, reason, _ = evaluate_domain_anomaly("nonexistent.invalid", 1)
        self.assertEqual(flag, "NXDOMAIN")
        self.assertIsNotNone(reason)

    def test_get_live_dns_cache(self):
        records = get_live_dns_cache()
        self.assertIsInstance(records, list)
        for r in records:
            self.assertIsInstance(r, DnsQueryRecord)
            self.assertIsNotNone(r.domain)
            self.assertIn(r.anomaly_flag, ["CLEAN", "SUSPICIOUS_TLD", "DGA_ENTROPY", "DNS_TUNNELING", "NXDOMAIN"])

    def test_run_dns_monitor_audit(self):
        rep = run_dns_monitor_audit()
        self.assertIsInstance(rep, DnsMonitorReport)
        self.assertEqual(rep.total_queries, rep.clean_count + rep.anomaly_count)


if __name__ == "__main__":
    unittest.main()
