"""
Tests for core/dns_internet.py (Connectivity Ladder)
"""

import unittest
from core.dns_internet import (
    check_adapter_stage,
    check_dns_stage,
    check_gateway_stage,
    check_https_stage,
    check_internet_ip_stage,
    check_latency_stage,
    run_internet_health_check,
)


class TestInternetDiagnostics(unittest.TestCase):
    def test_check_adapter_stage(self):
        res = check_adapter_stage()
        self.assertEqual(res.stage_number, 1)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL"])
        self.assertIsNotNone(res.summary)

    def test_check_gateway_stage(self):
        res = check_gateway_stage()
        self.assertEqual(res.stage_number, 2)
        self.assertIn(res.verdict, ["PASS", "FAIL"])

    def test_check_internet_ip_stage(self):
        res = check_internet_ip_stage()
        self.assertEqual(res.stage_number, 3)
        self.assertIn(res.verdict, ["PASS", "FAIL"])

    def test_check_dns_stage(self):
        res = check_dns_stage()
        self.assertEqual(res.stage_number, 4)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL"])

    def test_check_https_stage(self):
        res = check_https_stage()
        self.assertEqual(res.stage_number, 5)
        self.assertIn(res.verdict, ["PASS", "FAIL"])

    def test_check_latency_stage(self):
        res = check_latency_stage()
        self.assertEqual(res.stage_number, 6)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL"])

    def test_full_health_check_pipeline(self):
        report = run_internet_health_check()
        self.assertIn(report.overall_status, ["HEALTHY", "DEGRADED", "OFFLINE"])
        self.assertEqual(len(report.stages), 6)
        self.assertEqual(report.passed_count + report.failed_count + report.warning_count, 6)
        self.assertIsNotNone(report.summary_verdict)
        self.assertIsNotNone(report.recommended_action)


if __name__ == "__main__":
    unittest.main()
