"""
Tests for core/security_checks.py
"""

import unittest
from core.security_checks import (
    SecurityAuditReport,
    SecurityCheckItem,
    check_antivirus,
    check_firewall,
    check_guest_account,
    check_rdp,
    check_smbv1,
    check_uac,
    check_user_privileges,
    run_security_audit,
)


class TestSecurityChecks(unittest.TestCase):
    def test_check_firewall(self):
        res = check_firewall()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL", "UNKNOWN"])
        self.assertIsNotNone(res.name)
        self.assertIsNotNone(res.summary)

    def test_check_antivirus(self):
        res = check_antivirus()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL", "UNKNOWN"])

    def test_check_user_privileges(self):
        res = check_user_privileges()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertEqual(res.verdict, "PASS")

    def test_check_guest_account(self):
        res = check_guest_account()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "FAIL", "UNKNOWN"])

    def test_check_uac(self):
        res = check_uac()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "FAIL", "UNKNOWN"])

    def test_check_smbv1(self):
        res = check_smbv1()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "FAIL", "UNKNOWN"])

    def test_check_rdp(self):
        res = check_rdp()
        self.assertIsInstance(res, SecurityCheckItem)
        self.assertIn(res.verdict, ["PASS", "WARNING", "FAIL", "UNKNOWN"])

    def test_run_security_audit(self):
        report = run_security_audit()
        self.assertIsInstance(report, SecurityAuditReport)
        self.assertIn(report.overall_posture, ["SECURE", "NEEDS_ATTENTION", "AT_RISK"])
        self.assertGreaterEqual(report.score_percent, 0.0)
        self.assertLessEqual(report.score_percent, 100.0)
        self.assertEqual(len(report.checks), 7)
        self.assertEqual(report.passed_count + report.failed_count + report.warning_count, 7)


if __name__ == "__main__":
    unittest.main()
