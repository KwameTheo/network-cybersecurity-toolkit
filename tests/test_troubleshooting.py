"""
Tests for core/troubleshooting.py (Rule-Based Expert System)
"""

import unittest
from core.troubleshooting import (
    TroubleshootScenarioResult,
    diagnose_no_internet,
    diagnose_slow_network,
    diagnose_website_issue,
    diagnose_wifi_no_internet,
)


class TestTroubleshooting(unittest.TestCase):
    def test_diagnose_no_internet(self):
        res = diagnose_no_internet()
        self.assertIsInstance(res, TroubleshootScenarioResult)
        self.assertEqual(res.scenario_id, "no_internet")
        self.assertIn(res.overall_verdict, ["RESOLVED_ONLINE", "ISSUE_DETECTED", "WARNING_DEGRADED"])
        self.assertGreater(len(res.confirmed_facts), 0)
        self.assertIsNotNone(res.probable_root_cause)
        self.assertGreater(len(res.remediation_steps), 0)

    def test_diagnose_wifi_no_internet(self):
        res = diagnose_wifi_no_internet()
        self.assertIsInstance(res, TroubleshootScenarioResult)
        self.assertEqual(res.scenario_id, "wifi_no_internet")
        self.assertGreater(len(res.confirmed_facts), 0)

    def test_diagnose_website_issue_valid(self):
        res = diagnose_website_issue("google.com")
        self.assertIsInstance(res, TroubleshootScenarioResult)
        self.assertEqual(res.overall_verdict, "RESOLVED_ONLINE")
        self.assertIn("online", res.probable_root_cause.lower())

    def test_diagnose_website_issue_invalid(self):
        res = diagnose_website_issue("this-is-not-a-valid-domain-123456789xyz.invalid")
        self.assertIsInstance(res, TroubleshootScenarioResult)
        self.assertEqual(res.overall_verdict, "ISSUE_DETECTED")
        self.assertIn("dns", res.probable_root_cause.lower())

    def test_diagnose_slow_network(self):
        res = diagnose_slow_network()
        self.assertIsInstance(res, TroubleshootScenarioResult)
        self.assertEqual(res.scenario_id, "slow_network")
        self.assertGreater(len(res.confirmed_facts), 0)


if __name__ == "__main__":
    unittest.main()
