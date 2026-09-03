"""
Tests for core/event_analyzer.py
"""

import unittest
from core.event_analyzer import (
    CATEGORY_META,
    EventQueryResult,
    _categorize_event,
    query_event_logs,
)


class TestEventAnalyzer(unittest.TestCase):
    def test_category_meta(self):
        self.assertIn("failed_logins", CATEGORY_META)
        self.assertIn("successful_logins", CATEGORY_META)
        self.assertIn("service_failures", CATEGORY_META)
        self.assertIn("system_errors", CATEGORY_META)
        self.assertIn("app_crashes", CATEGORY_META)

        self.assertTrue(CATEGORY_META["failed_logins"]["requires_admin"])
        self.assertFalse(CATEGORY_META["service_failures"]["requires_admin"])

    def test_categorize_event(self):
        self.assertEqual(_categorize_event(4625, "Security", "Information"), "Failed Login")
        self.assertEqual(_categorize_event(4624, "Security", "Information"), "Successful Login")
        self.assertEqual(_categorize_event(4740, "Security", "Information"), "Account Lockout")
        self.assertEqual(_categorize_event(7000, "System", "Error"), "Service Failure")
        self.assertEqual(_categorize_event(6008, "System", "Error"), "Unexpected Shutdown")
        self.assertEqual(_categorize_event(1000, "Application", "Error"), "App Crash / Hang")

    def test_query_service_failures(self):
        result = query_event_logs(category="service_failures", time_range_hours=168, max_events=10)
        self.assertIsInstance(result, EventQueryResult)
        self.assertTrue(result.success)
        self.assertIsInstance(result.events, list)


if __name__ == "__main__":
    unittest.main()
