"""
Tests for core/service_manager.py
"""

import unittest
from core.service_manager import (
    CRITICAL_SERVICES,
    ServiceControlResult,
    WindowsServiceInfo,
    get_services_summary,
    get_windows_services,
    restart_windows_service,
    start_windows_service,
    stop_windows_service,
)


class TestServiceManager(unittest.TestCase):
    def test_get_windows_services(self):
        svcs = get_windows_services()
        self.assertIsInstance(svcs, list)
        self.assertGreater(len(svcs), 0)
        for s in svcs:
            self.assertIsInstance(s, WindowsServiceInfo)
            self.assertIsNotNone(s.name)
            self.assertIn(s.status, ["running", "stopped", "paused", "start_pending", "stop_pending", "unknown"])
            self.assertIn(s.start_type, ["automatic", "manual", "disabled", "unknown"])

    def test_get_services_summary(self):
        summary = get_services_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("total_services", summary)
        self.assertIn("running_count", summary)
        self.assertIn("stopped_count", summary)
        self.assertIn("critical_running", summary)
        self.assertEqual(summary["total_services"], summary["running_count"] + summary["stopped_count"])
        self.assertGreater(summary["critical_total"], 0)

    def test_critical_services_constants(self):
        self.assertIn("Spooler", CRITICAL_SERVICES)
        self.assertIn("wuauserv", CRITICAL_SERVICES)
        self.assertIn("Dhcp", CRITICAL_SERVICES)
        self.assertIn("Dnscache", CRITICAL_SERVICES)

    def test_service_control_sanitization(self):
        # Malicious injection attempt
        bad_name = "Spooler; rm -rf /; calc.exe"
        res = restart_windows_service(bad_name)
        self.assertIsInstance(res, ServiceControlResult)
        self.assertFalse(res.success)
        self.assertIn("Invalid", res.message)


if __name__ == "__main__":
    unittest.main()
