"""
Tests for core/system_info.py
"""

import unittest
from core.system_info import collect_system_info, format_uptime, get_cpu_info, get_ram_info


class TestSystemInfo(unittest.TestCase):
    def test_collect_system_info(self):
        info = collect_system_info()
        self.assertIsNotNone(info.computer_name)
        self.assertIsNotNone(info.username)
        self.assertIsNotNone(info.os_name)
        self.assertGreater(info.ram_total_gb, 0)
        self.assertGreater(info.ram_available_gb, 0)
        self.assertGreaterEqual(info.cpu_physical_cores, 1)
        self.assertGreaterEqual(info.cpu_logical_cores, 1)
        self.assertIn("Python", f"Python {info.python_version}")
        self.assertIsInstance(info.is_admin, bool)

    def test_format_uptime(self):
        # 65 seconds -> 1m 5s
        self.assertEqual(format_uptime(65), "1m 5s")
        # 3665 seconds -> 1h 1m 5s
        self.assertEqual(format_uptime(3665), "1h 1m 5s")
        # 90065 seconds -> 1d 1h 1m 5s
        self.assertEqual(format_uptime(90065), "1d 1h 1m 5s")

    def test_get_cpu_info(self):
        cpu = get_cpu_info()
        self.assertIn("model", cpu)
        self.assertIn("physical_cores", cpu)
        self.assertIn("logical_cores", cpu)
        self.assertIn("usage_percent", cpu)
        self.assertGreaterEqual(cpu["physical_cores"], 1)

    def test_get_ram_info(self):
        ram = get_ram_info()
        self.assertGreater(ram["total_gb"], 0)
        self.assertGreaterEqual(ram["used_gb"], 0)
        self.assertGreaterEqual(ram["available_gb"], 0)
        self.assertGreaterEqual(ram["usage_percent"], 0.0)
        self.assertLessEqual(ram["usage_percent"], 100.0)


if __name__ == "__main__":
    unittest.main()
