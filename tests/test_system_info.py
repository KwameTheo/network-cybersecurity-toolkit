import unittest
from unittest.mock import MagicMock, patch
from core.system_info import (
    collect_system_info,
    format_uptime,
    get_cpu_info,
    get_os_details,
    get_ram_info,
    get_windows_edition,
)


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

    def test_get_os_details_live(self):
        details = get_os_details()
        self.assertIn("os_name", details)
        self.assertIn("os_version", details)
        self.assertIn("os_build", details)
        self.assertIn("os_edition", details)
        self.assertTrue(len(details["os_edition"]) > 0)
        edition = get_windows_edition()
        self.assertEqual(edition, details["os_edition"])

    def test_windows_11_detection_from_legacy_product_name(self):
        """
        Tests that when Windows 11 (build >= 22000) has legacy 'Windows 10 Pro'
        in registry, get_os_details() correctly returns '11' and 'Windows 11 Pro (23H2)'.
        """
        fake_winver = MagicMock()
        fake_winver.build = 22631

        def fake_query_val(key, name):
            mapping = {
                "ProductName": ("Windows 10 Pro", 1),
                "DisplayVersion": ("23H2", 1),
                "EditionID": ("Professional", 1),
                "InstallationType": ("Client", 1),
                "CurrentBuildNumber": ("22631", 1),
                "UBR": (3880, 4),
            }
            if name in mapping:
                return mapping[name]
            raise FileNotFoundError()

        with patch("platform.system", return_value="Windows"), \
             patch("sys.getwindowsversion", return_value=fake_winver), \
             patch("winreg.OpenKey", return_value=MagicMock()), \
             patch("winreg.QueryValueEx", side_effect=fake_query_val), \
             patch("platform.version", return_value="10.0.22631"):
            details = get_os_details()
            self.assertEqual(details["os_version"], "11")
            self.assertEqual(details["os_edition"], "Windows 11 Pro (23H2)")
            self.assertEqual(details["os_build"], "10.0.22631.3880")

    def test_windows_10_detection(self):
        """
        Tests that Windows 10 (build 19045) returns '10' and 'Windows 10 Pro (22H2)'.
        """
        fake_winver = MagicMock()
        fake_winver.build = 19045

        def fake_query_val(key, name):
            mapping = {
                "ProductName": ("Windows 10 Pro", 1),
                "DisplayVersion": ("22H2", 1),
                "EditionID": ("Professional", 1),
                "InstallationType": ("Client", 1),
                "CurrentBuildNumber": ("19045", 1),
                "UBR": (7663, 4),
            }
            if name in mapping:
                return mapping[name]
            raise FileNotFoundError()

        with patch("platform.system", return_value="Windows"), \
             patch("sys.getwindowsversion", return_value=fake_winver), \
             patch("winreg.OpenKey", return_value=MagicMock()), \
             patch("winreg.QueryValueEx", side_effect=fake_query_val), \
             patch("platform.version", return_value="10.0.19045"):
            details = get_os_details()
            self.assertEqual(details["os_version"], "10")
            self.assertEqual(details["os_edition"], "Windows 10 Pro (22H2)")
            self.assertEqual(details["os_build"], "10.0.19045.7663")

    def test_windows_server_detection(self):
        """
        Tests that Windows Server 2022 (build 20348) is accurately identified.
        """
        fake_winver = MagicMock()
        fake_winver.build = 20348

        def fake_query_val(key, name):
            mapping = {
                "ProductName": ("Windows Server 2022 Datacenter", 1),
                "DisplayVersion": ("21H2", 1),
                "EditionID": ("ServerDatacenter", 1),
                "InstallationType": ("Server", 1),
                "CurrentBuildNumber": ("20348", 1),
                "UBR": (1000, 4),
            }
            if name in mapping:
                return mapping[name]
            raise FileNotFoundError()

        with patch("platform.system", return_value="Windows"), \
             patch("sys.getwindowsversion", return_value=fake_winver), \
             patch("winreg.OpenKey", return_value=MagicMock()), \
             patch("winreg.QueryValueEx", side_effect=fake_query_val), \
             patch("platform.version", return_value="10.0.20348"):
            details = get_os_details()
            self.assertEqual(details["os_version"], "Server 2022")
            self.assertEqual(details["os_edition"], "Windows Server 2022 Datacenter (21H2)")

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
