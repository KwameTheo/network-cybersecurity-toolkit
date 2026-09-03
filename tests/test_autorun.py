"""
Tests for core/autorun_inspector.py
"""

import unittest
from core.autorun_inspector import (
    PersistenceItem,
    PersistenceSummary,
    evaluate_persistence_threat,
    extract_target_binary,
    run_persistence_audit,
    scan_registry_run_keys,
    scan_startup_folders,
)


class TestAutorunInspector(unittest.TestCase):
    def test_extract_target_binary(self):
        # Quoted string with arguments
        cmd1 = '"C:\\Program Files\\App\\app.exe" --startup --hidden'
        self.assertEqual(extract_target_binary(cmd1), "C:\\Program Files\\App\\app.exe")

        # Unquoted string
        cmd2 = "C:\\Windows\\notepad.exe myfile.txt"
        self.assertEqual(extract_target_binary(cmd2), "C:\\Windows\\notepad.exe")

    def test_evaluate_persistence_threat_heuristics(self):
        # Suspicious script execution
        cmd_bad = "wscript.exe //B //Nologo C:\\Users\\Public\\malware.vbs"
        bin_p, threat, exists, reasons = evaluate_persistence_threat("MalTask", cmd_bad, "HKCU Run")
        self.assertEqual(threat, "SUSPICIOUS")
        self.assertGreater(len(reasons), 0)

        # Unquoted path with spaces
        cmd_unquoted = "C:\\Program Files\\Vulnerable App\\app.exe"
        bin_p, threat, exists, reasons = evaluate_persistence_threat("UnquotedTask", cmd_unquoted, "HKLM Run")
        self.assertIn(threat, ["WARNING", "SUSPICIOUS"])

    def test_scan_registry_run_keys(self):
        items = scan_registry_run_keys()
        self.assertIsInstance(items, list)
        for it in items:
            self.assertIsInstance(it, PersistenceItem)
            self.assertEqual(it.entry_type, "Registry Run")
            self.assertIsNotNone(it.name)
            self.assertIsNotNone(it.command)
            self.assertIn(it.threat_level, ["CLEAN", "WARNING", "SUSPICIOUS"])

    def test_run_persistence_audit(self):
        summary = run_persistence_audit()
        self.assertIsInstance(summary, PersistenceSummary)
        self.assertGreaterEqual(summary.total_items, 0)
        self.assertEqual(
            summary.total_items,
            summary.clean_count + summary.warning_count + summary.suspicious_count
        )
        self.assertIsInstance(summary.items, list)


if __name__ == "__main__":
    unittest.main()
