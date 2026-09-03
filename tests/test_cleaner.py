"""
Tests for core/system_cleaner.py
"""

import os
import tempfile
import unittest
from core.system_cleaner import (
    CleanupCategoryInfo,
    CleanupExecutionResult,
    DiskSpaceSummary,
    analyze_disk_space,
    get_directory_size,
    get_target_cleanup_directories,
    safe_clean_directory,
)


class TestSystemCleaner(unittest.TestCase):
    def test_get_target_cleanup_directories(self):
        targets = get_target_cleanup_directories()
        self.assertIsInstance(targets, dict)
        self.assertIn("user_temp", targets)
        self.assertIn("system_temp", targets)
        self.assertIn("win_update_cache", targets)
        self.assertIn("crash_dumps", targets)
        for key, val in targets.items():
            self.assertIn("name", val)
            self.assertIn("path", val)
            self.assertIn("desc", val)

    def test_analyze_disk_space(self):
        summary = analyze_disk_space("C:\\")
        self.assertIsInstance(summary, DiskSpaceSummary)
        self.assertEqual(summary.drive_letter, "C:\\")
        self.assertGreater(summary.total_gb, 0.0)
        self.assertGreater(summary.free_gb, 0.0)
        self.assertGreaterEqual(summary.percent_used, 0.0)
        self.assertLessEqual(summary.percent_used, 100.0)
        self.assertIsInstance(summary.categories, list)
        self.assertGreater(len(summary.categories), 0)
        for c in summary.categories:
            self.assertIsInstance(c, CleanupCategoryInfo)
            self.assertGreaterEqual(c.file_count, 0)
            self.assertGreaterEqual(c.total_bytes, 0)

    def test_safe_clean_directory_in_mock_temp(self):
        # Create a mock temporary directory to test safe pruning without affecting real system
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file_1 = os.path.join(tmpdir, "test1.tmp")
            test_file_2 = os.path.join(tmpdir, "test2.log")
            with open(test_file_1, "w") as f:
                f.write("A" * 1024)
            with open(test_file_2, "w") as f:
                f.write("B" * 2048)

            f_count, b_size, access = get_directory_size(tmpdir)
            self.assertEqual(f_count, 2)
            self.assertEqual(b_size, 3072)
            self.assertTrue(access)

            deleted, failed, freed, logs = safe_clean_directory(tmpdir)
            self.assertEqual(deleted, 2)
            self.assertEqual(failed, 0)
            self.assertEqual(freed, 3072)
            self.assertEqual(len(os.listdir(tmpdir)), 0)


if __name__ == "__main__":
    unittest.main()
