"""
Tests for core/database.py and core/report_generator.py
"""

import os
import unittest
from pathlib import Path
from core.database import (
    delete_report,
    get_recent_reports,
    get_report_by_id,
    init_db,
    save_report,
)
from core.report_generator import (
    assemble_full_audit_report,
    export_report_csv,
    export_report_json,
    export_report_txt,
    get_default_report_options,
)


class TestReportGeneratorAndDatabase(unittest.TestCase):
    def setUp(self):
        init_db()

    def test_database_crud(self):
        # Save
        dummy_data = {"test_key": "test_value", "timestamp": "2026-09-03 12:00:00"}
        rep_id = save_report(
            report_type="Test Audit",
            host_name="TEST-PC",
            os_edition="Windows 11 Pro",
            summary_text="Test Summary Text",
            full_report_dict=dummy_data,
            score_percent=85.0
        )
        self.assertGreater(rep_id, 0)

        # Read
        fetched = get_report_by_id(rep_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["host_name"], "TEST-PC")
        self.assertEqual(fetched["score_percent"], 85.0)

        # Recent list
        recent = get_recent_reports(limit=5)
        self.assertGreater(len(recent), 0)

        # Delete
        success = delete_report(rep_id)
        self.assertTrue(success)
        self.assertIsNone(get_report_by_id(rep_id))

    def test_assemble_and_export_reports(self):
        opts = {
            "system_info": True,
            "network_config": True,
            "ports_sockets": True,
            "internet_health": False,  # skip network latency ping for fast test
            "security_baseline": True,
            "event_logs": False,
        }
        report = assemble_full_audit_report(opts)
        self.assertIn("metadata", report)
        self.assertIn("system_info", report)
        self.assertIn("network_adapters", report)
        self.assertIn("security_audit", report)

        # TXT export
        txt_path = export_report_txt(report)
        self.assertTrue(os.path.exists(txt_path))
        with open(txt_path, "r", encoding="utf-8") as f:
            content = f.read()
            self.assertIn("NETWORK & CYBERSECURITY IT SUPPORT AUDIT REPORT", content)

        # JSON export
        json_path = export_report_json(report)
        self.assertTrue(os.path.exists(json_path))

        # CSV export
        csv_path = export_report_csv(report)
        self.assertTrue(os.path.exists(csv_path))


if __name__ == "__main__":
    unittest.main()
