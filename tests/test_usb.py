"""
Tests for core/usb_forensics.py
"""

import unittest
from core.usb_forensics import (
    COMMON_USB_VIDS,
    USBForensicsSummary,
    USBStorageDeviceRecord,
    get_connected_usb_peripherals,
    get_usb_storage_history,
    parse_friendly_manufacturer,
    run_usb_forensic_audit,
)


class TestUSBForensics(unittest.TestCase):
    def test_parse_friendly_manufacturer(self):
        self.assertEqual(parse_friendly_manufacturer("Disk&Ven_Kingston&Prod_DataTraveler", ""), "Kingston Technology")
        self.assertEqual(parse_friendly_manufacturer("Disk&Ven_SanDisk&Prod_Ultra", ""), "SanDisk")
        self.assertEqual(parse_friendly_manufacturer("Disk&Ven_Toshiba&Prod_TransMemory", ""), "Toshiba")
        self.assertEqual(parse_friendly_manufacturer("Disk&Ven_Generic&Prod_Flash_Disk", ""), "Generic USB Flash Drive")

    def test_common_vids_dictionary(self):
        self.assertIn("0951", COMMON_USB_VIDS)  # Kingston
        self.assertIn("0781", COMMON_USB_VIDS)  # SanDisk
        self.assertIn("046D", COMMON_USB_VIDS)  # Logitech

    def test_get_usb_storage_history(self):
        records = get_usb_storage_history()
        self.assertIsInstance(records, list)
        for r in records:
            self.assertIsInstance(r, USBStorageDeviceRecord)
            self.assertIsNotNone(r.device_name)
            self.assertIsNotNone(r.serial_number)
            self.assertIsNotNone(r.registry_path)

    def test_run_usb_forensic_audit(self):
        summary = run_usb_forensic_audit()
        self.assertIsInstance(summary, USBForensicsSummary)
        self.assertGreaterEqual(summary.total_historical_storage_devices, 0)
        self.assertGreaterEqual(summary.currently_connected_usb_peripherals, 0)
        self.assertIsInstance(summary.storage_devices, list)
        self.assertIsInstance(summary.connected_peripherals, list)


if __name__ == "__main__":
    unittest.main()
