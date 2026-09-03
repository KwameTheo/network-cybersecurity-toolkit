"""
Tests for core/wifi_analyzer.py
"""

import unittest
from core.wifi_analyzer import (
    ConnectedWifiInfo,
    DiscoveredAccessPoint,
    WifiScanReport,
    analyze_channel_congestion,
    channel_to_band,
    get_connected_wifi_info,
    run_full_wifi_scan,
    scan_nearby_wifi_networks,
    signal_percent_to_dbm,
)


class TestWifiAnalyzer(unittest.TestCase):
    def test_signal_percent_to_dbm(self):
        self.assertEqual(signal_percent_to_dbm(100), -50)
        self.assertEqual(signal_percent_to_dbm(50), -75)
        self.assertEqual(signal_percent_to_dbm(0), -100)

    def test_channel_to_band(self):
        self.assertEqual(channel_to_band(1), "2.4 GHz")
        self.assertEqual(channel_to_band(6), "2.4 GHz")
        self.assertEqual(channel_to_band(11), "2.4 GHz")
        self.assertEqual(channel_to_band(36), "5 GHz")
        self.assertEqual(channel_to_band(48), "5 GHz")
        self.assertEqual(channel_to_band(149), "5 GHz")

    def test_get_connected_wifi_info(self):
        info = get_connected_wifi_info()
        # May be None or ConnectedWifiInfo depending on whether Wi-Fi hardware is present
        if info:
            self.assertIsInstance(info, ConnectedWifiInfo)
            self.assertIn(info.state, ["connected", "disconnected", "disabled"])

    def test_scan_nearby_wifi_networks(self):
        aps = scan_nearby_wifi_networks()
        self.assertIsInstance(aps, list)
        for ap in aps:
            self.assertIsInstance(ap, DiscoveredAccessPoint)
            self.assertIsNotNone(ap.ssid)
            self.assertIsNotNone(ap.bssid)
            self.assertIn(ap.security_rating, ["SECURE", "WARNING_OPEN", "DEPRECATED"])

    def test_analyze_channel_congestion(self):
        dummy_aps = [
            DiscoveredAccessPoint(
                ssid="Test-24G",
                bssid="00:11:22:33:44:55",
                signal_percent=80,
                signal_dbm=-60,
                radio_type="802.11ax",
                channel=4,  # Overlapping non-standard channel
                band="2.4 GHz",
                auth="WPA2-Personal",
                encryption="CCMP",
                security_rating="SECURE",
                is_connected=False
            ),
            DiscoveredAccessPoint(
                ssid="Test-5G",
                bssid="00:11:22:33:44:56",
                signal_percent=70,
                signal_dbm=-65,
                radio_type="802.11ac",
                channel=48,
                band="5 GHz",
                auth="WPA2-Personal",
                encryption="CCMP",
                security_rating="SECURE",
                is_connected=True
            ),
        ]
        rep = analyze_channel_congestion(dummy_aps)
        self.assertIsInstance(rep, WifiScanReport)
        self.assertEqual(rep.total_aps_found, 2)
        self.assertEqual(rep.band_24_counts.get(4), 1)
        self.assertEqual(rep.band_5_counts.get(48), 1)
        # Channel 4 should trigger overlap warning
        self.assertGreater(len(rep.overlap_warnings), 0)
        self.assertIn(rep.best_24_channel, [1, 6, 11])

    def test_run_full_wifi_scan(self):
        rep = run_full_wifi_scan()
        self.assertIsInstance(rep, WifiScanReport)
        self.assertGreaterEqual(rep.total_aps_found, 0)


if __name__ == "__main__":
    unittest.main()
