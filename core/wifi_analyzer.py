"""
Wi-Fi Signal & Wireless Channel Analyzer Engine
Scans active wireless interfaces, discovers nearby BSSID access points,
measures signal quality (percentage & dBm), and detects 2.4GHz/5GHz channel congestion.
"""

import platform
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.subprocess_runner import run_command

logger = get_logger()


@dataclass
class ConnectedWifiInfo:
    interface_name: str
    adapter_description: str
    mac_address: str
    state: str  # "connected", "disconnected", "disabled"
    ssid: str
    bssid: str
    radio_type: str  # "802.11ac", "802.11ax", "802.11n", etc.
    auth: str  # "WPA2-Personal", "WPA3-Personal", "Open"
    cipher: str  # "CCMP", "GCMP", "None"
    channel: int
    band: str  # "2.4 GHz", "5 GHz", "6 GHz"
    signal_percent: int
    signal_dbm: int
    rx_rate_mbps: float
    tx_rate_mbps: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredAccessPoint:
    ssid: str
    bssid: str
    signal_percent: int
    signal_dbm: int
    radio_type: str
    channel: int
    band: str
    auth: str
    encryption: str
    security_rating: str  # "SECURE", "WARNING_OPEN", "DEPRECATED"
    is_connected: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WifiScanReport:
    connected_info: Optional[ConnectedWifiInfo]
    discovered_aps: List[DiscoveredAccessPoint]
    total_aps_found: int
    band_24_counts: Dict[int, int]
    band_5_counts: Dict[int, int]
    crowded_channels: List[int]
    overlap_warnings: List[str]
    best_24_channel: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# HELPER CONVERTERS
# =========================================================================

def signal_percent_to_dbm(percent: int) -> int:
    """
    Converts Windows Wi-Fi signal percentage (0-100) to approximate dBm (-100 to -50 dBm).
    Formula: dBm = (percent / 2) - 100
    e.g. 100% -> -50 dBm, 50% -> -75 dBm, 0% -> -100 dBm.
    """
    pct = max(0, min(100, percent))
    return int((pct / 2.0) - 100)


def channel_to_band(channel: int) -> str:
    """Determines wireless frequency band from channel number."""
    if 1 <= channel <= 14:
        return "2.4 GHz"
    elif 32 <= channel <= 177:
        return "5 GHz"
    elif channel > 180:
        return "6 GHz"
    return "Unknown Band"


# =========================================================================
# ACTIVE CONNECTED WI-FI INTERFACE
# =========================================================================

def get_connected_wifi_info() -> Optional[ConnectedWifiInfo]:
    """
    Queries 'netsh wlan show interfaces' to get telemetry on current Wi-Fi connection.
    """
    if platform.system() != "Windows":
        return None

    res = run_command(["netsh", "wlan", "show", "interfaces"])
    if not res.success or not res.stdout:
        return None

    out = res.stdout
    name_m = re.search(r"Name\s*:\s*(.+)", out)
    desc_m = re.search(r"Description\s*:\s*(.+)", out)
    mac_m = re.search(r"Physical address\s*:\s*(.+)", out)
    state_m = re.search(r"State\s*:\s*(.+)", out)

    if not name_m or not state_m:
        return None

    state = state_m.group(1).strip().lower()
    if state != "connected":
        return ConnectedWifiInfo(
            interface_name=name_m.group(1).strip(),
            adapter_description=desc_m.group(1).strip() if desc_m else "Wireless Adapter",
            mac_address=mac_m.group(1).strip() if mac_m else "--",
            state=state,
            ssid="Disconnected",
            bssid="--",
            radio_type="--",
            auth="--",
            cipher="--",
            channel=0,
            band="--",
            signal_percent=0,
            signal_dbm=-100,
            rx_rate_mbps=0.0,
            tx_rate_mbps=0.0
        )

    ssid_m = re.search(r"SSID\s*:\s*(.+)", out)
    bssid_m = re.search(r"BSSID\s*:\s*(.+)", out)
    radio_m = re.search(r"Radio type\s*:\s*(.+)", out)
    auth_m = re.search(r"Authentication\s*:\s*(.+)", out)
    cipher_m = re.search(r"Cipher\s*:\s*(.+)", out)
    channel_m = re.search(r"Channel\s*:\s*(\d+)", out)
    sig_m = re.search(r"Signal\s*:\s*(\d+)%", out)
    rx_m = re.search(r"Receive rate \(Mbps\)\s*:\s*([\d\.]+)", out)
    tx_m = re.search(r"Transmit rate \(Mbps\)\s*:\s*([\d\.]+)", out)

    chan = int(channel_m.group(1)) if channel_m else 0
    sig_pct = int(sig_m.group(1)) if sig_m else 0

    return ConnectedWifiInfo(
        interface_name=name_m.group(1).strip(),
        adapter_description=desc_m.group(1).strip() if desc_m else "Wireless Adapter",
        mac_address=mac_m.group(1).strip() if mac_m else "--",
        state="connected",
        ssid=ssid_m.group(1).strip() if ssid_m else "Unknown SSID",
        bssid=bssid_m.group(1).strip() if bssid_m else "--",
        radio_type=radio_m.group(1).strip() if radio_m else "802.11",
        auth=auth_m.group(1).strip() if auth_m else "Unknown",
        cipher=cipher_m.group(1).strip() if cipher_m else "Unknown",
        channel=chan,
        band=channel_to_band(chan),
        signal_percent=sig_pct,
        signal_dbm=signal_percent_to_dbm(sig_pct),
        rx_rate_mbps=float(rx_m.group(1)) if rx_m else 0.0,
        tx_rate_mbps=float(tx_m.group(1)) if tx_m else 0.0
    )


# =========================================================================
# NEARBY DISCOVERED ACCESS POINTS
# =========================================================================

def scan_nearby_wifi_networks(connected_bssid: Optional[str] = None) -> List[DiscoveredAccessPoint]:
    """
    Parses 'netsh wlan show networks mode=bssid' to discover all nearby wireless APs.
    """
    if platform.system() != "Windows":
        return []

    res = run_command(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if not res.success or not res.stdout:
        return []

    lines = res.stdout.splitlines()
    aps: List[DiscoveredAccessPoint] = []

    current_ssid = "Hidden Network"
    current_auth = "Unknown"
    current_enc = "Unknown"

    current_bssid = None
    current_sig = 0
    current_radio = "802.11"
    current_channel = 0

    def push_bssid():
        nonlocal current_bssid, current_sig, current_radio, current_channel
        if current_bssid:
            band_str = channel_to_band(current_channel)
            # Security rating
            auth_upper = current_auth.upper()
            if "OPEN" in auth_upper or "NONE" in auth_upper:
                sec_rating = "WARNING_OPEN"
            elif "WEP" in auth_upper or "WPA-" in auth_upper:
                sec_rating = "DEPRECATED"
            else:
                sec_rating = "SECURE"

            is_conn = (connected_bssid and current_bssid.lower() == connected_bssid.lower())

            aps.append(DiscoveredAccessPoint(
                ssid=current_ssid,
                bssid=current_bssid,
                signal_percent=current_sig,
                signal_dbm=signal_percent_to_dbm(current_sig),
                radio_type=current_radio,
                channel=current_channel,
                band=band_str,
                auth=current_auth,
                encryption=current_enc,
                security_rating=sec_rating,
                is_connected=bool(is_conn)
            ))
            current_bssid = None
            current_sig = 0
            current_channel = 0

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SSID "):
            push_bssid()
            m = re.match(r"SSID \d+\s*:\s*(.*)", stripped)
            current_ssid = m.group(1).strip() if m and m.group(1).strip() else "Hidden Network"
        elif "Authentication" in stripped:
            m = re.search(r"Authentication\s*:\s*(.*)", stripped)
            if m:
                current_auth = m.group(1).strip()
        elif "Encryption" in stripped:
            m = re.search(r"Encryption\s*:\s*(.*)", stripped)
            if m:
                current_enc = m.group(1).strip()
        elif stripped.startswith("BSSID "):
            push_bssid()
            m = re.search(r"BSSID \d+\s*:\s*([0-9a-fA-F:]+)", stripped)
            if m:
                current_bssid = m.group(1).strip()
        elif "Signal" in stripped and current_bssid:
            m = re.search(r"Signal\s*:\s*(\d+)%", stripped)
            if m:
                current_sig = int(m.group(1))
        elif "Radio type" in stripped and current_bssid:
            m = re.search(r"Radio type\s*:\s*(.*)", stripped)
            if m:
                current_radio = m.group(1).strip()
        elif "Channel" in stripped and current_bssid:
            m = re.search(r"Channel\s*:\s*(\d+)", stripped)
            if m:
                current_channel = int(m.group(1))

    push_bssid()
    logger.info(f"Discovered {len(aps)} Wi-Fi Access Points.")
    return aps


# =========================================================================
# CHANNEL CONGESTION ANALYSIS
# =========================================================================

def analyze_channel_congestion(aps: List[DiscoveredAccessPoint]) -> WifiScanReport:
    """
    Analyzes channel distribution across 2.4 GHz and 5 GHz bands, identifies
    overlapping non-standard channels, and recommends optimal channels.
    """
    band_24_counts: Dict[int, int] = {}
    band_5_counts: Dict[int, int] = {}
    overlap_warnings: List[str] = []

    for ap in aps:
        if ap.band == "2.4 GHz":
            band_24_counts[ap.channel] = band_24_counts.get(ap.channel, 0) + 1
            # Check for non-standard 2.4GHz channels (outside 1, 6, 11)
            if ap.channel not in [1, 6, 11, 0]:
                overlap_warnings.append(
                    f"SSID '{ap.ssid}' (BSSID {ap.bssid}) is using Channel {ap.channel}. "
                    f"Non-standard 2.4GHz channels cause adjacent-channel overlap on Channels 1, 6, and 11."
                )
        elif ap.band == "5 GHz":
            band_5_counts[ap.channel] = band_5_counts.get(ap.channel, 0) + 1

    # Find crowded channels (channels with 2 or more APs)
    crowded_channels = [ch for ch, cnt in {**band_24_counts, **band_5_counts}.items() if cnt >= 2]

    # Best 2.4 GHz channel recommendation among 1, 6, 11
    counts_1_6_11 = {
        1: band_24_counts.get(1, 0),
        6: band_24_counts.get(6, 0),
        11: band_24_counts.get(11, 0),
    }
    best_24 = min(counts_1_6_11, key=counts_1_6_11.get)

    connected_info = get_connected_wifi_info()

    return WifiScanReport(
        connected_info=connected_info,
        discovered_aps=aps,
        total_aps_found=len(aps),
        band_24_counts=band_24_counts,
        band_5_counts=band_5_counts,
        crowded_channels=crowded_channels,
        overlap_warnings=overlap_warnings,
        best_24_channel=best_24
    )


def run_full_wifi_scan() -> WifiScanReport:
    """Executes a complete Wi-Fi survey and returns structured report."""
    logger.info("Starting Wi-Fi wireless survey...")
    conn = get_connected_wifi_info()
    conn_bssid = conn.bssid if conn and conn.state == "connected" else None
    aps = scan_nearby_wifi_networks(connected_bssid=conn_bssid)
    return analyze_channel_congestion(aps)
