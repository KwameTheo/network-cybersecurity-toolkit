"""
Subnet IP Scanner & LAN Device Mapper Engine
Executes high-speed multithreaded ARP and ICMP sweeps across local IPv4 subnets,
resolves hostnames, parses MAC addresses, and identifies hardware vendors (OUI).
"""

import concurrent.futures
import ipaddress
import re
import socket
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional

from core.network_diagnostics import get_network_adapters
from utils.logger import get_logger
from utils.subprocess_runner import run_command
from utils.validators import validate_target

logger = get_logger()

# Common IEEE Organizationally Unique Identifier (OUI) MAC prefix dictionary
OUI_VENDOR_DATABASE: Dict[str, str] = {
    # Apple
    "00:03:93": "Apple", "00:05:02": "Apple", "00:0A:27": "Apple", "00:10:FA": "Apple",
    "00:17:F2": "Apple", "00:1B:63": "Apple", "00:1E:52": "Apple", "00:23:DF": "Apple",
    "00:26:08": "Apple", "04:0C:CE": "Apple", "04:15:52": "Apple", "04:26:65": "Apple",
    "04:db:56": "Apple", "0c:4d:e9": "Apple", "14:10:9f": "Apple", "14:20:5e": "Apple",
    "18:af:61": "Apple", "20:c9:d0": "Apple", "28:cf:e9": "Apple", "3c:22:fb": "Apple",
    "40:6c:8f": "Apple", "48:d7:05": "Apple", "5c:96:9d": "Apple", "60:03:08": "Apple",
    "64:b0:a6": "Apple", "70:3e:ac": "Apple", "7c:04:d0": "Apple", "88:66:a5": "Apple",
    "90:72:40": "Apple", "98:01:a7": "Apple", "a4:83:e7": "Apple", "ac:bc:32": "Apple",
    "b8:78:26": "Apple", "c8:69:cd": "Apple", "d4:61:9d": "Apple", "dc:a9:04": "Apple",
    "e0:b9:ba": "Apple", "f0:18:98": "Apple", "f4:0f:24": "Apple", "f8:ff:c2": "Apple",

    # Cisco & Linksys
    "00:00:0C": "Cisco", "00:01:42": "Cisco", "00:01:C7": "Cisco", "00:02:B9": "Cisco",
    "00:03:6B": "Cisco", "00:06:53": "Cisco", "00:0C:85": "Cisco", "00:14:69": "Cisco",
    "00:1A:2B": "Cisco", "00:1B:0D": "Cisco", "00:1D:70": "Cisco", "00:21:55": "Cisco",
    "00:24:98": "Cisco", "00:26:98": "Cisco", "00:0F:66": "Cisco-Linksys", "00:18:39": "Cisco-Linksys",

    # Intel
    "00:02:B3": "Intel", "00:03:47": "Intel", "00:04:23": "Intel", "00:0C:F1": "Intel",
    "00:13:02": "Intel", "00:1B:21": "Intel", "00:21:6A": "Intel", "08:11:96": "Intel",
    "0c:8b:7d": "Intel", "34:13:e8": "Intel", "3c:6a:9d": "Intel", "48:51:b7": "Intel",
    "50:76:af": "Intel", "68:05:ca": "Intel", "7c:b0:c2": "Intel", "80:86:f2": "Intel",
    "9c:29:76": "Intel", "a0:a8:cd": "Intel", "b4:96:91": "Intel", "c8:5b:76": "Intel",

    # Microsoft
    "00:03:FF": "Microsoft", "00:0D:3A": "Microsoft", "00:12:5A": "Microsoft", "00:15:5D": "Microsoft (Hyper-V)",
    "00:1D:D8": "Microsoft", "00:25:AE": "Microsoft", "28:18:78": "Microsoft", "60:45:bd": "Microsoft",
    "70:66:55": "Microsoft", "dc:97:58": "Microsoft (Xbox)",

    # Dell & HP
    "00:14:22": "Dell", "00:18:8B": "Dell", "00:21:70": "Dell", "00:24:E8": "Dell",
    "18:66:da": "Dell", "34:e6:d7": "Dell", "44:a8:42": "Dell", "74:86:7a": "Dell",
    "00:01:E6": "HP", "00:08:02": "HP", "00:0E:7F": "HP", "00:17:A4": "HP",
    "00:23:7D": "HP", "18:a9:58": "HP", "30:d3:2d": "HP", "3c:d9:2b": "HP",

    # Samsung & Google
    "00:07:AB": "Samsung", "00:12:47": "Samsung", "00:16:32": "Samsung", "00:21:19": "Samsung",
    "08:fc:52": "Samsung", "18:67:b0": "Samsung", "24:4b:03": "Samsung", "40:0e:85": "Samsung",
    "50:01:d9": "Samsung", "78:4b:87": "Samsung", "98:52:b1": "Samsung", "d8:47:32": "Samsung",
    "00:1A:11": "Google", "3c:5a:37": "Google (Nest/Chromecast)", "54:60:09": "Google",
    "74:c6:3b": "Google", "a4:77:33": "Google", "f8:8f:ca": "Google",

    # Networking Gear (TP-Link, Netgear, ASUS, Ubiquiti, D-Link)
    "00:19:E0": "TP-Link", "00:27:19": "TP-Link", "14:cc:20": "TP-Link", "24:4b:fe": "TP-Link",
    "50:c7:bf": "TP-Link", "70:4f:57": "TP-Link", "98:da:c4": "TP-Link", "c0:06:c3": "TP-Link",
    "00:09:5B": "Netgear", "00:14:6C": "Netgear", "00:1E:2A": "Netgear", "00:26:F2": "Netgear",
    "08:bd:43": "Netgear", "20:4e:7f": "Netgear", "9c:3d:cf": "Netgear", "c0:3f:0e": "Netgear",
    "00:0C:6E": "ASUSTeK", "00:1E:8C": "ASUSTeK", "04:d9:f5": "ASUSTeK", "10:7b:44": "ASUSTeK",
    "00:15:6D": "Ubiquiti", "04:18:d6": "Ubiquiti", "24:a4:3c": "Ubiquiti", "78:8a:20": "Ubiquiti",
    "00:05:5D": "D-Link", "00:0D:88": "D-Link", "00:15:E9": "D-Link", "00:1E:58": "D-Link",

    # IoT, Virtualization & Single Board Computers
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "24:6f:28": "Espressif (ESP32/ESP8266 IoT)", "30:ae:a4": "Espressif (IoT)", "84:cc:a8": "Espressif (IoT)",
    "00:05:69": "VMware", "00:0C:29": "VMware", "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox",
    "00:11:32": "Synology NAS", "00:08:9B": "QNAP NAS",
    "00:08:22": "Inseego / MiFi Gateway",
    "ac:5e:14": "Huawei Technologies",
    "9a:e7:e8": "Samsung Electronics",
}


@dataclass
class DiscoveredDevice:
    ip: str
    mac: str
    vendor: str
    hostname: str
    latency_ms: float
    status: str  # "Active", "Gateway", "This Computer"
    is_gateway: bool
    is_self: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubnetScanResult:
    subnet_cidr: str
    total_hosts_scanned: int
    active_hosts_found: int
    scan_duration_sec: float
    devices: List[DiscoveredDevice]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# OUI VENDOR LOOKUP & ARP CACHE
# =========================================================================

def lookup_mac_vendor(mac_str: str) -> str:
    """
    Resolves the hardware vendor/manufacturer for a given MAC address.
    """
    if not mac_str or mac_str == "--" or len(mac_str) < 8:
        return "Unknown Device"

    # Normalize delimiter to colon lowercase (e.g. "ac-5e-14-3f-f8-20" -> "ac:5e:14")
    clean_mac = re.sub(r"[^a-fA-F0-9]", ":", mac_str.strip()).lower()
    parts = clean_mac.split(":")
    if len(parts) >= 3:
        prefix = f"{parts[0]}:{parts[1]}:{parts[2]}"
        for oui_key, vendor_name in OUI_VENDOR_DATABASE.items():
            if oui_key.lower() == prefix:
                return vendor_name

    # Check for randomized / private MAC addresses (bit 1 of 1st byte set)
    try:
        first_byte = int(parts[0], 16)
        if first_byte & 0b00000010:
            return "Private / Randomized MAC (Phone/Tablet)"
    except Exception:
        pass

    return "Generic Network Device"


def get_windows_arp_table() -> Dict[str, str]:
    """
    Queries 'arp -a' and returns a dictionary mapping IPv4 -> MAC address.
    """
    arp_map: Dict[str, str] = {}
    res = run_command(["arp", "-a"])
    if not res.success or not res.stdout:
        return arp_map

    # Pattern: 192.168.100.1      ac-5e-14-3f-f8-20     dynamic
    pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\-]{17})\s+(\w+)")
    for line in res.stdout.splitlines():
        match = pattern.search(line)
        if match:
            ip = match.group(1)
            mac = match.group(2).replace("-", ":").upper()
            # Ignore multicast and broadcast IPs
            if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                arp_map[ip] = mac

    return arp_map


def resolve_lan_hostname(ip: str) -> str:
    """
    Performs reverse DNS lookup for a local LAN IP address.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except (socket.herror, socket.gaierror, OSError):
        return "--"


def detect_default_subnet() -> tuple[str, str, str]:
    """
    Identifies the active local network subnet CIDR, local IP, and default gateway.
    Prioritizes adapters with an active default gateway.
    Returns: (subnet_cidr, local_ip, gateway_ip)
    """
    adapters = get_network_adapters()
    candidates = []

    for a in adapters:
        if (
            a.ipv4
            and not a.ipv4.startswith("127.")
            and not a.ipv4.startswith("169.254.")
            and a.subnet_mask
            and a.subnet_mask != "Not Assigned"
        ):
            try:
                net = ipaddress.IPv4Network(f"{a.ipv4}/{a.subnet_mask}", strict=False)
                has_gw = bool(a.default_gateway and a.default_gateway != "Not Configured")
                gw = a.default_gateway if has_gw else ""
                candidates.append((has_gw, str(net), a.ipv4, gw))
            except Exception:
                continue

    if candidates:
        # Sort so adapters with gateway come first
        candidates.sort(key=lambda x: not x[0])
        _, best_net, best_ip, best_gw = candidates[0]
        return best_net, best_ip, best_gw

    return "192.168.1.0/24", "192.168.1.100", "192.168.1.1"


# =========================================================================
# MULTITHREADED SUBNET SWEEP
# =========================================================================

import subprocess

def ping_single_host(ip: str) -> Optional[tuple[str, float]]:
    """
    Sends a single fast ICMP ping probe (300ms timeout) to test host reachability.
    Returns: (ip, latency_ms) if alive, or None.
    """
    start_t = time.perf_counter()
    try:
        proc = subprocess.run(
            ["ping", "-n", "1", "-w", "300", ip],
            capture_output=True,
            text=True,
            shell=False,
            timeout=1.0
        )
        dur = (time.perf_counter() - start_t) * 1000

        if proc.returncode == 0 and "TTL=" in (proc.stdout or "").upper():
            m = re.search(r"time[=<]\s*(\d+)ms", proc.stdout, re.IGNORECASE)
            if m:
                return ip, float(m.group(1))
            return ip, round(dur, 1)
    except Exception:
        pass

    return None


def scan_subnet(
    subnet_cidr: str,
    progress_callback: Optional[Callable[[int, int], None]] = None
) -> SubnetScanResult:
    """
    Executes a high-speed multithreaded ARP and ICMP sweep across the target CIDR block.
    """
    try:
        network = ipaddress.IPv4Network(subnet_cidr, strict=False)
    except Exception as e:
        logger.error(f"Invalid subnet CIDR '{subnet_cidr}': {e}")
        return SubnetScanResult(subnet_cidr, 0, 0, 0.0, [])

    start_scan_time = time.perf_counter()
    _, local_ip, gateway_ip = detect_default_subnet()

    # Generate list of host IPs (limit to max 256 for performance)
    hosts = [str(h) for h in network.hosts()][:254]
    total_hosts = len(hosts)
    logger.info(f"Initiating subnet sweep for {subnet_cidr} ({total_hosts} hosts)...")

    live_hosts: Dict[str, float] = {}
    completed_count = 0

    # 1. High-speed concurrent ICMP sweep
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_map = {executor.submit(ping_single_host, ip): ip for ip in hosts}
        for future in concurrent.futures.as_completed(future_map):
            completed_count += 1
            if progress_callback:
                progress_callback(completed_count, total_hosts)

            result = future.result()
            if result:
                host_ip, rtt = result
                live_hosts[host_ip] = rtt

    # 2. Extract updated ARP cache table from OS
    arp_map = get_windows_arp_table()

    # Add hosts present in ARP cache even if they silently dropped ICMP ping
    for arp_ip in arp_map.keys():
        if arp_ip in hosts and arp_ip not in live_hosts:
            live_hosts[arp_ip] = 1.0  # Present on LAN layer 2

    # Always ensure local host IP is included
    if local_ip in hosts and local_ip not in live_hosts:
        live_hosts[local_ip] = 0.0

    # 3. Resolve Hostnames & Hardware Vendors
    discovered_devices: List[DiscoveredDevice] = []

    for ip, latency in live_hosts.items():
        is_gw = (ip == gateway_ip)
        is_self = (ip == local_ip)
        mac = arp_map.get(ip, "--")

        if is_self:
            status_text = "This Computer"
        elif is_gw:
            status_text = "Default Gateway"
        else:
            status_text = "Active Host"

        hostname = resolve_lan_hostname(ip)
        vendor = lookup_mac_vendor(mac)

        discovered_devices.append(DiscoveredDevice(
            ip=ip,
            mac=mac,
            vendor=vendor,
            hostname=hostname,
            latency_ms=latency,
            status=status_text,
            is_gateway=is_gw,
            is_self=is_self
        ))

    # Sort devices by IP numeric order (Gateway / Self prioritized)
    def ip_sort_key(dev: DiscoveredDevice):
        try:
            return (not dev.is_gateway, not dev.is_self, int(ipaddress.IPv4Address(dev.ip)))
        except Exception:
            return (1, 1, 0)

    discovered_devices.sort(key=ip_sort_key)
    scan_duration = round(time.perf_counter() - start_scan_time, 2)
    logger.info(f"Subnet scan completed in {scan_duration}s: Found {len(discovered_devices)} active devices.")

    return SubnetScanResult(
        subnet_cidr=subnet_cidr,
        total_hosts_scanned=total_hosts,
        active_hosts_found=len(discovered_devices),
        scan_duration_sec=scan_duration,
        devices=discovered_devices
    )
