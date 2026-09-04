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

from core.network_diagnostics import (
    OUI_VENDOR_DATABASE,
    get_network_adapters,
    lookup_mac_vendor,
)
from utils.logger import get_logger
from utils.subprocess_runner import run_command
from utils.validators import validate_target

logger = get_logger()


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
