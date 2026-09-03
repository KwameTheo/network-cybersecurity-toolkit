"""
Network Diagnostics Engine
Handles adapter discovery, IP/DNS/DHCP metadata, Ping, Traceroute, DNS lookup,
and safe network control operations.
"""

import ipaddress
import platform
import re
import socket
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import psutil
from utils.logger import get_logger
from utils.subprocess_runner import CommandResult, run_command
from utils.validators import validate_target

logger = get_logger()


@dataclass
class NetworkAdapter:
    name: str
    description: str
    status: str  # "Connected / Up" or "Disconnected / Down"
    is_up: bool
    ipv4: str
    subnet_mask: str
    ipv6: str
    mac_address: str
    default_gateway: str
    dns_servers: List[str] = field(default_factory=list)
    dhcp_enabled: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PingResult:
    target: str
    target_type: str  # "ip" or "domain"
    sent: int
    received: int
    lost: int
    loss_percent: float
    min_rtt_ms: Optional[float]
    max_rtt_ms: Optional[float]
    avg_rtt_ms: Optional[float]
    raw_output: str
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TracerouteHop:
    hop_number: int
    rtt1: str
    rtt2: str
    rtt3: str
    host_or_ip: str


@dataclass
class TracerouteResult:
    target: str
    hops: List[TracerouteHop]
    raw_output: str
    reached_target: bool
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DNSLookupResult:
    query: str
    canonical_name: str
    addresses: List[str]
    raw_output: str
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =====================================================================
# Adapter Discovery & IP Configuration
# =====================================================================

def _parse_windows_ipconfig_all() -> Dict[str, Dict[str, Any]]:
    """
    Parses Windows 'ipconfig /all' output to extract Gateways, DNS servers,
    and DHCP status per network adapter.
    """
    config_by_adapter: Dict[str, Dict[str, Any]] = {}
    res = run_command(["ipconfig", "/all"], timeout_seconds=10)
    if not res.success or not res.stdout:
        return config_by_adapter

    current_adapter = None
    lines = res.stdout.splitlines()

    for line in lines:
        raw_line = line.strip()
        # Detect adapter header e.g. "Wireless LAN adapter Wi-Fi:" or "Ethernet adapter Ethernet:"
        if "adapter" in line and line.rstrip().endswith(":"):
            adapter_match = re.search(r"adapter\s+(.+?):", line, re.IGNORECASE)
            if adapter_match:
                current_adapter = adapter_match.group(1).strip()
                config_by_adapter[current_adapter] = {
                    "gateway": "",
                    "dns_servers": [],
                    "dhcp_enabled": None,
                    "description": ""
                }
            continue

        if not current_adapter or current_adapter not in config_by_adapter:
            continue

        data = config_by_adapter[current_adapter]

        # Extract Description
        if "Description" in raw_line and ":" in raw_line:
            data["description"] = raw_line.split(":", 1)[1].strip()

        # Extract DHCP Enabled
        if "DHCP Enabled" in raw_line and ":" in raw_line:
            val = raw_line.split(":", 1)[1].strip().lower()
            data["dhcp_enabled"] = (val == "yes")

        # Extract Default Gateway
        if "Default Gateway" in raw_line and ":" in raw_line:
            val = raw_line.split(":", 1)[1].strip()
            if val:
                data["gateway"] = val
        elif raw_line and data["gateway"] and not ":" in raw_line:
            # Check if this is a secondary gateway continuation (e.g. IPv4 under IPv6)
            cand = raw_line.strip()
            if re.match(r"^[\d\.]+$", cand) or re.match(r"^[\da-fA-F\:\%]+$", cand):
                data["gateway"] = cand

        # Extract DNS Servers
        if "DNS Servers" in raw_line and ":" in raw_line:
            val = raw_line.split(":", 1)[1].strip()
            if val and val not in data["dns_servers"]:
                data["dns_servers"].append(val)
        elif raw_line and data["dns_servers"] and not ":" in raw_line:
            # Subsequent line continuation for secondary DNS server
            cand = raw_line.strip()
            if (re.match(r"^[\d\.]+$", cand) or re.match(r"^[\da-fA-F\:\%]+$", cand)) and cand not in data["dns_servers"]:
                data["dns_servers"].append(cand)

    return config_by_adapter


def get_network_adapters() -> List[NetworkAdapter]:
    """
    Retrieves all network interfaces on the machine with their IPv4, IPv6,
    MAC address, Subnet Mask, Gateway, DNS, and DHCP status.
    """
    logger.info("Scanning network adapters...")
    adapters: List[NetworkAdapter] = []
    
    if_addrs = psutil.net_if_addrs()
    if_stats = psutil.net_if_stats()
    ipconfig_data = _parse_windows_ipconfig_all() if platform.system() == "Windows" else {}

    for name, addrs in if_addrs.items():
        is_up = False
        if name in if_stats:
            is_up = if_stats[name].isup

        ipv4 = "Not Assigned"
        subnet = "Not Assigned"
        ipv6 = "Not Assigned"
        mac = "Not Assigned"

        for addr in addrs:
            # Address families: AF_INET (IPv4), AF_INET6 (IPv6), AF_LINK (MAC)
            if addr.family == socket.AF_INET:
                ipv4 = addr.address or "Not Assigned"
                subnet = addr.netmask or "Not Assigned"
            elif addr.family == socket.AF_INET6:
                # Store first non-temporary IPv6
                if ipv6 == "Not Assigned" and addr.address:
                    ipv6 = addr.address.split("%")[0]  # Remove scope ID
            elif hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                mac = addr.address or "Not Assigned"

        # Match with ipconfig data
        gateway = "Not Configured"
        dns_servers = []
        dhcp_enabled = None
        desc = name

        # Look up matching adapter in ipconfig dictionary
        matched_cfg = None
        for cfg_name, cfg_val in ipconfig_data.items():
            if cfg_name.lower() in name.lower() or name.lower() in cfg_name.lower():
                matched_cfg = cfg_val
                break

        if matched_cfg:
            gateway = matched_cfg.get("gateway") or "Not Configured"
            dns_servers = matched_cfg.get("dns_servers", [])
            dhcp_enabled = matched_cfg.get("dhcp_enabled")
            desc = matched_cfg.get("description") or name

        adapter = NetworkAdapter(
            name=name,
            description=desc,
            status="Connected / Up" if is_up else "Disconnected / Down",
            is_up=is_up,
            ipv4=ipv4,
            subnet_mask=subnet,
            ipv6=ipv6,
            mac_address=mac,
            default_gateway=gateway,
            dns_servers=dns_servers,
            dhcp_enabled=dhcp_enabled
        )
        adapters.append(adapter)

    # Sort adapters: Active/Connected adapters with valid IPv4 first
    adapters.sort(key=lambda a: (a.is_up, a.ipv4 != "Not Assigned", not a.name.startswith("Loopback")), reverse=True)
    logger.info(f"Discovered {len(adapters)} network adapters.")
    return adapters


def get_primary_adapter() -> Optional[NetworkAdapter]:
    """
    Returns the primary active connected network adapter, prioritizing
    physical adapters with configured default gateways.
    """
    adapters = get_network_adapters()
    
    # 1. First priority: Connected adapter with IPv4 AND an active default gateway (not virtual)
    for adp in adapters:
        if (
            adp.is_up
            and adp.ipv4 != "Not Assigned"
            and adp.default_gateway != "Not Configured"
            and not adp.name.lower().startswith("vethernet")
            and not adp.name.lower().startswith("loopback")
        ):
            return adp

    # 2. Second priority: Any connected adapter with default gateway
    for adp in adapters:
        if adp.is_up and adp.default_gateway != "Not Configured":
            return adp

    # 3. Third priority: Any connected non-loopback adapter with an IPv4
    for adp in adapters:
        if adp.is_up and adp.ipv4 != "Not Assigned" and not adp.name.lower().startswith("loopback"):
            return adp

    return adapters[0] if adapters else None


# =====================================================================
# Ping Utility (ICMP Echo)
# =====================================================================

def ping_target(target: str, count: int = 4, timeout_sec: int = 3) -> PingResult:
    """
    Pings an IP address or domain name safely using Windows 'ping'.
    Calculates packet loss and round-trip latency metrics.
    """
    valid, clean_target, target_type = validate_target(target)
    if not valid:
        return PingResult(
            target=target,
            target_type="invalid",
            sent=0,
            received=0,
            lost=0,
            loss_percent=100.0,
            min_rtt_ms=None,
            max_rtt_ms=None,
            avg_rtt_ms=None,
            raw_output="",
            success=False,
            error_message=clean_target
        )

    # Windows ping command: ping -n <count> -w <timeout_ms> <target>
    timeout_ms = timeout_sec * 1000
    cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), clean_target]
    logger.info(f"Pinging {clean_target} ({count} packets)...")

    res = run_command(cmd, timeout_seconds=(count * timeout_sec) + 5)
    raw = res.stdout if res.stdout else res.stderr

    # Parse Sent / Received / Lost
    sent = count
    received = 0
    lost = count
    loss_percent = 100.0
    min_rtt = None
    max_rtt = None
    avg_rtt = None

    # Regex search for: Packets: Sent = 4, Received = 4, Lost = 0 (0% loss)
    packet_match = re.search(r"Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+),\s*Lost\s*=\s*(\d+)\s*\(([\d\.]+)%\s*loss\)", raw, re.IGNORECASE)
    if packet_match:
        sent = int(packet_match.group(1))
        received = int(packet_match.group(2))
        lost = int(packet_match.group(3))
        loss_percent = float(packet_match.group(4))

    # Regex search for: Minimum = 12ms, Maximum = 15ms, Average = 13ms
    rtt_match = re.search(r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms", raw, re.IGNORECASE)
    if rtt_match:
        min_rtt = float(rtt_match.group(1))
        max_rtt = float(rtt_match.group(2))
        avg_rtt = float(rtt_match.group(3))

    is_success = (received > 0)
    logger.info(f"Ping result for {clean_target}: {received}/{sent} packets received ({loss_percent}% loss).")

    return PingResult(
        target=clean_target,
        target_type=target_type,
        sent=sent,
        received=received,
        lost=lost,
        loss_percent=loss_percent,
        min_rtt_ms=min_rtt,
        max_rtt_ms=max_rtt,
        avg_rtt_ms=avg_rtt,
        raw_output=raw,
        success=is_success,
        error_message=None if is_success else "Host unreachable or packet loss 100%."
    )


# =====================================================================
# Traceroute Utility (tracert)
# =====================================================================

def traceroute_target(target: str, max_hops: int = 30) -> TracerouteResult:
    """
    Traces the route to a remote host using Windows 'tracert'.
    Uses -d (no DNS resolution per hop) for faster execution.
    """
    valid, clean_target, _ = validate_target(target)
    if not valid:
        return TracerouteResult(
            target=target,
            hops=[],
            raw_output="",
            reached_target=False,
            success=False,
            error_message=clean_target
        )

    # Windows tracert: tracert -d -h <max_hops> -w 1000 <target>
    cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", clean_target]
    logger.info(f"Running traceroute to {clean_target} (max {max_hops} hops)...")

    res = run_command(cmd, timeout_seconds=90)
    raw = res.stdout if res.stdout else res.stderr

    hops: List[TracerouteHop] = []
    reached = False

    # Example line: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
    # Or:           "  2     *        *        *     Request timed out."
    for line in raw.splitlines():
        line_clean = line.strip()
        hop_match = re.match(r"^(\d+)\s+([\d\<\*\s\w]+?)\s+([a-zA-Z0-9\.\:\_\-]+|Request timed out\.?)$", line_clean)
        if hop_match:
            hop_num = int(hop_match.group(1))
            rtt_section = hop_match.group(2).strip()
            host = hop_match.group(3).strip()

            # Split RTTs
            rtt_parts = rtt_section.split()
            rtt1 = rtt_parts[0] if len(rtt_parts) > 0 else "*"
            rtt2 = rtt_parts[1] if len(rtt_parts) > 1 else "*"
            rtt3 = rtt_parts[2] if len(rtt_parts) > 2 else "*"

            hops.append(TracerouteHop(
                hop_number=hop_num,
                rtt1=rtt1,
                rtt2=rtt2,
                rtt3=rtt3,
                host_or_ip=host
            ))

            if host == clean_target:
                reached = True

    is_success = bool(hops)
    logger.info(f"Traceroute to {clean_target} completed with {len(hops)} hops.")

    return TracerouteResult(
        target=clean_target,
        hops=hops,
        raw_output=raw,
        reached_target=reached,
        success=is_success,
        error_message=None if is_success else "Traceroute failed to return any hops."
    )


# =====================================================================
# DNS Resolution Utility (nslookup / socket)
# =====================================================================

def dns_lookup(query: str) -> DNSLookupResult:
    """
    Performs forward or reverse DNS lookups using Python socket and Windows nslookup.
    """
    valid, clean_query, q_type = validate_target(query)
    if not valid:
        return DNSLookupResult(
            query=query,
            canonical_name="",
            addresses=[],
            raw_output="",
            success=False,
            error_message=clean_query
        )

    logger.info(f"Performing DNS lookup for '{clean_query}'...")
    addresses = []
    canonical = clean_query

    # Native Python resolution
    try:
        if q_type == "ip":
            # Reverse lookup (PTR)
            host, _, _ = socket.gethostbyaddr(clean_query)
            canonical = host
            addresses = [clean_query]
        else:
            # Forward lookup (A/AAAA)
            canonical, aliases, addr_list = socket.gethostbyname_ex(clean_query)
            addresses = addr_list
    except socket.gaierror as e:
        logger.warning(f"Socket resolution failed for {clean_query}: {e}")
    except Exception as e:
        logger.warning(f"Reverse DNS failed for {clean_query}: {e}")

    # Also capture Windows nslookup output for detailed technician view
    res = run_command(["nslookup", clean_query], timeout_seconds=10)
    raw = res.stdout if res.stdout else res.stderr

    is_success = bool(addresses or res.success)
    return DNSLookupResult(
        query=clean_query,
        canonical_name=canonical,
        addresses=addresses,
        raw_output=raw,
        success=is_success,
        error_message=None if is_success else "DNS query returned no records or server timed out."
    )


# =====================================================================
# Safe Network Adapter Controls (DNS Flush & DHCP)
# =====================================================================

def flush_dns_cache() -> CommandResult:
    """Flushes the local Windows DNS Resolver Cache."""
    logger.info("Executing DNS cache flush (ipconfig /flushdns)...")
    res = run_command(["ipconfig", "/flushdns"], timeout_seconds=10)
    logger.info(f"Flush DNS result: returncode={res.return_code}")
    return res


def release_dhcp_lease() -> CommandResult:
    """Releases active DHCP leases (drops connection)."""
    logger.info("Executing DHCP lease release (ipconfig /release)...")
    res = run_command(["ipconfig", "/release"], timeout_seconds=15)
    logger.info(f"Release DHCP result: returncode={res.return_code}")
    return res


def renew_dhcp_lease() -> CommandResult:
    """Renews DHCP lease from local DHCP server."""
    logger.info("Executing DHCP lease renewal (ipconfig /renew)...")
    res = run_command(["ipconfig", "/renew"], timeout_seconds=30)
    logger.info(f"Renew DHCP result: returncode={res.return_code}")
    return res
