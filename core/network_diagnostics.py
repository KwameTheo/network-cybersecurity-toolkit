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


@dataclass
class ARPEntry:
    interface_ip: str
    ip_address: str
    mac_address: str
    entry_type: str  # "dynamic", "static"
    vendor: str
    is_multicast_or_broadcast: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ARPTableResult:
    entries: List[ARPEntry]
    raw_output: str
    total_entries: int
    dynamic_count: int
    static_count: int
    interfaces: List[str]
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


# =====================================================================
# IEEE OUI Vendor Resolution & ARP Cache Inspection (arp -a)
# =====================================================================

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


def get_arp_table(interface_ip: Optional[str] = None) -> ARPTableResult:
    """
    Queries Windows 'arp -a' and returns parsed ARP cache entries across
    all network interfaces (or filtered by interface_ip).
    Resolves MAC hardware vendors and categorizes dynamic vs static records.
    """
    cmd = ["arp", "-a"]
    if interface_ip:
        valid, clean_ip, _ = validate_target(interface_ip)
        if valid:
            cmd.extend(["-N", clean_ip])

    logger.info(f"Querying ARP cache table ({' '.join(cmd)})...")
    res = run_command(cmd, timeout_seconds=10)
    raw = res.stdout if res.stdout else (res.stderr or "")

    if not res.success and not res.stdout:
        return ARPTableResult(
            entries=[],
            raw_output=raw,
            total_entries=0,
            dynamic_count=0,
            static_count=0,
            interfaces=[],
            success=False,
            error_message=res.stderr or "Failed to execute 'arp -a'."
        )

    entries: List[ARPEntry] = []
    interfaces: List[str] = []
    current_interface = "Unknown"

    iface_regex = re.compile(r"Interface:\s*([\d\.]+)", re.IGNORECASE)
    entry_regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F\-]{17})\s+(\w+)")

    for line in raw.splitlines():
        line_clean = line.strip()
        if not line_clean:
            continue

        iface_match = iface_regex.search(line_clean)
        if iface_match:
            current_interface = iface_match.group(1)
            if current_interface not in interfaces:
                interfaces.append(current_interface)
            continue

        entry_match = entry_regex.search(line_clean)
        if entry_match:
            ip = entry_match.group(1)
            raw_mac = entry_match.group(2)
            entry_type = entry_match.group(3).lower()

            mac = raw_mac.replace("-", ":").upper()

            is_mcast_or_bcast = (
                ip.startswith("224.") or
                ip.startswith("239.") or
                ip == "255.255.255.255" or
                ip.endswith(".255") or
                mac == "FF:FF:FF:FF:FF:FF" or
                mac.startswith("01:00:5E")
            )

            vendor = lookup_mac_vendor(mac) if not is_mcast_or_bcast else "Multicast / Broadcast"

            entries.append(ARPEntry(
                interface_ip=current_interface,
                ip_address=ip,
                mac_address=mac,
                entry_type=entry_type,
                vendor=vendor,
                is_multicast_or_broadcast=is_mcast_or_bcast
            ))

    dynamic_cnt = sum(1 for e in entries if e.entry_type == "dynamic")
    static_cnt = sum(1 for e in entries if e.entry_type == "static")

    return ARPTableResult(
        entries=entries,
        raw_output=raw,
        total_entries=len(entries),
        dynamic_count=dynamic_cnt,
        static_count=static_cnt,
        interfaces=interfaces,
        success=True
    )


def flush_arp_cache() -> CommandResult:
    """
    Flushes the local Windows ARP table cache (netsh interface ip delete arpcache / arp -d *).
    Requires administrative privileges.
    """
    logger.info("Executing ARP cache flush (netsh interface ip delete arpcache)...")
    res = run_command(["netsh", "interface", "ip", "delete", "arpcache"], timeout_seconds=10)
    if not res.success:
        logger.info("Falling back to 'arp -d *'...")
        res = run_command(["arp", "-d", "*"], timeout_seconds=10)
    logger.info(f"Flush ARP cache result: returncode={res.return_code}")
    return res
