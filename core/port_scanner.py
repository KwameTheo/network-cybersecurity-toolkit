"""
Port & Connection Analysis Engine
Audits active TCP/UDP sockets, listening endpoints, established sessions,
and maps sockets to Windows Process IDs (PIDs) and process names.
"""

import socket
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import psutil
from utils.logger import get_logger

logger = get_logger()

# Common port to service name mapping for IT and security context
WELL_KNOWN_PORTS: Dict[int, str] = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH / SFTP",
    23: "Telnet (Insecure)",
    25: "SMTP (Email)",
    53: "DNS",
    67: "DHCP Server",
    68: "DHCP Client",
    80: "HTTP (Web)",
    88: "Kerberos",
    110: "POP3 (Email)",
    123: "NTP (Time Sync)",
    135: "MS-RPC / Endpoint Mapper",
    137: "NetBIOS Name",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP (Email)",
    389: "LDAP (Active Directory)",
    443: "HTTPS (Secure Web)",
    445: "SMB / Windows File Sharing",
    465: "SMTPS",
    500: "ISAKMP / IPsec",
    514: "Syslog",
    587: "SMTP (Submission)",
    636: "LDAPS (Secure LDAP)",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5353: "mDNS",
    5432: "PostgreSQL Database",
    5900: "VNC Remote Access",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt",
}


@dataclass
class SocketConnection:
    protocol: str  # "TCP" or "UDP"
    local_address: str
    local_port: int
    remote_address: str
    remote_port: Optional[int]
    state: str  # "LISTEN", "ESTABLISHED", "TIME_WAIT", "CLOSE_WAIT", "UDP_ACTIVE"
    pid: Optional[int]
    process_name: str
    service_tag: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_service_tag(port: int) -> str:
    """Returns a friendly service name for well-known ports."""
    return WELL_KNOWN_PORTS.get(port, "")


def get_active_connections(
    protocol_filter: str = "all",
    state_filter: str = "all"
) -> List[SocketConnection]:
    """
    Scans the local machine for active TCP and UDP network sockets.
    Maps each connection to its owning process name and PID.

    :param protocol_filter: 'all', 'tcp', or 'udp'
    :param state_filter: 'all', 'listening', 'established', or specific state
    :return: List of SocketConnection dataclasses
    """
    logger.info(f"Auditing network sockets (proto={protocol_filter}, state={state_filter})...")
    connections: List[SocketConnection] = []

    # Map PIDs to process names efficiently in one pass to avoid repeated process calls
    pid_to_name: Dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid_to_name[proc.info["pid"]] = proc.info["name"] or "Unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    # Determine psutil kind parameter
    kind = "inet"  # IPv4 and IPv6 (both TCP and UDP)
    if protocol_filter.lower() == "tcp":
        kind = "tcp"
    elif protocol_filter.lower() == "udp":
        kind = "udp"

    try:
        raw_conns = psutil.net_connections(kind=kind)
    except (psutil.AccessDenied, PermissionError) as e:
        logger.warning(f"Access denied retrieving some sockets (Admin elevation recommended): {e}")
        try:
            raw_conns = psutil.net_connections(kind="tcp4")
        except Exception:
            raw_conns = []

    state_filter_norm = state_filter.lower().strip()

    for conn in raw_conns:
        # Determine protocol
        proto = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        status = conn.status if conn.status else ("NONE" if proto == "UDP" else "UNKNOWN")

        # Normalize state
        if proto == "UDP":
            display_status = "ACTIVE (UDP)"
        elif status == psutil.CONN_LISTEN:
            display_status = "LISTENING"
        elif status == psutil.CONN_ESTABLISHED:
            display_status = "ESTABLISHED"
        elif status == psutil.CONN_TIME_WAIT:
            display_status = "TIME_WAIT"
        elif status == psutil.CONN_CLOSE_WAIT:
            display_status = "CLOSE_WAIT"
        elif status == psutil.CONN_SYN_SENT:
            display_status = "SYN_SENT"
        else:
            display_status = status.upper()

        # Apply state filter
        if state_filter_norm == "listening":
            if display_status not in ["LISTENING", "ACTIVE (UDP)"]:
                continue
        elif state_filter_norm == "established":
            if display_status != "ESTABLISHED":
                continue
        elif state_filter_norm != "all":
            if display_status.lower() != state_filter_norm:
                continue

        # Extract local and remote endpoints
        local_ip = conn.laddr.ip if conn.laddr else "0.0.0.0"
        local_port = conn.laddr.port if conn.laddr else 0

        remote_ip = "*"
        remote_port = None
        if conn.raddr:
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

        # Process metadata
        pid = conn.pid
        proc_name = pid_to_name.get(pid, "System / Protected") if pid else "System / Protected"

        # Service tag
        service = get_service_tag(local_port) or (get_service_tag(remote_port) if remote_port else "")

        connections.append(SocketConnection(
            protocol=proto,
            local_address=local_ip,
            local_port=local_port,
            remote_address=remote_ip,
            remote_port=remote_port,
            state=display_status,
            pid=pid,
            process_name=proc_name,
            service_tag=service
        ))

    # Sort: Listening ports and established connections first, sorted by port
    connections.sort(key=lambda c: (c.state != "LISTENING", c.state != "ESTABLISHED", c.local_port))
    logger.info(f"Discovered {len(connections)} socket connections.")
    return connections


def get_listening_summary() -> Dict[str, Any]:
    """
    Returns quick statistical counts of listening ports, established sessions,
    and unique processes.
    """
    all_conns = get_active_connections()
    listening_count = sum(1 for c in all_conns if c.state == "LISTENING")
    established_count = sum(1 for c in all_conns if c.state == "ESTABLISHED")
    udp_count = sum(1 for c in all_conns if c.protocol == "UDP")
    unique_pids = len(set(c.pid for c in all_conns if c.pid is not None))

    return {
        "total_sockets": len(all_conns),
        "listening_tcp": listening_count,
        "established_sessions": established_count,
        "udp_endpoints": udp_count,
        "active_processes": unique_pids
    }
