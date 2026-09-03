"""
Windows Services Manager & Hung Service Fixer Engine
Enumerates Windows background services, identifies critical IT helpdesk services,
and provides safe service lifecycle controls (start, stop, restart).
"""

import platform
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
import psutil

from utils.logger import get_logger
from utils.subprocess_runner import run_command, run_powershell
from utils.validators import sanitize_identifier

logger = get_logger()

# Key Windows services commonly handled in IT support triage
CRITICAL_SERVICES = {
    "Spooler": "Print Spooler (Manages print queue and printer communication)",
    "wuauserv": "Windows Update (Downloads and installs OS security patches)",
    "Dhcp": "DHCP Client (Registers and updates IP addresses and DNS records)",
    "Dnscache": "DNS Client (Resolves and caches domain names)",
    "W32Time": "Windows Time (Maintains date and time sync for Kerberos auth)",
    "MpsSvc": "Windows Defender Firewall (Inbound/outbound packet filtering)",
    "WinDefend": "Microsoft Defender Antivirus Service (Real-time malware protection)",
    "LanmanServer": "Server (Supports file, print, and named-pipe sharing over network)",
    "LanmanWorkstation": "Workstation (Creates and maintains client network connections)",
    "EventLog": "Windows Event Log (Logs system, security, and application events)",
    "TermService": "Remote Desktop Services (Allows remote management connections)",
}


@dataclass
class WindowsServiceInfo:
    name: str
    display_name: str
    status: str  # "running", "stopped", "paused", etc.
    start_type: str  # "automatic", "manual", "disabled"
    pid: Optional[int]
    description: str
    is_critical: bool

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceControlResult:
    service_name: str
    action: str  # "start", "stop", "restart"
    success: bool
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# SERVICE ENUMERATION
# =========================================================================

def get_windows_services() -> List[WindowsServiceInfo]:
    """
    Scans and returns all registered Windows services using psutil.
    """
    if platform.system() != "Windows":
        return []

    services: List[WindowsServiceInfo] = []

    try:
        for s in psutil.win_service_iter():
            try:
                d = s.as_dict()
                s_name = d.get("name", "")
                is_crit = s_name in CRITICAL_SERVICES

                services.append(WindowsServiceInfo(
                    name=s_name,
                    display_name=d.get("display_name", s_name),
                    status=d.get("status", "unknown").lower(),
                    start_type=d.get("start_type", "unknown").lower(),
                    pid=d.get("pid"),
                    description=d.get("description", "") or (CRITICAL_SERVICES.get(s_name, "")),
                    is_critical=is_crit
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue

        # Sort with critical services first, then alphabetically
        services.sort(key=lambda x: (not x.is_critical, x.display_name.lower()))
        logger.info(f"Discovered {len(services)} Windows services.")
        return services
    except Exception as e:
        logger.error(f"Failed to enumerate Windows services: {e}", exc_info=True)
        return []


def get_services_summary() -> Dict[str, Any]:
    """
    Returns high-level statistics on running vs stopped services.
    """
    all_svcs = get_windows_services()
    total = len(all_svcs)
    running = sum(1 for s in all_svcs if s.status == "running")
    stopped = sum(1 for s in all_svcs if s.status == "stopped")
    automatic = sum(1 for s in all_svcs if s.start_type == "automatic")
    critical_running = sum(1 for s in all_svcs if s.is_critical and s.status == "running")
    critical_total = sum(1 for s in all_svcs if s.is_critical)

    return {
        "total_services": total,
        "running_count": running,
        "stopped_count": stopped,
        "automatic_count": automatic,
        "critical_running": critical_running,
        "critical_total": critical_total,
        "services": all_svcs
    }


# =========================================================================
# SERVICE LIFECYCLE CONTROLS
# =========================================================================

def restart_windows_service(service_name: str) -> ServiceControlResult:
    """
    Safely stops and restarts a Windows service.
    """
    clean_name = sanitize_identifier(service_name)
    if not clean_name:
        return ServiceControlResult(service_name, "restart", False, "Invalid service name.")

    logger.info(f"Attempting to restart Windows service '{clean_name}'...")
    cmd = f"Restart-Service -Name '{clean_name}' -Force -ErrorAction Stop"
    res = run_powershell(cmd)

    if res.success:
        logger.info(f"Service '{clean_name}' restarted successfully.")
        return ServiceControlResult(clean_name, "restart", True, f"Service '{clean_name}' was restarted successfully.")
    else:
        err_msg = res.stderr or res.stdout or "Access Denied or Service does not accept stop control."
        logger.warning(f"Failed to restart service '{clean_name}': {err_msg}")
        return ServiceControlResult(clean_name, "restart", False, f"Failed to restart '{clean_name}': {err_msg.strip()}")


def start_windows_service(service_name: str) -> ServiceControlResult:
    """
    Starts a stopped Windows service.
    """
    clean_name = sanitize_identifier(service_name)
    if not clean_name:
        return ServiceControlResult(service_name, "start", False, "Invalid service name.")

    logger.info(f"Attempting to start Windows service '{clean_name}'...")
    res = run_command(["net", "start", clean_name])

    if res.success:
        return ServiceControlResult(clean_name, "start", True, f"Service '{clean_name}' started successfully.")
    else:
        err = res.stderr or res.stdout or "Failed to start service."
        return ServiceControlResult(clean_name, "start", False, f"Start failed: {err.strip()}")


def stop_windows_service(service_name: str) -> ServiceControlResult:
    """
    Stops a running Windows service.
    """
    clean_name = sanitize_identifier(service_name)
    if not clean_name:
        return ServiceControlResult(service_name, "stop", False, "Invalid service name.")

    logger.info(f"Attempting to stop Windows service '{clean_name}'...")
    res = run_command(["net", "stop", clean_name, "/y"])

    if res.success:
        return ServiceControlResult(clean_name, "stop", True, f"Service '{clean_name}' stopped successfully.")
    else:
        err = res.stderr or res.stdout or "Failed to stop service."
        return ServiceControlResult(clean_name, "stop", False, f"Stop failed: {err.strip()}")
