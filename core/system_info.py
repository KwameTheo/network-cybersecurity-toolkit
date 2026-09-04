"""
System Information Engine
Gathers host specifications, operating system details, CPU, RAM metrics,
privilege level, and system uptime.
"""

import datetime
import os
import platform
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict

import psutil
from utils.logger import get_logger
from utils.privileges import get_privilege_info
from utils.subprocess_runner import run_powershell

logger = get_logger()


@dataclass
class SystemInfo:
    computer_name: str
    username: str
    os_name: str
    os_version: str
    os_build: str
    os_edition: str
    cpu_model: str
    cpu_physical_cores: int
    cpu_logical_cores: int
    cpu_usage_percent: float
    ram_total_gb: float
    ram_used_gb: float
    ram_available_gb: float
    ram_usage_percent: float
    architecture: str
    python_version: str
    boot_time: str
    uptime_formatted: str
    uptime_seconds: float
    is_admin: bool
    elevation_status: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def get_os_details() -> Dict[str, str]:
    """
    Accurately detects OS Name, OS Version (e.g. '11' vs '10'), Build Number (with UBR),
    and exact Windows Edition (e.g. 'Windows 11 Pro (23H2)').
    
    Resolves Microsoft's legacy backward-compatibility behavior where Windows 11
    identifies as 'Windows 10' or major version 10 in standard Python/platform APIs.
    """
    if platform.system() != "Windows":
        return {
            "os_name": platform.system(),
            "os_version": platform.release(),
            "os_build": platform.version(),
            "os_edition": f"{platform.system()} {platform.release()}"
        }

    build_num = 0
    try:
        build_num = sys.getwindowsversion().build
    except Exception:
        pass

    product_name = ""
    display_version = ""
    release_id = ""
    edition_id = ""
    installation_type = ""
    ubr = None

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        for var, name in [
            ("product_name", "ProductName"),
            ("display_version", "DisplayVersion"),
            ("release_id", "ReleaseId"),
            ("edition_id", "EditionID"),
            ("installation_type", "InstallationType"),
            ("current_build", "CurrentBuildNumber"),
            ("ubr", "UBR")
        ]:
            try:
                val, _ = winreg.QueryValueEx(key, name)
                if var == "product_name" and val:
                    product_name = str(val).strip()
                elif var == "display_version" and val:
                    display_version = str(val).strip()
                elif var == "release_id" and val and not display_version:
                    display_version = str(val).strip()
                elif var == "edition_id" and val:
                    edition_id = str(val).strip()
                elif var == "installation_type" and val:
                    installation_type = str(val).strip()
                elif var == "current_build" and val and not build_num:
                    try:
                        build_num = int(val)
                    except ValueError:
                        pass
                elif var == "ubr" and val is not None:
                    try:
                        ubr = int(val)
                    except ValueError:
                        pass
            except Exception:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass

    # Determine Server vs Client
    is_server = (
        "server" in installation_type.lower()
        or "server" in product_name.lower()
        or "server" in edition_id.lower()
    )

    if is_server:
        if build_num >= 26100:
            os_version = "Server 2025"
        elif build_num >= 20348:
            os_version = "Server 2022"
        elif build_num >= 17763:
            os_version = "Server 2019"
        elif build_num >= 14393:
            os_version = "Server 2016"
        else:
            os_version = platform.release()
    elif build_num >= 22000:
        # Windows 11 builds start at 22000 (21H2=22000, 22H2=22621, 23H2=22631, 24H2=26100+)
        os_version = "11"
        if "Windows 10" in product_name:
            product_name = product_name.replace("Windows 10", "Windows 11")
        elif not product_name or "Windows" not in product_name:
            if edition_id:
                pretty_edition = "Pro" if "Pro" in edition_id else ("Home" if "Core" in edition_id else edition_id)
                product_name = f"Windows 11 {pretty_edition}"
            else:
                product_name = "Windows 11"
    elif build_num >= 10240:
        os_version = "10"
        if not product_name:
            if edition_id:
                pretty_edition = "Pro" if "Pro" in edition_id else ("Home" if "Core" in edition_id else edition_id)
                product_name = f"Windows 10 {pretty_edition}"
            else:
                product_name = "Windows 10"
    else:
        os_version = platform.release()

    # Format OS Edition
    if display_version and product_name:
        os_edition = f"{product_name} ({display_version})"
    elif product_name:
        os_edition = product_name
    else:
        os_edition = f"Windows {os_version}"

    # Format Full Build (incorporating UBR if available)
    raw_build = platform.version() or (f"10.0.{build_num}" if build_num else "")
    if ubr and raw_build and raw_build.count(".") == 2:
        os_build = f"{raw_build}.{ubr}"
    else:
        os_build = raw_build

    return {
        "os_name": platform.system(),
        "os_version": os_version,
        "os_build": os_build,
        "os_edition": os_edition
    }


def get_windows_edition() -> str:
    """
    Attempts to retrieve the exact Windows Edition (e.g. 'Windows 11 Pro (23H2)').
    """
    return get_os_details()["os_edition"]


def get_cpu_info() -> Dict[str, Any]:
    """Retrieves CPU model name, core counts, and current utilization."""
    model = platform.processor() or "Unknown Processor"

    # On Windows, platform.processor() often returns a generic identifier like 'Intel64 Family 6 Model...'
    # We can get the friendly name from the registry or WMI
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
            )
            friendly_name, _ = winreg.QueryValueEx(key, "ProcessorNameString")
            winreg.CloseKey(key)
            if friendly_name:
                model = friendly_name.strip()
        except Exception:
            pass

    physical_cores = psutil.cpu_count(logical=False) or 1
    logical_cores = psutil.cpu_count(logical=True) or 1
    cpu_percent = psutil.cpu_percent(interval=0.1)

    return {
        "model": model,
        "physical_cores": physical_cores,
        "logical_cores": logical_cores,
        "usage_percent": cpu_percent
    }


def get_ram_info() -> Dict[str, float]:
    """Retrieves RAM metrics in Gigabytes (GB) and percentage."""
    mem = psutil.virtual_memory()
    gb = 1024 ** 3
    return {
        "total_gb": round(mem.total / gb, 2),
        "used_gb": round(mem.used / gb, 2),
        "available_gb": round(mem.available / gb, 2),
        "usage_percent": mem.percent
    }


def format_uptime(seconds: float) -> str:
    """Formats raw uptime seconds into 'X days, Y hours, Z mins, S secs'."""
    td = datetime.timedelta(seconds=int(seconds))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def get_uptime_info() -> Dict[str, Any]:
    """Retrieves system boot time and elapsed uptime."""
    boot_timestamp = psutil.boot_time()
    boot_dt = datetime.datetime.fromtimestamp(boot_timestamp)
    now_ts = time.time()
    uptime_sec = max(0.0, now_ts - boot_timestamp)

    return {
        "boot_time": boot_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "uptime_seconds": uptime_sec,
        "uptime_formatted": format_uptime(uptime_sec)
    }


def collect_system_info() -> SystemInfo:
    """
    Collects a complete snapshot of host system specifications.
    """
    logger.info("Collecting host system information...")
    priv = get_privilege_info()
    cpu = get_cpu_info()
    ram = get_ram_info()
    uptime = get_uptime_info()
    os_details = get_os_details()

    info = SystemInfo(
        computer_name=platform.node(),
        username=priv.username,
        os_name=os_details["os_name"],
        os_version=os_details["os_version"],
        os_build=os_details["os_build"],
        os_edition=os_details["os_edition"],
        cpu_model=cpu["model"],
        cpu_physical_cores=cpu["physical_cores"],
        cpu_logical_cores=cpu["logical_cores"],
        cpu_usage_percent=cpu["usage_percent"],
        ram_total_gb=ram["total_gb"],
        ram_used_gb=ram["used_gb"],
        ram_available_gb=ram["available_gb"],
        ram_usage_percent=ram["usage_percent"],
        architecture=f"{platform.machine()} ({platform.architecture()[0]})",
        python_version=platform.python_version(),
        boot_time=uptime["boot_time"],
        uptime_formatted=uptime["uptime_formatted"],
        uptime_seconds=uptime["uptime_seconds"],
        is_admin=priv.is_admin,
        elevation_status=priv.elevation_status
    )
    logger.info("System information collected successfully.")
    return info
