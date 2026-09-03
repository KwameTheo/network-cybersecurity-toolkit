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


def get_windows_edition() -> str:
    """
    Attempts to retrieve the exact Windows Edition (e.g. 'Windows 11 Pro').
    Uses Windows Registry or PowerShell fallback.
    """
    if platform.system() != "Windows":
        return platform.system()

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        )
        product_name, _ = winreg.QueryValueEx(key, "ProductName")
        display_version, _ = winreg.QueryValueEx(key, "DisplayVersion")
        winreg.CloseKey(key)
        return f"{product_name} ({display_version})"
    except Exception:
        pass

    # Fallback to platform.win32_edition() if available
    try:
        if hasattr(platform, "win32_edition"):
            edition = platform.win32_edition()
            if edition:
                return f"Windows {platform.release()} {edition}"
    except Exception:
        pass

    return f"Windows {platform.release()}"


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
    edition = get_windows_edition()

    info = SystemInfo(
        computer_name=platform.node(),
        username=priv.username,
        os_name=platform.system(),
        os_version=platform.release(),
        os_build=platform.version(),
        os_edition=edition,
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
