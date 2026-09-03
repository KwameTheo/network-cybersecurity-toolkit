"""
Privilege and Elevation Detection Utility
Detects whether the current process is running with Administrator privileges on Windows.
"""

import ctypes
import os
import platform
from dataclasses import dataclass
from utils.logger import get_logger

logger = get_logger()


@dataclass
class PrivilegeInfo:
    is_admin: bool
    username: str
    is_windows: bool
    elevation_status: str
    description: str


def is_running_as_admin() -> bool:
    """
    Checks if the current process has administrative / elevated privileges.
    Uses Windows API shell32.IsUserAnAdmin via ctypes.
    """
    if platform.system() != "Windows":
        # On POSIX systems (Linux/macOS), check if effective user ID is root (0)
        return hasattr(os, "geteuid") and os.geteuid() == 0

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception as e:
        logger.warning(f"Failed to check admin privileges via ctypes: {e}")
        return False


def get_privilege_info() -> PrivilegeInfo:
    """
    Returns comprehensive details about the current process execution context.
    """
    is_win = platform.system() == "Windows"
    admin = is_running_as_admin()
    
    # Attempt to retrieve current username
    try:
        username = os.getlogin()
    except Exception:
        username = os.environ.get("USERNAME", os.environ.get("USER", "Unknown"))

    if admin:
        status = "Administrator (Elevated)"
        desc = "Full administrative access. All diagnostics, event logs, and network controls are available."
    else:
        status = "Standard User"
        desc = "Running with standard user permissions. Some security event logs and DHCP controls may require elevation."

    logger.debug(f"Process privilege check: {username} -> {status}")
    return PrivilegeInfo(
        is_admin=admin,
        username=username,
        is_windows=is_win,
        elevation_status=status,
        description=desc
    )
