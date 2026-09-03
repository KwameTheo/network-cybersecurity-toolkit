"""
Windows Event Log Analysis Engine
Queries, filters, and analyzes Windows Event Logs for authentication activity
(Logon 4624, Failed 4625, Lockout 4740), service failures, crashes, and system errors.
"""

import datetime
import json
import platform
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.privileges import is_running_as_admin
from utils.subprocess_runner import run_powershell

logger = get_logger()

# Event Category definitions
CATEGORY_META = {
    "failed_logins": {
        "name": "Failed Logins (4625)",
        "log": "Security",
        "ids": [4625],
        "requires_admin": True,
        "desc": "Authentication failures, wrong passwords, and potential brute-force attempts."
    },
    "successful_logins": {
        "name": "Successful Logins (4624)",
        "log": "Security",
        "ids": [4624],
        "requires_admin": True,
        "desc": "User and service account logon sessions."
    },
    "account_lockouts": {
        "name": "Account Lockouts (4740)",
        "log": "Security",
        "ids": [4740],
        "requires_admin": True,
        "desc": "User accounts locked out due to exceeding bad password limits."
    },
    "service_failures": {
        "name": "Service Failures (7000-7034)",
        "log": "System",
        "ids": [7000, 7001, 7009, 7022, 7023, 7024, 7031, 7032, 7034, 7043],
        "requires_admin": False,
        "desc": "Windows background services that failed to start, timed out, or terminated unexpectedly."
    },
    "system_errors": {
        "name": "System & Kernel Errors",
        "log": "System",
        "levels": [1, 2],  # Critical and Error
        "requires_admin": False,
        "desc": "Critical operating system errors, BSODs, driver faults, and kernel power events."
    },
    "app_crashes": {
        "name": "Application Crashes (1000/1002)",
        "log": "Application",
        "ids": [1000, 1001, 1002],
        "requires_admin": False,
        "desc": "Software application crashes, unhandled exceptions, and application hangs."
    }
}


@dataclass
class WindowsEvent:
    event_id: int
    log_name: str
    level: str  # "Information", "Warning", "Error", "Critical"
    time_created: str
    provider_name: str
    message: str
    category: str
    user_or_account: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventQueryResult:
    events: List[WindowsEvent]
    total_found: int
    category: str
    time_range_hours: int
    is_admin: bool
    requires_admin: bool
    admin_warning: Optional[str]
    success: bool
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _categorize_event(event_id: int, log_name: str, level: str) -> str:
    """Assigns a human-friendly category label to an event."""
    if event_id == 4625:
        return "Failed Login"
    elif event_id == 4624:
        return "Successful Login"
    elif event_id == 4740:
        return "Account Lockout"
    elif event_id in [7000, 7001, 7009, 7022, 7023, 7024, 7031, 7032, 7034, 7043]:
        return "Service Failure"
    elif event_id in [6008, 41]:
        return "Unexpected Shutdown"
    elif event_id in [1000, 1001, 1002]:
        return "App Crash / Hang"
    elif level in ["Error", "Critical"]:
        return f"{log_name} Error"
    return f"{log_name} Event"


def query_event_logs(
    category: str = "all",
    time_range_hours: int = 24,
    max_events: int = 50
) -> EventQueryResult:
    """
    Safely queries Windows Event Logs using PowerShell Get-WinEvent.

    :param category: 'all', 'failed_logins', 'successful_logins', 'account_lockouts',
                     'service_failures', 'system_errors', 'app_crashes'
    :param time_range_hours: Time window in hours (e.g. 24, 168 for 7d, 720 for 30d)
    :param max_events: Maximum number of events to retrieve
    :return: EventQueryResult
    """
    logger.info(f"Querying Windows Event Logs (category={category}, time_range={time_range_hours}h, max={max_events})...")
    admin = is_running_as_admin()

    if platform.system() != "Windows":
        return EventQueryResult(
            events=[],
            total_found=0,
            category=category,
            time_range_hours=time_range_hours,
            is_admin=admin,
            requires_admin=False,
            admin_warning=None,
            success=False,
            error_message="Windows Event Log analysis is only supported on Windows systems."
        )

    # Check if requested category requires Admin
    cat_meta = CATEGORY_META.get(category)
    needs_admin = cat_meta["requires_admin"] if cat_meta else (category in ["failed_logins", "successful_logins", "account_lockouts"])
    
    admin_warning = None
    if needs_admin and not admin:
        admin_warning = (
            f"The '{category}' category inspects the Windows Security log, which requires Administrator elevation. "
            "Please run the toolkit as Administrator to query these events."
        )
        logger.warning(admin_warning)

    # Build PowerShell FilterHashtable
    # Format: @{ LogName='System'; StartTime=(Get-Date).AddHours(-24); ... }
    ps_filter_parts = [f"StartTime=(Get-Date).AddHours(-{time_range_hours})"]

    if category == "failed_logins":
        ps_filter_parts.append("LogName='Security'")
        ps_filter_parts.append("Id=4625")
    elif category == "successful_logins":
        ps_filter_parts.append("LogName='Security'")
        ps_filter_parts.append("Id=4624")
    elif category == "account_lockouts":
        ps_filter_parts.append("LogName='Security'")
        ps_filter_parts.append("Id=4740")
    elif category == "service_failures":
        ps_filter_parts.append("LogName='System'")
        ps_filter_parts.append("Id=7000,7001,7009,7022,7023,7024,7031,7032,7034,7043")
    elif category == "system_errors":
        ps_filter_parts.append("LogName='System'")
        ps_filter_parts.append("Level=1,2")  # Critical & Error
    elif category == "app_crashes":
        ps_filter_parts.append("LogName='Application'")
        ps_filter_parts.append("Id=1000,1001,1002")
    else:
        # Category == "all"
        # If admin, query System, Application, and Security. If standard user, query System and Application.
        log_names = "'System', 'Application'"
        if admin:
            log_names = "'System', 'Application', 'Security'"
        ps_filter_parts.append(f"LogName=@({log_names})")
        ps_filter_parts.append("Level=1,2,3")  # Critical, Error, Warning

    filter_str = "; ".join(ps_filter_parts)

    ps_script = f"""
    $events = Get-WinEvent -FilterHashtable @{{{filter_str}}} -MaxEvents {max_events} -ErrorAction SilentlyContinue
    if (-not $events) {{
        @() | ConvertTo-Json
    }} else {{
        $list = @($events) | ForEach-Object {{
            $msg = if ($_.Message) {{ $_.Message.Trim() }} else {{ "" }}
            $usr = if ($_.UserId) {{ $_.UserId.Value }} else {{ "" }}
            [PSCustomObject]@{{
                Id = $_.Id
                LogName = $_.LogName
                Level = $_.LevelDisplayName
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                ProviderName = $_.ProviderName
                Message = $msg
                User = $usr
            }}
        }}
        $list | ConvertTo-Json -Compress
    }}
    """

    res = run_powershell(ps_script, timeout_seconds=20)
    events: List[WindowsEvent] = []

    if res.stdout:
        try:
            parsed = json.loads(res.stdout)
            # PowerShell ConvertTo-Json returns a dict for single object, list for multiple
            raw_list = parsed if isinstance(parsed, list) else [parsed]
            
            for item in raw_list:
                if not isinstance(item, dict) or "Id" not in item:
                    continue

                eid = int(item.get("Id", 0))
                lname = str(item.get("LogName", "System"))
                lvl = str(item.get("Level", "Information") or "Information")
                time_str = str(item.get("TimeCreated", ""))
                provider = str(item.get("ProviderName", "") or "Windows")
                msg = str(item.get("Message", "") or "No message detail.")
                user_val = str(item.get("User", "") or "")

                cat_label = _categorize_event(eid, lname, lvl)

                events.append(WindowsEvent(
                    event_id=eid,
                    log_name=lname,
                    level=lvl,
                    time_created=time_str,
                    provider_name=provider,
                    message=msg,
                    category=cat_label,
                    user_or_account=user_val
                ))
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Event Log JSON: {e} -> raw: {res.stdout[:200]}")

    logger.info(f"Retrieved {len(events)} Windows events.")
    return EventQueryResult(
        events=events,
        total_found=len(events),
        category=category,
        time_range_hours=time_range_hours,
        is_admin=admin,
        requires_admin=needs_admin,
        admin_warning=admin_warning,
        success=True
    )
