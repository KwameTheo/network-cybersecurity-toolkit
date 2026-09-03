"""
Windows Persistence & Autorun Inspector Engine
Scans Windows Registry Run/RunOnce keys, Startup folders, and Scheduled Tasks.
Evaluates startup binary paths using threat heuristics (MITRE ATT&CK T1547 & T1053).
"""

import json
import os
import platform
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

if platform.system() == "Windows":
    import winreg
else:
    winreg = None

from utils.logger import get_logger
from utils.subprocess_runner import run_powershell

logger = get_logger()

# Suspicious keywords indicative of script payloads or obfuscation
SUSPICIOUS_CMD_KEYWORDS = [
    "powershell -enc",
    "powershell.exe -e ",
    "powershell -windowstyle hidden",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "cmd.exe /c",
    "bitsadmin",
    "certutil -urlcache",
    "rundll32.exe",
    ".vbs",
    ".ps1",
    ".bat",
    ".cmd",
    "\\temp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
]


@dataclass
class PersistenceItem:
    name: str
    entry_type: str  # "Registry Run", "Startup Folder", "Scheduled Task"
    location: str
    command: str
    target_binary: str
    file_exists: bool
    threat_level: str  # "CLEAN", "WARNING", "SUSPICIOUS"
    threat_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PersistenceSummary:
    total_items: int
    clean_count: int
    warning_count: int
    suspicious_count: int
    registry_count: int
    startup_folder_count: int
    scheduled_task_count: int
    items: List[PersistenceItem]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# THREAT HEURISTICS EVALUATOR
# =========================================================================

def extract_target_binary(cmd_str: str) -> str:
    """Extracts the primary executable path from a command string with arguments."""
    if not cmd_str:
        return ""
    clean = cmd_str.strip()

    # If quoted e.g. "C:\Program Files\App\app.exe" --param
    if clean.startswith('"'):
        end_idx = clean.find('"', 1)
        if end_idx != -1:
            return clean[1:end_idx]
        return clean.strip('"')

    # Unquoted: split at first space or take full string
    parts = clean.split(" ")
    return parts[0]


def evaluate_persistence_threat(name: str, cmd_str: str, location: str) -> tuple[str, str, bool, List[str]]:
    """
    Analyzes an autorun entry against threat heuristics.
    Returns: (target_binary, threat_level, file_exists, reasons)
    """
    reasons: List[str] = []
    target_bin = extract_target_binary(cmd_str)
    expanded_bin = os.path.expandvars(target_bin)
    file_exists = os.path.isfile(expanded_bin) if expanded_bin else False

    cmd_lower = cmd_str.lower()
    bin_lower = expanded_bin.lower()

    # 1. Check for suspicious scripting or temp directory execution
    for kw in SUSPICIOUS_CMD_KEYWORDS:
        if kw in cmd_lower or kw in bin_lower:
            reasons.append(f"Contains suspicious execution pattern: '{kw}'")

    # 2. Check for missing binary on disk
    if target_bin and not file_exists and not target_bin.startswith("%"):
        reasons.append(f"Referenced target binary does not exist on disk ({expanded_bin})")

    # 3. Check for unquoted spaces in path (Unquoted Service / Run Path vulnerability)
    if " " in target_bin and not cmd_str.strip().startswith('"'):
        reasons.append("Unquoted executable path with spaces (vulnerable to binary hijacking)")

    # 4. Determine overall Threat Level
    if any("suspicious" in r.lower() for r in reasons):
        threat_level = "SUSPICIOUS"
    elif reasons:
        threat_level = "WARNING"
    else:
        threat_level = "CLEAN"

    return target_bin, threat_level, file_exists, reasons


# =========================================================================
# PERSISTENCE SCANNERS
# =========================================================================

def scan_registry_run_keys() -> List[PersistenceItem]:
    """Scans user and system Windows Registry Run / RunOnce keys."""
    if platform.system() != "Windows" or winreg is None:
        return []

    registry_targets = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run (Current User)"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce (Current User)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (All Users)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (All Users)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM WOW6432 Run (32-bit All Users)"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM WOW6432 RunOnce (32-bit All Users)")
    ]

    items: List[PersistenceItem] = []

    for hkey, subkey, label in registry_targets:
        try:
            with winreg.OpenKey(hkey, subkey) as key:
                num_vals = winreg.QueryInfoKey(key)[1]
                for i in range(num_vals):
                    try:
                        v_name, v_cmd, _ = winreg.EnumValue(key, i)
                        if not v_cmd:
                            continue

                        target_bin, threat, exists, reasons = evaluate_persistence_threat(v_name, str(v_cmd), label)
                        items.append(PersistenceItem(
                            name=v_name or "Unnamed Registry Autorun",
                            entry_type="Registry Run",
                            location=label,
                            command=str(v_cmd),
                            target_binary=target_bin,
                            file_exists=exists,
                            threat_level=threat,
                            threat_reasons=reasons
                        ))
                    except Exception:
                        continue
        except Exception:
            continue

    return items


def scan_startup_folders() -> List[PersistenceItem]:
    """Scans user and system Startup shortcut directories."""
    appdata = os.environ.get("APPDATA", "")
    program_data = os.environ.get("ProgramData", "C:\\ProgramData")

    folders = [
        (os.path.join(appdata, r"Microsoft\Windows\Start Menu\Programs\Startup"), "User Startup Folder (%APPDATA%)"),
        (os.path.join(program_data, r"Microsoft\Windows\Start Menu\Programs\Startup"), "Common Startup Folder (%ProgramData%)")
    ]

    items: List[PersistenceItem] = []

    for folder_path, label in folders:
        if not os.path.exists(folder_path):
            continue

        try:
            for f in os.listdir(folder_path):
                # Ignore desktop.ini
                if f.lower() == "desktop.ini":
                    continue

                full_p = os.path.join(folder_path, f)
                target_bin, threat, exists, reasons = evaluate_persistence_threat(f, full_p, label)

                items.append(PersistenceItem(
                    name=f,
                    entry_type="Startup Folder",
                    location=label,
                    command=full_p,
                    target_binary=full_p,
                    file_exists=exists,
                    threat_level=threat,
                    threat_reasons=reasons
                ))
        except Exception as e:
            logger.warning(f"Error scanning startup folder '{folder_path}': {e}")

    return items


def scan_scheduled_tasks() -> List[PersistenceItem]:
    """Queries non-Microsoft third-party and custom scheduled tasks."""
    if platform.system() != "Windows":
        return []

    cmd = "Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\Windows*' } | Select-Object -Property TaskName, TaskPath, State, @{Name='Execute';Expression={$_.Actions.Execute}}, @{Name='Arguments';Expression={$_.Actions.Arguments}} | ConvertTo-Json"
    res = run_powershell(cmd)

    items: List[PersistenceItem] = []
    if not res.success or not res.stdout:
        return items

    try:
        data = json.loads(res.stdout)
        if isinstance(data, dict):
            data = [data]

        for t in data:
            t_name = t.get("TaskName") or "Unknown Task"
            t_path = t.get("TaskPath") or "\\"
            exec_bin = t.get("Execute") or ""
            args = t.get("Arguments") or ""
            full_cmd = f"{exec_bin} {args}".strip() or t_name
            full_loc = f"Task Scheduler: {t_path}"

            target_bin, threat, exists, reasons = evaluate_persistence_threat(t_name, full_cmd, full_loc)
            items.append(PersistenceItem(
                name=t_name,
                entry_type="Scheduled Task",
                location=full_loc,
                command=full_cmd,
                target_binary=target_bin or exec_bin,
                file_exists=exists if exec_bin else True,
                threat_level=threat,
                threat_reasons=reasons
            ))
    except Exception as e:
        logger.warning(f"Error parsing scheduled tasks: {e}")

    return items


def run_persistence_audit() -> PersistenceSummary:
    """
    Executes a complete persistence audit across Registry, Startup folders, and Scheduled tasks.
    """
    reg_items = scan_registry_run_keys()
    startup_items = scan_startup_folders()
    task_items = scan_scheduled_tasks()

    all_items = reg_items + startup_items + task_items

    # Sort with Suspicious/Warning first, then by type
    threat_order = {"SUSPICIOUS": 0, "WARNING": 1, "CLEAN": 2}
    all_items.sort(key=lambda x: (threat_order.get(x.threat_level, 3), x.name.lower()))

    clean_count = sum(1 for i in all_items if i.threat_level == "CLEAN")
    warning_count = sum(1 for i in all_items if i.threat_level == "WARNING")
    suspicious_count = sum(1 for i in all_items if i.threat_level == "SUSPICIOUS")

    logger.info(f"Persistence Audit Complete: {len(all_items)} items ({suspicious_count} suspicious, {warning_count} warnings).")

    return PersistenceSummary(
        total_items=len(all_items),
        clean_count=clean_count,
        warning_count=warning_count,
        suspicious_count=suspicious_count,
        registry_count=len(reg_items),
        startup_folder_count=len(startup_items),
        scheduled_task_count=len(task_items),
        items=all_items
    )
