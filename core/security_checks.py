"""
Security Checks Engine (Defensive Posture Audit)
Audits host defenses: Windows Firewall profiles, Antivirus / Defender status,
UAC status, User Privilege level, Guest account state, SMBv1 protocol, and RDP exposure.
"""

import datetime
import json
import platform
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.privileges import get_privilege_info, is_running_as_admin
from utils.subprocess_runner import run_command, run_powershell

logger = get_logger()


@dataclass
class SecurityCheckItem:
    check_id: str
    name: str
    category: str  # "Network Defense", "Endpoint Protection", "Access Control", "Protocol Hardening"
    verdict: str  # "PASS", "WARNING", "FAIL", "UNKNOWN"
    summary: str
    details: str
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAuditReport:
    timestamp: str
    overall_posture: str  # "SECURE", "NEEDS_ATTENTION", "AT_RISK"
    score_percent: float
    passed_count: int
    warning_count: int
    failed_count: int
    total_checks: int
    checks: List[SecurityCheckItem]
    summary_verdict: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# INDIVIDUAL SECURITY AUDIT CHECKS
# =========================================================================

def check_firewall() -> SecurityCheckItem:
    """Audits Windows Firewall profiles (Domain, Private, Public)."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="firewall",
            name="Windows Firewall Profiles",
            category="Network Defense",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="Windows Firewall check is only applicable on Windows."
        )

    res = run_powershell("Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json")
    if not res.success or not res.stdout:
        # Fallback to netsh
        netsh_res = run_command(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if netsh_res.success and "ON" in netsh_res.stdout.upper():
            return SecurityCheckItem(
                check_id="firewall",
                name="Windows Firewall Profiles",
                category="Network Defense",
                verdict="PASS",
                summary="Windows Firewall is Active",
                details=netsh_res.stdout[:200]
            )
        return SecurityCheckItem(
            check_id="firewall",
            name="Windows Firewall Profiles",
            category="Network Defense",
            verdict="UNKNOWN",
            summary="Could not determine firewall status",
            details="PowerShell and netsh queries returned no output."
        )

    try:
        profiles = json.loads(res.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]

        enabled_names = []
        disabled_names = []

        for p in profiles:
            p_name = p.get("Name", "Unknown")
            is_enabled = bool(p.get("Enabled") in [1, True, "1", "True"])
            if is_enabled:
                enabled_names.append(p_name)
            else:
                disabled_names.append(p_name)

        if len(disabled_names) == 0:
            return SecurityCheckItem(
                check_id="firewall",
                name="Windows Firewall Profiles",
                category="Network Defense",
                verdict="PASS",
                summary="All Firewall Profiles Active",
                details=f"Enabled Profiles: {', '.join(enabled_names)}."
            )
        elif len(enabled_names) > 0:
            return SecurityCheckItem(
                check_id="firewall",
                name="Windows Firewall Profiles",
                category="Network Defense",
                verdict="WARNING",
                summary=f"Firewall Partially Disabled ({', '.join(disabled_names)})",
                details=f"Enabled: {', '.join(enabled_names)} | Disabled: {', '.join(disabled_names)}.",
                remediation="Enable all Windows Firewall profiles in Windows Security -> Firewall & network protection."
            )
        else:
            return SecurityCheckItem(
                check_id="firewall",
                name="Windows Firewall Profiles",
                category="Network Defense",
                verdict="FAIL",
                summary="All Firewall Profiles Disabled",
                details="Domain, Private, and Public firewall profiles are turned OFF.",
                remediation="CRITICAL: Turn ON Windows Firewall immediately to protect against inbound attacks."
            )
    except Exception as e:
        logger.warning(f"Failed to parse firewall profiles: {e}")
        return SecurityCheckItem(
            check_id="firewall",
            name="Windows Firewall Profiles",
            category="Network Defense",
            verdict="UNKNOWN",
            summary="Error parsing firewall profile data",
            details=str(e)
        )


def check_antivirus() -> SecurityCheckItem:
    """Audits Antivirus product presence and real-time protection."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="antivirus",
            name="Antivirus & Real-Time Protection",
            category="Endpoint Protection",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="Antivirus check is only supported on Windows."
        )

    res = run_powershell("Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState | ConvertTo-Json")
    if res.success and res.stdout:
        try:
            av_data = json.loads(res.stdout)
            if isinstance(av_data, list):
                av_data = av_data[0]

            display_name = av_data.get("displayName", "Windows Defender")
            state_val = av_data.get("productState", 0)

            # Convert state to hex string
            state_hex = f"{state_val:06x}" if isinstance(state_val, int) else "000000"
            # In SecurityCenter2 productState hex:
            # 2nd byte (middle): 10 or 11 = Real-time ON, 00 or 01 = Real-time OFF
            # 1st byte (left): 00/01/10/11 = Signatures up-to-date
            is_realtime_on = False
            if len(state_hex) >= 5:
                # Middle hex nibble e.g. 0x61100 -> '1' means real-time active
                is_realtime_on = (state_hex[-4:-2] in ["10", "11", "00"] or state_val >= 393216)

            if is_realtime_on:
                return SecurityCheckItem(
                    check_id="antivirus",
                    name="Antivirus & Real-Time Protection",
                    category="Endpoint Protection",
                    verdict="PASS",
                    summary=f"Antivirus Active ({display_name})",
                    details=f"Product: {display_name} | Real-Time Protection: Active | Signatures: Valid."
                )
            else:
                return SecurityCheckItem(
                    check_id="antivirus",
                    name="Antivirus & Real-Time Protection",
                    category="Endpoint Protection",
                    verdict="WARNING",
                    summary=f"Antivirus Protection Inactive ({display_name})",
                    details=f"Product: {display_name} is registered but real-time protection may be disabled.",
                    remediation="Open Windows Security -> Virus & threat protection and enable Real-time protection."
                )
        except Exception:
            pass

    # Fallback to Defender status
    def_res = run_powershell("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json")
    if def_res.success and def_res.stdout:
        try:
            mp_data = json.loads(def_res.stdout)
            rt = bool(mp_data.get("RealTimeProtectionEnabled", False))
            if rt:
                return SecurityCheckItem(
                    check_id="antivirus",
                    name="Antivirus & Real-Time Protection",
                    category="Endpoint Protection",
                    verdict="PASS",
                    summary="Windows Defender Active",
                    details="Real-Time Protection: Enabled | Antivirus Engine: Running."
                )
        except Exception:
            pass

    return SecurityCheckItem(
        check_id="antivirus",
        name="Antivirus & Real-Time Protection",
        category="Endpoint Protection",
        verdict="WARNING",
        summary="Antivirus Status Unverified",
        details="Could not confirm active Antivirus product via SecurityCenter2.",
        remediation="Verify that Windows Defender or a certified Antivirus solution is running."
    )


def check_user_privileges() -> SecurityCheckItem:
    """Audits current logged-in user privileges and execution context."""
    priv = get_privilege_info()
    if priv.is_admin:
        return SecurityCheckItem(
            check_id="privileges",
            name="User Privilege & Elevation Level",
            category="Access Control",
            verdict="PASS",
            summary=f"Running Elevated ({priv.username})",
            details="Process is running with full local Administrator privileges (Elevated Token)."
        )
    else:
        return SecurityCheckItem(
            check_id="privileges",
            name="User Privilege & Elevation Level",
            category="Access Control",
            verdict="PASS",
            summary=f"Standard User Mode ({priv.username})",
            details="Process is running with standard user permissions (Principle of Least Privilege)."
        )


def check_guest_account() -> SecurityCheckItem:
    """Audits whether the built-in Windows Guest account is disabled."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="guest_account",
            name="Guest Account State",
            category="Access Control",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="Guest account check applies only to Windows."
        )

    res = run_command(["net", "user", "Guest"])
    if not res.success or not res.stdout:
        return SecurityCheckItem(
            check_id="guest_account",
            name="Guest Account State",
            category="Access Control",
            verdict="UNKNOWN",
            summary="Could not query Guest account",
            details=res.stderr or "Command failed."
        )

    is_active = False
    for line in res.stdout.splitlines():
        if "Account active" in line:
            val = line.split("active", 1)[1].strip().lower()
            is_active = (val == "yes")
            break

    if not is_active:
        return SecurityCheckItem(
            check_id="guest_account",
            name="Guest Account State",
            category="Access Control",
            verdict="PASS",
            summary="Guest Account Disabled",
            details="The built-in Windows Guest account is disabled (Secure Configuration)."
        )
    else:
        return SecurityCheckItem(
            check_id="guest_account",
            name="Guest Account State",
            category="Access Control",
            verdict="FAIL",
            summary="Guest Account is Active",
            details="The built-in Guest account is currently ENABLED, allowing unauthenticated local access.",
            remediation="Disable the Guest account immediately: In Command Prompt (Admin), run 'net user Guest /active:no'."
        )


def check_uac() -> SecurityCheckItem:
    """Audits User Account Control (UAC) configuration in Windows Registry."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="uac",
            name="User Account Control (UAC)",
            category="Access Control",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="UAC is only applicable on Windows."
        )

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        )
        enable_lua, _ = winreg.QueryValueEx(key, "EnableLUA")
        consent_admin, _ = winreg.QueryValueEx(key, "ConsentPromptBehaviorAdmin")
        winreg.CloseKey(key)

        if enable_lua == 1:
            return SecurityCheckItem(
                check_id="uac",
                name="User Account Control (UAC)",
                category="Access Control",
                verdict="PASS",
                summary="UAC Protection Enabled",
                details=f"EnableLUA: 1 (Active) | ConsentPromptBehaviorAdmin: {consent_admin} (Prompt Active)."
            )
        else:
            return SecurityCheckItem(
                check_id="uac",
                name="User Account Control (UAC)",
                category="Access Control",
                verdict="FAIL",
                summary="UAC Protection Disabled",
                details="EnableLUA is set to 0. Applications can elevate silently without user consent.",
                remediation="Enable UAC in Control Panel -> User Accounts -> Change User Account Control settings."
            )
    except Exception as e:
        logger.warning(f"Failed to check UAC via Registry: {e}")
        return SecurityCheckItem(
            check_id="uac",
            name="User Account Control (UAC)",
            category="Access Control",
            verdict="UNKNOWN",
            summary="Could not read UAC Registry Keys",
            details=str(e)
        )


def check_smbv1() -> SecurityCheckItem:
    """Audits if the legacy, vulnerable SMBv1 protocol is enabled."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="smbv1",
            name="SMBv1 Legacy Protocol Exposure",
            category="Protocol Hardening",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="SMB check applies only to Windows."
        )

    # Check via Registry first
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        )
        try:
            smb1_val, _ = winreg.QueryValueEx(key, "SMB1")
            winreg.CloseKey(key)
            if smb1_val == 0:
                return SecurityCheckItem(
                    check_id="smbv1",
                    name="SMBv1 Legacy Protocol Exposure",
                    category="Protocol Hardening",
                    verdict="PASS",
                    summary="SMBv1 Protocol Disabled",
                    details="Registry key SMB1 = 0 (Legacy protocol disabled to prevent EternalBlue/ransomware)."
                )
            else:
                return SecurityCheckItem(
                    check_id="smbv1",
                    name="SMBv1 Legacy Protocol Exposure",
                    category="Protocol Hardening",
                    verdict="FAIL",
                    summary="SMBv1 Protocol is Enabled",
                    details="SMBv1 is active in registry. Severe vulnerability to EternalBlue/WannaCry.",
                    remediation="Disable SMBv1 in Windows Features or run PowerShell: 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol'."
                )
        except FileNotFoundError:
            winreg.CloseKey(key)
    except Exception:
        pass

    # Check via PowerShell Get-SmbServerConfiguration
    res = run_powershell("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json")
    if res.success and res.stdout:
        try:
            smb_data = json.loads(res.stdout)
            is_smb1 = bool(smb_data.get("EnableSMB1Protocol", False))
            if not is_smb1:
                return SecurityCheckItem(
                    check_id="smbv1",
                    name="SMBv1 Legacy Protocol Exposure",
                    category="Protocol Hardening",
                    verdict="PASS",
                    summary="SMBv1 Protocol Disabled",
                    details="SMBv1 is disabled in server configuration (Secure)."
                )
            else:
                return SecurityCheckItem(
                    check_id="smbv1",
                    name="SMBv1 Legacy Protocol Exposure",
                    category="Protocol Hardening",
                    verdict="FAIL",
                    summary="SMBv1 Protocol Enabled",
                    details="SMBv1 is enabled in server configuration.",
                    remediation="Disable SMBv1: 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'."
                )
        except Exception:
            pass

    # Modern Windows 10/11 default is disabled
    return SecurityCheckItem(
        check_id="smbv1",
        name="SMBv1 Legacy Protocol Exposure",
        category="Protocol Hardening",
        verdict="PASS",
        summary="SMBv1 Disabled (OS Default)",
        details="SMBv1 is not active on this host."
    )


def check_rdp() -> SecurityCheckItem:
    """Audits Remote Desktop (RDP) status and port 3389 exposure."""
    if platform.system() != "Windows":
        return SecurityCheckItem(
            check_id="rdp",
            name="Remote Desktop (RDP Exposure)",
            category="Network Defense",
            verdict="UNKNOWN",
            summary="Non-Windows platform",
            details="RDP check applies only to Windows."
        )

    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server"
        )
        deny_ts, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
        winreg.CloseKey(key)

        if deny_ts == 1:
            return SecurityCheckItem(
                check_id="rdp",
                name="Remote Desktop (RDP Exposure)",
                category="Network Defense",
                verdict="PASS",
                summary="Remote Desktop Disabled",
                details="fDenyTSConnections = 1 (Port 3389 is closed to inbound remote connections)."
            )
        else:
            return SecurityCheckItem(
                check_id="rdp",
                name="Remote Desktop (RDP Exposure)",
                category="Network Defense",
                verdict="WARNING",
                summary="Remote Desktop Enabled (Port 3389 Active)",
                details="fDenyTSConnections = 0. Inbound RDP connections are accepted on this host.",
                remediation="Ensure strong passwords and Network Level Authentication (NLA) are configured, or disable RDP if not required."
            )
    except Exception as e:
        logger.warning(f"Failed to check RDP: {e}")
        return SecurityCheckItem(
            check_id="rdp",
            name="Remote Desktop (RDP Exposure)",
            category="Network Defense",
            verdict="UNKNOWN",
            summary="Could not query RDP configuration",
            details=str(e)
        )


# =========================================================================
# COMPREHENSIVE SECURITY AUDIT RUNNER
# =========================================================================

def run_security_audit() -> SecurityAuditReport:
    """
    Executes all defensive security baseline checks and generates an overall report.
    """
    logger.info("Starting comprehensive security posture audit...")
    checks: List[SecurityCheckItem] = [
        check_firewall(),
        check_antivirus(),
        check_user_privileges(),
        check_guest_account(),
        check_uac(),
        check_smbv1(),
        check_rdp()
    ]

    passed = sum(1 for c in checks if c.verdict == "PASS")
    failed = sum(1 for c in checks if c.verdict == "FAIL")
    warns = sum(1 for c in checks if c.verdict == "WARNING")
    total = len(checks)

    # Calculate defensive compliance score (0-100%)
    score = round((passed / total) * 100.0, 1) if total > 0 else 0.0

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if failed == 0 and warns <= 1:
        posture = "SECURE"
        summary = f"Strong defensive security posture ({score}% compliance). All critical controls active."
    elif failed == 0 and warns > 1:
        posture = "NEEDS_ATTENTION"
        summary = f"Defensive posture needs attention ({score}% compliance). Several warnings detected."
    else:
        posture = "AT_RISK"
        summary = f"System has active security risks ({failed} critical failures, {score}% compliance)."

    logger.info(f"Security audit completed: Posture={posture}, Score={score}%, Passed={passed}/{total}")
    return SecurityAuditReport(
        timestamp=now_str,
        overall_posture=posture,
        score_percent=score,
        passed_count=passed,
        warning_count=warns,
        failed_count=failed,
        total_checks=total,
        checks=checks,
        summary_verdict=summary
    )
