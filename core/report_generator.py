"""
Report Generation & Multi-Format Exporter Engine
Assembles full diagnostic audits, formats human-readable plaintext reports,
exports structured JSON for SIEM/APIs, and exports CSV spreadsheets for Excel.
"""

import csv
import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.database import save_report
from core.dns_internet import run_internet_health_check
from core.event_analyzer import query_event_logs
from core.network_diagnostics import get_network_adapters
from core.port_scanner import get_active_connections, get_listening_summary
from core.security_checks import run_security_audit
from core.system_info import collect_system_info
from utils.logger import get_logger

logger = get_logger()

# Reports output directory
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"


def get_default_report_options() -> Dict[str, bool]:
    """Returns default section toggles for report generation."""
    return {
        "system_info": True,
        "network_config": True,
        "ports_sockets": True,
        "internet_health": True,
        "security_baseline": True,
        "event_logs": True,
    }


def assemble_full_audit_report(
    options: Optional[Dict[str, bool]] = None
) -> Dict[str, Any]:
    """
    Collects diagnostics across all toolkit modules based on selected options.
    Automatically persists a record in the local SQLite database.
    """
    logger.info("Assembling full diagnostic audit report...")
    opts = options or get_default_report_options()
    now_dt = datetime.datetime.now()
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    timestamp_filename = now_dt.strftime("%Y%m%d_%H%M%S")

    report_data: Dict[str, Any] = {
        "metadata": {
            "title": "Network & Cybersecurity IT Support Audit Report",
            "generated_at": now_str,
            "version": "1.0.0",
            "author": "NetSec IT Support Toolkit"
        }
    }

    host_name = "Unknown-Host"
    os_edition = "Windows"
    overall_score = None

    # 1. System Info
    if opts.get("system_info", True):
        sys_info = collect_system_info()
        report_data["system_info"] = sys_info.to_dict()
        host_name = sys_info.computer_name
        os_edition = sys_info.os_edition

    # 2. Network Configuration
    if opts.get("network_config", True):
        adapters = get_network_adapters()
        report_data["network_adapters"] = [a.to_dict() for a in adapters]

    # 3. Ports & Active Sockets
    if opts.get("ports_sockets", True):
        conns = get_active_connections()
        summary = get_listening_summary()
        report_data["ports_summary"] = summary
        report_data["active_sockets"] = [c.to_dict() for c in conns[:100]]  # Top 100 for report

    # 4. Internet Health Ladder
    if opts.get("internet_health", True):
        health = run_internet_health_check()
        report_data["internet_health"] = health.to_dict()

    # 5. Security Posture Audit
    if opts.get("security_baseline", True):
        sec_audit = run_security_audit()
        report_data["security_audit"] = sec_audit.to_dict()
        overall_score = sec_audit.score_percent

    # 6. Event Logs
    if opts.get("event_logs", True):
        events_res = query_event_logs(category="service_failures", time_range_hours=168, max_events=25)
        report_data["event_logs"] = events_res.to_dict()

    # Summary Text for Database Indexing
    summary_parts = []
    if "security_audit" in report_data:
        summary_parts.append(f"Security: {report_data['security_audit']['overall_posture']} ({overall_score}%)")
    if "internet_health" in report_data:
        summary_parts.append(f"Internet: {report_data['internet_health']['overall_status']}")
    if "ports_summary" in report_data:
        summary_parts.append(f"Listening Ports: {report_data['ports_summary']['listening_tcp']}")
    
    summary_text = " | ".join(summary_parts) if summary_parts else "Diagnostic audit snapshot."
    report_data["summary"] = summary_text

    # Save snapshot to SQLite DB
    report_id = save_report(
        report_type="Full Diagnostic Audit",
        host_name=host_name,
        os_edition=os_edition,
        summary_text=summary_text,
        full_report_dict=report_data,
        score_percent=overall_score
    )
    report_data["metadata"]["report_id"] = report_id
    report_data["metadata"]["filename_base"] = f"audit_report_{host_name}_{timestamp_filename}"

    logger.info(f"Audit report #{report_id} assembled successfully.")
    return report_data


# =========================================================================
# EXPORT FORMATTERS: TXT, JSON, CSV
# =========================================================================

def export_report_txt(report_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Formats report data into a clean, professional plaintext document."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    meta = report_data.get("metadata", {})
    file_base = meta.get("filename_base", "audit_report")
    out_file = Path(output_path) if output_path else REPORTS_DIR / f"{file_base}.txt"

    lines: List[str] = []
    sep = "=" * 76

    lines.append(sep)
    lines.append("  NETWORK & CYBERSECURITY IT SUPPORT AUDIT REPORT")
    lines.append(f"  Generated: {meta.get('generated_at', '')}  |  Report ID: #{meta.get('report_id', '--')}")
    lines.append(sep)
    lines.append("")

    # 1. System Info
    if "system_info" in report_data:
        s = report_data["system_info"]
        lines.append("--- [1] SYSTEM & HOST SPECIFICATIONS ---")
        lines.append(f"  Computer Name:    {s.get('computer_name')}")
        lines.append(f"  Current User:     {s.get('username')} ({s.get('elevation_status')})")
        lines.append(f"  Windows Edition:  {s.get('os_edition')}")
        lines.append(f"  OS Build:         {s.get('os_build')} ({s.get('architecture')})")
        lines.append(f"  Processor (CPU):  {s.get('cpu_model')} ({s.get('cpu_physical_cores')} Cores / {s.get('cpu_logical_cores')} Threads)")
        lines.append(f"  System Memory:    {s.get('ram_total_gb')} GB Total ({s.get('ram_used_gb')} GB Used - {s.get('ram_usage_percent')}%)")
        lines.append(f"  System Uptime:    {s.get('uptime_formatted')} (Boot: {s.get('boot_time')})")
        lines.append(f"  Python Runtime:   Python {s.get('python_version')}")
        lines.append("")

    # 2. Network Adapters
    if "network_adapters" in report_data:
        lines.append("--- [2] NETWORK INTERFACES & IP CONFIGURATION ---")
        for adp in report_data["network_adapters"]:
            if adp.get("is_up") or adp.get("ipv4") != "Not Assigned":
                dns_str = ", ".join(adp.get("dns_servers", [])) or "None"
                dhcp_str = "Enabled (Dynamic)" if adp.get("dhcp_enabled") is True else ("Disabled (Static)" if adp.get("dhcp_enabled") is False else "Unknown")
                lines.append(f"  * Interface:       {adp.get('name')} [{adp.get('status')}]")
                lines.append(f"    - IPv4 Address:  {adp.get('ipv4')} (Subnet: {adp.get('subnet_mask')})")
                lines.append(f"    - Gateway:       {adp.get('default_gateway')}")
                lines.append(f"    - DNS Servers:   {dns_str}")
                lines.append(f"    - MAC Address:   {adp.get('mac_address')}")
                lines.append(f"    - DHCP Status:   {dhcp_str}")
                lines.append("")

    # 3. Internet Health Ladder
    if "internet_health" in report_data:
        h = report_data["internet_health"]
        lines.append("--- [3] INTERNET & DNS CONNECTIVITY HEALTH LADDER ---")
        lines.append(f"  Overall Status:   {h.get('overall_status')} ({h.get('passed_count')}/6 Stages Passed)")
        lines.append(f"  Summary:          {h.get('summary_verdict')}")
        lines.append(f"  Recommendation:   {h.get('recommended_action')}")
        lines.append("")
        for stage in h.get("stages", []):
            lines.append(f"  [{stage.get('verdict')}] {stage.get('name')}: {stage.get('summary')}")
            if stage.get("details"):
                lines.append(f"      Details: {stage.get('details')}")
        lines.append("")

    # 4. Security Baseline
    if "security_audit" in report_data:
        sec = report_data["security_audit"]
        lines.append("--- [4] HOST SECURITY POSTURE BASELINE ---")
        lines.append(f"  Overall Posture:  {sec.get('overall_posture')} ({sec.get('score_percent')}% Compliance)")
        lines.append(f"  Audit Summary:    {sec.get('summary_verdict')}")
        lines.append("")
        for check in sec.get("checks", []):
            lines.append(f"  [{check.get('verdict')}] {check.get('name')} ({check.get('category')}):")
            lines.append(f"      Finding: {check.get('summary')} — {check.get('details')}")
            if check.get("remediation"):
                lines.append(f"      REMEDIATION: {check.get('remediation')}")
        lines.append("")

    # 5. Ports Summary
    if "ports_summary" in report_data:
        ps = report_data["ports_summary"]
        lines.append("--- [5] ACTIVE SOCKETS & LISTENING SERVICES ---")
        lines.append(f"  Total Sockets:     {ps.get('total_sockets')}")
        lines.append(f"  Listening TCP:     {ps.get('listening_tcp')}")
        lines.append(f"  Active Sessions:   {ps.get('established_sessions')}")
        lines.append(f"  UDP Endpoints:     {ps.get('udp_endpoints')}")
        lines.append(f"  Active Processes:  {ps.get('active_processes')}")
        lines.append("")

    # 6. Event Logs
    if "event_logs" in report_data:
        ev = report_data["event_logs"]
        lines.append("--- [6] SYSTEM & SERVICE EVENT AUDIT ---")
        lines.append(f"  Total Events:      {ev.get('total_found')} (Time Window: {ev.get('time_range_hours')}h)")
        for item in ev.get("events", [])[:10]:
            lines.append(f"  * [{item.get('time_created')}] ID {item.get('event_id')} ({item.get('level')}) {item.get('provider_name')}: {item.get('category')}")
        lines.append("")

    lines.append(sep)
    lines.append("  END OF AUDIT REPORT -- Generated by NetSec Toolkit")
    lines.append(sep)

    content = "\n".join(lines)
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(content)

    logger.info(f"Report exported to TXT: {out_file}")
    return str(out_file)


def export_report_json(report_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Exports structured report data to JSON."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    meta = report_data.get("metadata", {})
    file_base = meta.get("filename_base", "audit_report")
    out_file = Path(output_path) if output_path else REPORTS_DIR / f"{file_base}.json"

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    logger.info(f"Report exported to JSON: {out_file}")
    return str(out_file)


def export_report_csv(report_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Exports open ports and security checks to a CSV spreadsheet."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    meta = report_data.get("metadata", {})
    file_base = meta.get("filename_base", "audit_report")
    out_file = Path(output_path) if output_path else REPORTS_DIR / f"{file_base}.csv"

    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Section 1: Security Checks Table
        if "security_audit" in report_data:
            writer.writerow(["=== SECURITY BASELINE AUDIT CHECKS ==="])
            writer.writerow(["Check ID", "Check Name", "Category", "Verdict", "Summary", "Details", "Remediation"])
            for c in report_data["security_audit"].get("checks", []):
                writer.writerow([
                    c.get("check_id"),
                    c.get("name"),
                    c.get("category"),
                    c.get("verdict"),
                    c.get("summary"),
                    c.get("details"),
                    c.get("remediation") or "None"
                ])
            writer.writerow([])

        # Section 2: Active Sockets Table
        if "active_sockets" in report_data:
            writer.writerow(["=== ACTIVE NETWORK SOCKETS & PORTS ==="])
            writer.writerow(["Protocol", "Local Address", "Local Port", "Remote Address", "Remote Port", "State", "PID", "Process Name", "Service Tag"])
            for s in report_data["active_sockets"]:
                writer.writerow([
                    s.get("protocol"),
                    s.get("local_address"),
                    s.get("local_port"),
                    s.get("remote_address"),
                    s.get("remote_port") or "*",
                    s.get("state"),
                    s.get("pid") or "--",
                    s.get("process_name"),
                    s.get("service_tag")
                ])

    logger.info(f"Report exported to CSV: {out_file}")
    return str(out_file)
