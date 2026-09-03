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


def export_report_pdf(report_data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Exports an executive, styled, print-ready PDF audit report."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    meta = report_data.get("metadata", {})
    file_base = meta.get("filename_base", "audit_report")
    out_file = Path(output_path) if output_path else REPORTS_DIR / f"{file_base}.pdf"

    doc = SimpleDocTemplate(
        str(out_file),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#1E3A8A"),
        fontName="Helvetica-Bold"
    )
    subtitle_style = ParagraphStyle(
        "DocSub",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4B5563")
    )
    section_style = ParagraphStyle(
        "DocSection",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E40AF"),
        fontName="Helvetica-Bold",
        spaceBefore=10,
        spaceAfter=5
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1F2937")
    )
    badge_style = ParagraphStyle(
        "BadgeStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.white,
        fontName="Helvetica-Bold",
        alignment=1
    )

    story = []

    # Header
    story.append(Paragraph("NETWORK & CYBERSECURITY AUDIT REPORT", title_style))
    story.append(Paragraph("IT Support Diagnostics & Defensive Compliance Baseline", subtitle_style))
    story.append(Spacer(1, 8))

    # Metadata Table
    sys_info = report_data.get("system_info", {})
    sec_audit = report_data.get("security_audit", {})
    meta_data = [
        [
            Paragraph("<b>Host Name:</b>", body_style),
            Paragraph(sys_info.get("computer_name", "--"), body_style),
            Paragraph("<b>Generated:</b>", body_style),
            Paragraph(meta.get("generated_at", "--"), body_style)
        ],
        [
            Paragraph("<b>OS Edition:</b>", body_style),
            Paragraph(sys_info.get("os_edition", "--"), body_style),
            Paragraph("<b>Operator:</b>", body_style),
            Paragraph(sys_info.get("username", "--"), body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[75, 195, 75, 195])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F3F4F6")),
        ("PADDING", (0, 0), (-1, -1), 3),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D1D5DB")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # Posture Banner
    if sec_audit:
        score = sec_audit.get("score_percent", 0.0)
        rating = sec_audit.get("posture_rating", "UNKNOWN")
        passed = sec_audit.get("passed_checks", 0)
        total_chk = sec_audit.get("total_checks", 0)

        banner_color = colors.HexColor("#059669") if rating == "SECURE" else (colors.HexColor("#D97706") if rating == "NEEDS_ATTENTION" else colors.HexColor("#DC2626"))
        banner_data = [[
            Paragraph(f"OVERALL COMPLIANCE SCORE: {score:.1f}% ({rating}) — Passed {passed}/{total_chk} Baseline Checks", badge_style)
        ]]
        banner_table = Table(banner_data, colWidths=[540])
        banner_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), banner_color),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ]))
        story.append(banner_table)
        story.append(Spacer(1, 8))

    # 1. Security Checklist Table
    if sec_audit and sec_audit.get("checks"):
        story.append(Paragraph("1. Defensive Security Baseline Audit", section_style))
        chk_rows = [["Status", "Audit Item", "Category", "Finding Summary"]]
        for c in sec_audit.get("checks", []):
            verdict = c.get("verdict")
            v_color = "#166534" if verdict == "PASS" else "#991B1B"
            v_p = Paragraph(f"<b><font color='{v_color}'>{verdict}</font></b>", body_style)
            name_p = Paragraph(c.get("name", "--"), body_style)
            cat_p = Paragraph(c.get("category", "--"), body_style)
            sum_p = Paragraph(c.get("summary", "--"), body_style)
            chk_rows.append([v_p, name_p, cat_p, sum_p])

        chk_table = Table(chk_rows, colWidths=[50, 150, 100, 240])
        chk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E3A8A")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 3),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ]))
        story.append(chk_table)
        story.append(Spacer(1, 8))

    # 2. Network Configuration Table
    if "network_adapters" in report_data:
        story.append(Paragraph("2. Active Network Adapters", section_style))
        adp_rows = [["Interface Name", "Status", "IPv4 Address", "Default Gateway"]]
        for a in report_data.get("network_adapters", [])[:5]:
            st = "Connected" if a.get("is_up") else "Disconnected"
            adp_rows.append([
                Paragraph(a.get("name", "--"), body_style),
                Paragraph(st, body_style),
                Paragraph(a.get("ipv4", "--"), body_style),
                Paragraph(a.get("default_gateway") or "None", body_style)
            ])
        adp_table = Table(adp_rows, colWidths=[150, 80, 155, 155])
        adp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("PADDING", (0, 0), (-1, -1), 3),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
        ]))
        story.append(adp_table)
        story.append(Spacer(1, 8))

    # 3. Active Listening Ports
    if "active_sockets" in report_data:
        story.append(Paragraph("3. Active Listening Services & Ports", section_style))
        port_rows = [["Proto", "Port", "State", "PID", "Process Name", "Service"]]
        listen_sockets = [s for s in report_data.get("active_sockets", []) if s.get("state") in ["LISTENING", "ACTIVE (UDP)"]][:8]
        for s in listen_sockets:
            port_rows.append([
                Paragraph(s.get("protocol", "--"), body_style),
                Paragraph(str(s.get("local_port", "--")), body_style),
                Paragraph(s.get("state", "--"), body_style),
                Paragraph(str(s.get("pid") or "--"), body_style),
                Paragraph(s.get("process_name", "--"), body_style),
                Paragraph(s.get("service_tag", "--"), body_style)
            ])
        if len(port_rows) > 1:
            p_table = Table(port_rows, colWidths=[45, 45, 80, 45, 165, 160])
            p_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ]))
            story.append(p_table)
            story.append(Spacer(1, 10))

    # Sign-off footer
    story.append(Spacer(1, 8))
    sign_data = [
        [
            Paragraph("<b>Audited & Verified by:</b> ___________________________________", body_style),
            Paragraph("<b>Date:</b> ______________", body_style)
        ]
    ]
    sign_table = Table(sign_data, colWidths=[380, 160])
    sign_table.setStyle(TableStyle([
        ("PADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(sign_table)

    doc.build(story)
    logger.info(f"Report exported to PDF: {out_file}")
    return str(out_file)
