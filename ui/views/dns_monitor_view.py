"""
Live DNS Query Monitor & Anomaly Inspector View
Real-time DNS resolver cache telemetry, threat classification (DGA, Tunneling, Suspicious TLDs),
Shannon entropy analysis, and interactive query inspection.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.dns_monitor import (
    DnsMonitorReport,
    DnsQueryRecord,
    run_dns_monitor_audit,
)
from core.network_diagnostics import flush_dns_cache
from ui.components.confirmation_dialog import ConfirmationDialog
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class DnsMonitorView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.all_records: List[DnsQueryRecord] = []
        self.selected_record: Optional[DnsQueryRecord] = None
        self.is_refreshing = False

        self._create_header()
        self._create_metric_cards()
        self._create_filter_toolbar()
        self._create_table_section()
        self._create_detail_inspector()

        # Initial load
        self.refresh_data()

    def _create_header(self):
        """Top title and action buttons."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Live DNS Query Monitor & Threat Inspector",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        self.flush_btn = ctk.CTkButton(
            btn_box,
            text="Flush Cache",
            width=110,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._confirm_flush
        )
        self.flush_btn.pack(side="left", padx=(0, 6))

        self.refresh_btn = ctk.CTkButton(
            btn_box,
            text="Refresh DNS Stream",
            width=150,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.refresh_data
        )
        self.refresh_btn.pack(side="left")

    def _create_metric_cards(self):
        """Top metric cards showing anomaly counters."""
        cards_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cards_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        cards_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.card_total = InfoCard(cards_frame, title="Total Cached Queries", value="0", subtitle="Active resolver entries")
        self.card_total.grid(row=0, column=0, padx=(12, 6), pady=(12, 6), sticky="ew")

        self.card_clean = InfoCard(cards_frame, title="Clean Domains", value="0", subtitle="Standard trusted lookups")
        self.card_clean.grid(row=0, column=1, padx=6, pady=(12, 6), sticky="ew")

        self.card_threats = InfoCard(cards_frame, title="Anomalies & Flags", value="0", subtitle="Total suspicious entries")
        self.card_threats.grid(row=0, column=2, padx=(6, 12), pady=(12, 6), sticky="ew")

        self.card_tld = InfoCard(cards_frame, title="Suspicious TLDs", value="0", subtitle="High-risk extensions")
        self.card_tld.grid(row=1, column=0, padx=(12, 6), pady=(6, 12), sticky="ew")

        self.card_dga = InfoCard(cards_frame, title="DGA Entropy Flags", value="0", subtitle="Algorithmic domain risks")
        self.card_dga.grid(row=1, column=1, padx=6, pady=(6, 12), sticky="ew")

        self.card_tunnel = InfoCard(cards_frame, title="Tunneling / Long Labels", value="0", subtitle="Exfiltration risk")
        self.card_tunnel.grid(row=1, column=2, padx=(6, 12), pady=(6, 12), sticky="ew")

    def _create_filter_toolbar(self):
        """Filter segment and search bar."""
        filter_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        filter_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        filter_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(filter_frame, text="Filter Stream:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12, 6), pady=8, sticky="w")

        self.filter_segment = ctk.CTkSegmentedButton(
            filter_frame,
            values=["All Lookups", "Anomalies Only", "Clean Only"],
            command=lambda v: self._apply_filters()
        )
        self.filter_segment.set("All Lookups")
        self.filter_segment.grid(row=0, column=1, padx=6, pady=8, sticky="w")

        self.search_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="Search Domain, IP, Record Type...",
            width=230,
            height=28
        )
        self.search_entry.grid(row=0, column=2, padx=(6, 12), pady=8, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

    def _create_table_section(self):
        """Treeview table displaying active DNS query stream."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        columns = ("threat", "domain", "type", "target", "ttl", "status")
        self.tree = ttk.Treeview(
            tree_box,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=9
        )

        self.tree.heading("threat", text="Threat Tag", anchor="center")
        self.tree.heading("domain", text="Queried Domain Entry", anchor="w")
        self.tree.heading("type", text="Record Type", anchor="center")
        self.tree.heading("target", text="Resolved IP / Target Alias", anchor="w")
        self.tree.heading("ttl", text="TTL (s)", anchor="center")
        self.tree.heading("status", text="Resolver Status", anchor="center")

        self.tree.column("threat", width=120, minwidth=100, anchor="center")
        self.tree.column("domain", width=220, minwidth=180, anchor="w")
        self.tree.column("type", width=90, minwidth=80, anchor="center")
        self.tree.column("target", width=220, minwidth=170, anchor="w")
        self.tree.column("ttl", width=70, minwidth=60, anchor="center")
        self.tree.column("status", width=90, minwidth=80, anchor="center")

        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        # Tree tags for styling
        self.tree.tag_configure("clean", foreground="#10B981")
        self.tree.tag_configure("threat", foreground="#EF4444")
        self.tree.tag_configure("warning", foreground="#F59E0B")
        self.tree.tag_configure("nxdomain", foreground="#9CA3AF")

        self.tree.bind("<<TreeviewSelect>>", self._on_row_selected)

        # Count label
        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 queries",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="w")

    def _create_detail_inspector(self):
        """Inspector card showing Shannon Entropy and anomaly diagnosis."""
        self.inspector_card = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.inspector_card.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.inspector_card.grid_columnconfigure(0, weight=1)

        self.insp_title = ctk.CTkLabel(
            self.inspector_card,
            text="QUERY INSPECTOR: SELECT A DOMAIN ROW ABOVE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        self.insp_title.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.insp_details = ctk.CTkLabel(
            self.inspector_card,
            text="Click any DNS query in the stream table to inspect its Shannon Entropy, threat rationale, and resolution details.",
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#D1D5DB"),
            anchor="w",
            wraplength=700,
            justify="left"
        )
        self.insp_details.grid(row=1, column=0, padx=14, pady=(0, 12), sticky="w")

    def refresh_data(self):
        """Gathers DNS resolver cache and updates UI immediately."""
        try:
            self.refresh_btn.configure(state="disabled", text="Scanning...")
            report = run_dns_monitor_audit()
            self._apply_report(report)
        except Exception as e:
            logger.error(f"Error in DNS Monitor refresh: {e}", exc_info=True)
        finally:
            try:
                self.refresh_btn.configure(state="normal", text="Refresh DNS Stream")
            except Exception:
                pass

    def _apply_report(self, report: DnsMonitorReport):
        self.all_records = report.records

        # Update Metric Cards
        self.card_total.update_content(value=str(report.total_queries), subtitle="Active resolver entries")
        self.card_clean.update_content(value=str(report.clean_count), subtitle="Standard trusted lookups")
        self.card_threats.update_content(value=str(report.anomaly_count), subtitle="Total suspicious entries")
        self.card_tld.update_content(value=str(report.suspicious_tld_count), subtitle="High-risk extensions")
        self.card_dga.update_content(value=str(report.dga_count), subtitle="Algorithmic domain risks")
        self.card_tunnel.update_content(value=str(report.tunneling_count), subtitle="Exfiltration risk")

        self._apply_filters()

    def _apply_filters(self):
        filter_mode = self.filter_segment.get()
        query = self.search_entry.get().strip().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)

        count = 0
        for r in self.all_records:
            # Segment filter
            if filter_mode == "Anomalies Only" and r.anomaly_flag == "CLEAN":
                continue
            if filter_mode == "Clean Only" and r.anomaly_flag != "CLEAN":
                continue

            # Search text query
            if query:
                match = (
                    query in r.domain.lower() or
                    query in r.resolved_data.lower() or
                    query in r.record_type.lower() or
                    query in r.anomaly_flag.lower()
                )
                if not match:
                    continue

            tag = "clean"
            if r.anomaly_flag in ["DGA_ENTROPY", "DNS_TUNNELING"]:
                tag = "threat"
            elif r.anomaly_flag == "SUSPICIOUS_TLD":
                tag = "warning"
            elif r.anomaly_flag == "NXDOMAIN":
                tag = "nxdomain"

            self.tree.insert(
                "",
                "end",
                values=(
                    r.anomaly_flag,
                    r.domain,
                    r.record_type,
                    r.resolved_data,
                    r.ttl_seconds,
                    r.status
                ),
                tags=(tag,)
            )
            count += 1

        self.count_label.configure(text=f"Displaying {count} of {len(self.all_records)} cached DNS records")

    def _on_row_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        vals = self.tree.item(selected[0], "values")
        if vals:
            dom = vals[1]
            rec = next((r for r in self.all_records if r.domain == dom), None)
            if rec:
                self.insp_title.configure(text=f"QUERY INSPECTOR: {rec.domain} [{rec.anomaly_flag}]")
                reason_str = f"Threat Note: {rec.anomaly_reason}" if rec.anomaly_reason else "Security Verdict: Standard legitimate domain."
                lines = [
                    f"• Target Resolution: {rec.resolved_data} ({rec.record_type}) | TTL: {rec.ttl_seconds}s | Status: {rec.status}",
                    f"• Shannon Entropy Score: {rec.entropy_score} (Randomness measurement)",
                    f"• {reason_str}"
                ]
                self.insp_details.configure(text="\n".join(lines))

    def _confirm_flush(self):
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title="Flush DNS Cache",
            message="Clear the entire Windows DNS resolver cache?",
            warning_detail="This empties all currently cached domain names and resets the stream.",
            confirm_text="Flush Cache",
            on_confirm=self._execute_flush
        )

    def _execute_flush(self):
        flush_dns_cache()
        self.refresh_data()
