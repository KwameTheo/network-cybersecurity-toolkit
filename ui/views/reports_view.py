"""
Reports View
Provides interactive diagnostic audit assembly, multi-format exports (TXT, JSON, CSV),
live text preview, and SQLite audit history management.
"""

import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.database import delete_report, get_recent_reports, get_report_by_id
from core.report_generator import (
    REPORTS_DIR,
    assemble_full_audit_report,
    export_report_csv,
    export_report_json,
    export_report_txt,
    get_default_report_options,
)
from ui.components.log_console import LogConsole
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class ReportsView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.current_report_data: Optional[Dict[str, Any]] = None
        self.is_generating = False

        self._create_header()
        self._create_options_section()
        self._create_tabs_section()

        # Load initial history and generate default preview
        self.refresh_history()

    def _create_header(self):
        """Top title and action button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Diagnostic Audit Reports & History",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.generate_btn = ctk.CTkButton(
            header_frame,
            text="Generate Full Audit Report",
            width=190,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.generate_report
        )
        self.generate_btn.grid(row=0, column=1, sticky="e")

    def _create_options_section(self):
        """Checkboxes for report inclusion and export buttons."""
        opts_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        opts_container.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        opts_container.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(
            opts_container,
            text="AUDIT SECTIONS TO INCLUDE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        ).grid(row=0, column=0, columnspan=3, padx=14, pady=(10, 6), sticky="w")

        # Checkboxes
        self.chk_sys = ctk.CTkCheckBox(opts_container, text="System & Host Specs", onvalue=True, offvalue=False)
        self.chk_sys.select()
        self.chk_sys.grid(row=1, column=0, padx=14, pady=4, sticky="w")

        self.chk_net = ctk.CTkCheckBox(opts_container, text="Network Adapters & IP", onvalue=True, offvalue=False)
        self.chk_net.select()
        self.chk_net.grid(row=1, column=1, padx=14, pady=4, sticky="w")

        self.chk_ports = ctk.CTkCheckBox(opts_container, text="Active Sockets & Ports", onvalue=True, offvalue=False)
        self.chk_ports.select()
        self.chk_ports.grid(row=1, column=2, padx=14, pady=4, sticky="w")

        self.chk_health = ctk.CTkCheckBox(opts_container, text="Internet & DNS Health", onvalue=True, offvalue=False)
        self.chk_health.select()
        self.chk_health.grid(row=2, column=0, padx=14, pady=(4, 12), sticky="w")

        self.chk_sec = ctk.CTkCheckBox(opts_container, text="Security Baseline Audit", onvalue=True, offvalue=False)
        self.chk_sec.select()
        self.chk_sec.grid(row=2, column=1, padx=14, pady=(4, 12), sticky="w")

        self.chk_events = ctk.CTkCheckBox(opts_container, text="Event Log Failures", onvalue=True, offvalue=False)
        self.chk_events.select()
        self.chk_events.grid(row=2, column=2, padx=14, pady=(4, 12), sticky="w")

        # Exporter Action Toolbar
        action_bar = ctk.CTkFrame(opts_container, fg_color="transparent")
        action_bar.grid(row=3, column=0, columnspan=3, padx=14, pady=(0, 12), sticky="ew")

        ctk.CTkLabel(action_bar, text="Export Formats:", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", padx=(0, 8))

        self.export_txt_btn = ctk.CTkButton(
            action_bar,
            text="Export TXT",
            width=90,
            height=28,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._on_export_txt
        )
        self.export_txt_btn.pack(side="left", padx=4)

        self.export_json_btn = ctk.CTkButton(
            action_bar,
            text="Export JSON",
            width=95,
            height=28,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._on_export_json
        )
        self.export_json_btn.pack(side="left", padx=4)

        self.export_csv_btn = ctk.CTkButton(
            action_bar,
            text="Export CSV",
            width=90,
            height=28,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._on_export_csv
        )
        self.export_csv_btn.pack(side="left", padx=4)

        self.open_folder_btn = ctk.CTkButton(
            action_bar,
            text="Open Reports Folder",
            width=140,
            height=28,
            fg_color="#059669",
            hover_color="#047857",
            command=self._open_reports_folder
        )
        self.open_folder_btn.pack(side="right")

    def _create_tabs_section(self):
        """Tabs for Live Text Preview and SQLite Database History."""
        self.tabview = ctk.CTkTabview(self, corner_radius=10)
        self.tabview.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")

        self.tab_preview = self.tabview.add("Report Text Preview")
        self.tab_history = self.tabview.add("Database Audit History (SQLite)")

        # 1. Preview Tab
        self.tab_preview.grid_columnconfigure(0, weight=1)
        self.tab_preview.grid_rowconfigure(0, weight=1)

        self.report_console = LogConsole(self.tab_preview, title="AUDIT REPORT PREVIEW", height=380)
        self.report_console.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        self.report_console.set_text("Click 'Generate Full Audit Report' above to assemble a new diagnostic snapshot.")

        # 2. History Tab
        self._build_history_tab()

    def _build_history_tab(self):
        self.tab_history.grid_columnconfigure(0, weight=1)
        self.tab_history.grid_rowconfigure(1, weight=1)

        # Toolbar
        hist_top = ctk.CTkFrame(self.tab_history, fg_color="transparent")
        hist_top.grid(row=0, column=0, padx=8, pady=(8, 4), sticky="ew")
        hist_top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hist_top,
            text="HISTORICAL SNAPSHOTS SAVED IN LOCAL SQLITE DATABASE (data/toolkit.db)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#94A3B8"
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            hist_top,
            text="Refresh History",
            width=110,
            height=26,
            command=self.refresh_history
        ).grid(row=0, column=1, sticky="e")

        # Treeview
        table_box = ctk.CTkFrame(self.tab_history, corner_radius=8, fg_color=("#111827", "#0F172A"))
        table_box.grid(row=1, column=0, padx=8, pady=(0, 8), sticky="nsew")
        table_box.grid_columnconfigure(0, weight=1)
        table_box.grid_rowconfigure(0, weight=1)

        columns = ("id", "time", "host", "os", "score", "summary")
        self.history_tree = ttk.Treeview(
            table_box,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        self.history_tree.heading("id", text="ID", anchor="center")
        self.history_tree.heading("time", text="Timestamp", anchor="w")
        self.history_tree.heading("host", text="Host Name", anchor="w")
        self.history_tree.heading("os", text="OS Edition", anchor="w")
        self.history_tree.heading("score", text="Score", anchor="center")
        self.history_tree.heading("summary", text="Audit Summary", anchor="w")

        self.history_tree.column("id", width=45, minwidth=40, anchor="center")
        self.history_tree.column("time", width=140, minwidth=130, anchor="w")
        self.history_tree.column("host", width=120, minwidth=100, anchor="w")
        self.history_tree.column("os", width=150, minwidth=120, anchor="w")
        self.history_tree.column("score", width=70, minwidth=60, anchor="center")
        self.history_tree.column("summary", width=280, minwidth=200, anchor="w")

        v_scroll = ttk.Scrollbar(table_box, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=v_scroll.set)

        self.history_tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        self.history_tree.bind("<Double-1>", self._on_history_double_click)

    def generate_report(self):
        """Gathers telemetry across chosen modules in background thread."""
        if self.is_generating:
            return

        self.is_generating = True
        self.generate_btn.configure(state="disabled", text="Assembling Audit...")
        self.report_console.set_text("[*] Assembling full diagnostic audit report...\nQuerying System Specs, Network Adapters, Ports, Internet Health Ladder, and Security Baseline...\n")

        opts = {
            "system_info": self.chk_sys.get(),
            "network_config": self.chk_net.get(),
            "ports_sockets": self.chk_ports.get(),
            "internet_health": self.chk_health.get(),
            "security_baseline": self.chk_sec.get(),
            "event_logs": self.chk_events.get(),
        }

        def worker():
            report_data = assemble_full_audit_report(opts)
            txt_path = export_report_txt(report_data)
            export_report_json(report_data)
            export_report_csv(report_data)

            with open(txt_path, "r", encoding="utf-8") as f:
                content = f.read()

            def ui_update():
                self.current_report_data = report_data
                self.report_console.set_text(content)
                self.generate_btn.configure(state="normal", text="Generate Full Audit Report")
                self.is_generating = False
                self.refresh_history()

            try:
                self.after(0, ui_update)
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def refresh_history(self):
        """Loads recent SQLite report rows into Treeview."""
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)

        rows = get_recent_reports(limit=30)
        for r in rows:
            score_str = f"{r.get('score_percent')}%" if r.get("score_percent") is not None else "--"
            self.history_tree.insert(
                "",
                "end",
                values=(
                    r.get("id"),
                    r.get("timestamp"),
                    r.get("host_name"),
                    r.get("os_edition"),
                    score_str,
                    r.get("summary_text")
                )
            )

    def _on_history_double_click(self, event):
        """Loads selected historical report from SQLite into the preview tab."""
        selected = self.history_tree.selection()
        if not selected:
            return
        item_vals = self.history_tree.item(selected[0], "values")
        if item_vals:
            rep_id = int(item_vals[0])
            full_rep = get_report_by_id(rep_id)
            if full_rep and "parsed_data" in full_rep:
                self.current_report_data = full_rep["parsed_data"]
                txt_content = export_report_txt(self.current_report_data)
                with open(txt_content, "r", encoding="utf-8") as f:
                    preview_str = f.read()
                self.report_console.set_text(preview_str)
                self.tabview.set("Report Text Preview")

    def _on_export_txt(self):
        if not self.current_report_data:
            self.generate_report()
            return
        p = export_report_txt(self.current_report_data)
        self.export_txt_btn.configure(text="Exported!", fg_color="#059669")
        self.after(1500, lambda: self.export_txt_btn.configure(text="Export TXT", fg_color="#374151"))

    def _on_export_json(self):
        if not self.current_report_data:
            self.generate_report()
            return
        p = export_report_json(self.current_report_data)
        self.export_json_btn.configure(text="Exported!", fg_color="#059669")
        self.after(1500, lambda: self.export_json_btn.configure(text="Export JSON", fg_color="#374151"))

    def _on_export_csv(self):
        if not self.current_report_data:
            self.generate_report()
            return
        p = export_report_csv(self.current_report_data)
        self.export_csv_btn.configure(text="Exported!", fg_color="#059669")
        self.after(1500, lambda: self.export_csv_btn.configure(text="Export CSV", fg_color="#374151"))

    def _open_reports_folder(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(REPORTS_DIR))
        except Exception as e:
            logger.warning(f"Could not open explorer: {e}")
