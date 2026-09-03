"""
Windows Persistence & Autorun Inspector View
Audits Windows Registry Run keys, Startup folders, and Scheduled Tasks.
Performs heuristic threat analysis to identify suspicious script execution and persistence hooks.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.autorun_inspector import (
    PersistenceItem,
    PersistenceSummary,
    run_persistence_audit,
)
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class AutorunView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.summary: Optional[PersistenceSummary] = None
        self.items: List[PersistenceItem] = []
        self.selected_item: Optional[PersistenceItem] = None
        self.is_auditing = False

        self._create_header()
        self._create_summary_cards()
        self._create_filter_toolbar()
        self._create_table_section()
        self._create_inspector_section()

        # Initial audit
        self.refresh_audit()

    def _create_header(self):
        """Top title and audit button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Windows Persistence & Autorun Threat Inspector",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.audit_btn = ctk.CTkButton(
            header_frame,
            text="Run Persistence Audit",
            width=160,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.refresh_audit
        )
        self.audit_btn.grid(row=0, column=1, sticky="e")

    def _create_summary_cards(self):
        """4 Overview Threat Cards."""
        cards_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cards_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_total = InfoCard(cards_frame, title="Total Startup Hooks", value="0", subtitle="Registry & Tasks")
        self.card_total.grid(row=0, column=0, padx=(12, 4), pady=12, sticky="ew")

        self.card_clean = InfoCard(cards_frame, title="Clean & Verified", value="0", subtitle="Legitimate software")
        self.card_clean.grid(row=0, column=1, padx=4, pady=12, sticky="ew")

        self.card_warn = InfoCard(cards_frame, title="Warnings / Unquoted", value="0", subtitle="Potential vulnerabilities")
        self.card_warn.grid(row=0, column=2, padx=4, pady=12, sticky="ew")

        self.card_susp = InfoCard(cards_frame, title="Suspicious Scripts", value="0", subtitle="Script / Temp execution")
        self.card_susp.grid(row=0, column=3, padx=(4, 12), pady=12, sticky="ew")

    def _create_filter_toolbar(self):
        """Segmented filters and search bar."""
        toolbar = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        toolbar.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        toolbar.grid_columnconfigure(1, weight=1)

        self.seg_filter = ctk.CTkSegmentedButton(
            toolbar,
            values=["All Items", "Suspicious / Warnings", "Registry Run", "Scheduled Tasks", "Startup Folders"],
            command=lambda v: self._apply_filters()
        )
        self.seg_filter.set("All Items")
        self.seg_filter.grid(row=0, column=0, padx=(12, 6), pady=8, sticky="w")

        self.search_entry = ctk.CTkEntry(
            toolbar,
            placeholder_text="Search Item Name, Executable, Command...",
            width=250,
            height=28
        )
        self.search_entry.grid(row=0, column=1, padx=(6, 12), pady=8, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

    def _create_table_section(self):
        """Persistence Treeview Table."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        cols = ("threat", "type", "name", "location", "command")
        self.tree = ttk.Treeview(
            tree_box,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=9
        )

        self.tree.heading("threat", text="Threat Rating", anchor="center")
        self.tree.heading("type", text="Mechanism", anchor="center")
        self.tree.heading("name", text="Persistence Entry Name", anchor="w")
        self.tree.heading("location", text="Persistence Location", anchor="w")
        self.tree.heading("command", text="Command / Executable Path", anchor="w")

        self.tree.column("threat", width=110, minwidth=90, anchor="center")
        self.tree.column("type", width=120, minwidth=100, anchor="center")
        self.tree.column("name", width=180, minwidth=140, anchor="w")
        self.tree.column("location", width=200, minwidth=160, anchor="w")
        self.tree.column("command", width=280, minwidth=200, anchor="w")

        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        self.tree.tag_configure("suspicious", foreground="#EF4444")
        self.tree.tag_configure("warning", foreground="#F59E0B")
        self.tree.tag_configure("clean", foreground="#10B981")

        self.tree.bind("<<TreeviewSelect>>", self._on_item_selected)

        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 persistence items",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="w")

    def _create_inspector_section(self):
        """Selected persistence item metadata inspector."""
        self.insp_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.insp_frame.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.insp_frame.grid_columnconfigure(0, weight=1)

        self.insp_title = ctk.CTkLabel(
            self.insp_frame,
            text="SELECTED PERSISTENCE HOOK: NONE (CLICK A ROW ABOVE)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        self.insp_title.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.insp_details = ctk.CTkLabel(
            self.insp_frame,
            text="Select any startup entry above to analyze executable paths, threat reasons, and binary verification.",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#D1D5DB"),
            anchor="w",
            wraplength=850,
            justify="left"
        )
        self.insp_details.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

    def refresh_audit(self):
        """Executes full persistence audit in background."""
        self.audit_btn.configure(state="disabled", text="Auditing...")

        def worker():
            res = run_persistence_audit()

            def ui_update():
                self.summary = res
                self.items = res.items

                self.card_total.update_content(value=str(res.total_items), subtitle="Registered Hooks")
                self.card_clean.update_content(value=str(res.clean_count), subtitle="Legitimate software")
                self.card_warn.update_content(value=str(res.warning_count), subtitle="Check unquoted paths")
                self.card_susp.update_content(value=str(res.suspicious_count), subtitle="Requires Investigation")

                self._apply_filters()
                self.audit_btn.configure(state="normal", text="Run Persistence Audit")

            try:
                self.after(0, ui_update)
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_filters(self):
        mode = self.seg_filter.get()
        query = self.search_entry.get().strip().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)

        count = 0
        for it in self.items:
            # Segment filters
            if mode == "Suspicious / Warnings" and it.threat_level == "CLEAN":
                continue
            if mode == "Registry Run" and it.entry_type != "Registry Run":
                continue
            if mode == "Scheduled Tasks" and it.entry_type != "Scheduled Task":
                continue
            if mode == "Startup Folders" and it.entry_type != "Startup Folder":
                continue

            if query:
                match = (
                    query in it.name.lower() or
                    query in it.command.lower() or
                    query in it.location.lower() or
                    query in it.target_binary.lower() or
                    query in it.threat_level.lower()
                )
                if not match:
                    continue

                tag = "clean"
                if it.threat_level == "SUSPICIOUS":
                    tag = "suspicious"
                elif it.threat_level == "WARNING":
                    tag = "warning"

            tag = "clean"
            if it.threat_level == "SUSPICIOUS":
                tag = "suspicious"
            elif it.threat_level == "WARNING":
                tag = "warning"

            threat_badge = f"🔴 {it.threat_level}" if it.threat_level == "SUSPICIOUS" else (f"🟡 {it.threat_level}" if it.threat_level == "WARNING" else f"🟢 {it.threat_level}")

            self.tree.insert(
                "",
                "end",
                values=(
                    threat_badge,
                    it.entry_type,
                    it.name,
                    it.location,
                    it.command
                ),
                tags=(tag,)
            )
            count += 1

        self.count_label.configure(text=f"Displaying {count} of {len(self.items)} persistence items")

    def _on_item_selected(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals:
            name = vals[2]
            it = next((i for i in self.items if i.name == name), None)
            if it:
                self.selected_item = it
                self.insp_title.configure(text=f"ENTRY: {it.name} [{it.threat_level}] ({it.entry_type})")
                reasons_str = "None (Clean verified entry)" if not it.threat_reasons else "\n   • " + "\n   • ".join(it.threat_reasons)
                self.insp_details.configure(text=f"• Location: {it.location}\n• Target Binary: {it.target_binary} (File on disk: {'Yes' if it.file_exists else 'No'})\n• Full Command: {it.command}\n• Threat Analysis: {reasons_str}")
