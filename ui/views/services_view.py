"""
Windows Services Manager & Hung Service Fixer View
Interactive Windows services browser, critical IT service filters,
1-click helpdesk service fixers (Print Spooler, Windows Update, DHCP, Time),
and safe start/stop/restart lifecycle controls.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Any, Dict, List, Optional

from core.service_manager import (
    CRITICAL_SERVICES,
    ServiceControlResult,
    WindowsServiceInfo,
    get_services_summary,
    restart_windows_service,
    start_windows_service,
    stop_windows_service,
)
from ui.components.confirmation_dialog import ConfirmationDialog
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class ServicesView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.all_services: List[WindowsServiceInfo] = []
        self.selected_service: Optional[WindowsServiceInfo] = None
        self.is_refreshing = False

        self._create_header()
        self._create_summary_cards()
        self._create_quick_fixers()
        self._create_filter_toolbar()
        self._create_table_section()
        self._create_service_control_bar()

        # Initial load
        self.refresh_services()

    def _create_header(self):
        """Top title and refresh button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Windows Services Manager & Hung Service Fixer",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.refresh_btn = ctk.CTkButton(
            header_frame,
            text="Refresh Services",
            width=150,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.refresh_services
        )
        self.refresh_btn.grid(row=0, column=1, sticky="e")

    def _create_summary_cards(self):
        """Top summary cards."""
        cards_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cards_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_total = InfoCard(cards_frame, title="Total Services", value="0", subtitle="Registered in Windows")
        self.card_total.grid(row=0, column=0, padx=(12, 4), pady=12, sticky="ew")

        self.card_running = InfoCard(cards_frame, title="Running Services", value="0", subtitle="Active Session 0")
        self.card_running.grid(row=0, column=1, padx=4, pady=12, sticky="ew")

        self.card_stopped = InfoCard(cards_frame, title="Stopped Services", value="0", subtitle="Inactive / on-demand")
        self.card_stopped.grid(row=0, column=2, padx=4, pady=12, sticky="ew")

        self.card_critical = InfoCard(cards_frame, title="Critical IT Services", value="0", subtitle="Core infrastructure")
        self.card_critical.grid(row=0, column=3, padx=(4, 12), pady=12, sticky="ew")

    def _create_quick_fixers(self):
        """1-Click Helpdesk Quick Service Fixers."""
        fixer_box = ctk.CTkFrame(self, corner_radius=10, fg_color=("#DBEAFE", "#1E3A8A"))
        fixer_box.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="ew")
        fixer_box.grid_columnconfigure((0, 1, 2, 3), weight=1)

        title_lbl = ctk.CTkLabel(
            fixer_box,
            text="⚡ 1-CLICK HELPDESK QUICK SERVICE RECOVERY",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        title_lbl.grid(row=0, column=0, columnspan=4, padx=14, pady=(10, 6), sticky="w")

        btn1 = ctk.CTkButton(
            fixer_box,
            text="Restart Print Spooler",
            fg_color="#059669",
            hover_color="#047857",
            height=30,
            command=lambda: self._quick_restart("Spooler", "Print Spooler")
        )
        btn1.grid(row=1, column=0, padx=(12, 4), pady=(0, 12), sticky="ew")

        btn2 = ctk.CTkButton(
            fixer_box,
            text="Restart Windows Update",
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            height=30,
            command=lambda: self._quick_restart("wuauserv", "Windows Update")
        )
        btn2.grid(row=1, column=1, padx=4, pady=(0, 12), sticky="ew")

        btn3 = ctk.CTkButton(
            fixer_box,
            text="Restart DHCP Client",
            fg_color="#374151",
            hover_color="#4B5563",
            height=30,
            command=lambda: self._quick_restart("Dhcp", "DHCP Client")
        )
        btn3.grid(row=1, column=2, padx=4, pady=(0, 12), sticky="ew")

        btn4 = ctk.CTkButton(
            fixer_box,
            text="Restart Windows Time",
            fg_color="#D97706",
            hover_color="#B45309",
            height=30,
            command=lambda: self._quick_restart("W32Time", "Windows Time")
        )
        btn4.grid(row=1, column=3, padx=(4, 12), pady=(0, 12), sticky="ew")

    def _create_filter_toolbar(self):
        """Search bar and segment filters."""
        toolbar = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        toolbar.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")
        toolbar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(toolbar, text="Filter Services:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12, 6), pady=8, sticky="w")

        self.filter_segment = ctk.CTkSegmentedButton(
            toolbar,
            values=["All Services", "Running Only", "Stopped Only", "Critical IT Only"],
            command=lambda v: self._apply_filters()
        )
        self.filter_segment.set("All Services")
        self.filter_segment.grid(row=0, column=1, padx=6, pady=8, sticky="w")

        self.search_entry = ctk.CTkEntry(
            toolbar,
            placeholder_text="Search Service Name, Display, PID...",
            width=240,
            height=28
        )
        self.search_entry.grid(row=0, column=2, padx=(6, 12), pady=8, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

    def _create_table_section(self):
        """Services Treeview Table."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        columns = ("tag", "name", "display", "status", "start_type", "pid")
        self.tree = ttk.Treeview(
            tree_box,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=10
        )

        self.tree.heading("tag", text="Category", anchor="center")
        self.tree.heading("name", text="Service Name", anchor="w")
        self.tree.heading("display", text="Display Name", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("start_type", text="Startup Mode", anchor="center")
        self.tree.heading("pid", text="PID", anchor="center")

        self.tree.column("tag", width=110, minwidth=90, anchor="center")
        self.tree.column("name", width=140, minwidth=110, anchor="w")
        self.tree.column("display", width=250, minwidth=200, anchor="w")
        self.tree.column("status", width=90, minwidth=80, anchor="center")
        self.tree.column("start_type", width=100, minwidth=90, anchor="center")
        self.tree.column("pid", width=70, minwidth=60, anchor="center")

        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        # Styling tags
        self.tree.tag_configure("critical_running", foreground="#10B981")
        self.tree.tag_configure("critical_stopped", foreground="#EF4444")
        self.tree.tag_configure("running", foreground="#93C5FD")
        self.tree.tag_configure("stopped", foreground="#9CA3AF")

        self.tree.bind("<<TreeviewSelect>>", self._on_service_selected)

        # Count label
        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 services",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="w")

    def _create_service_control_bar(self):
        """Selected service inspector and action controls."""
        self.ctrl_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.ctrl_frame.grid(row=5, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.ctrl_frame.grid_columnconfigure(0, weight=1)

        self.sel_title = ctk.CTkLabel(
            self.ctrl_frame,
            text="SELECTED SERVICE: NONE (CLICK A ROW IN THE TABLE)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        self.sel_title.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.sel_desc = ctk.CTkLabel(
            self.ctrl_frame,
            text="Select any Windows service to inspect its description, status, and execute lifecycle controls.",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#D1D5DB"),
            anchor="w",
            wraplength=650,
            justify="left"
        )
        self.sel_desc.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

        # Action Buttons
        btn_box = ctk.CTkFrame(self.ctrl_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, rowspan=2, padx=14, pady=10, sticky="e")

        self.btn_start = ctk.CTkButton(
            btn_box,
            text="Start Service",
            width=105,
            height=28,
            fg_color="#059669",
            hover_color="#047857",
            command=self._on_start_clicked
        )
        self.btn_start.pack(side="left", padx=3)

        self.btn_restart = ctk.CTkButton(
            btn_box,
            text="Restart Service",
            width=115,
            height=28,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._on_restart_clicked
        )
        self.btn_restart.pack(side="left", padx=3)

        self.btn_stop = ctk.CTkButton(
            btn_box,
            text="Stop Service",
            width=105,
            height=28,
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._on_stop_clicked
        )
        self.btn_stop.pack(side="left", padx=3)

    def refresh_services(self):
        """Scans all Windows services and updates UI."""
        try:
            self.refresh_btn.configure(state="disabled", text="Scanning...")
            summary = get_services_summary()
            self._apply_summary(summary)
        except Exception as e:
            logger.error(f"Error refreshing services: {e}", exc_info=True)
        finally:
            try:
                self.refresh_btn.configure(state="normal", text="Refresh Services")
            except Exception:
                pass

    def _apply_summary(self, summary: Dict[str, Any]):
        self.all_services = summary.get("services", [])

        # Update cards
        self.card_total.update_content(value=str(summary.get("total_services", 0)), subtitle="Registered in Windows")
        self.card_running.update_content(value=str(summary.get("running_count", 0)), subtitle="Active Session 0")
        self.card_stopped.update_content(value=str(summary.get("stopped_count", 0)), subtitle="Inactive / on-demand")
        self.card_critical.update_content(value=f"{summary.get('critical_running', 0)} / {summary.get('critical_total', 0)}", subtitle="Running IT services")

        self._apply_filters()

    def _apply_filters(self):
        filter_mode = self.filter_segment.get()
        query = self.search_entry.get().strip().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)

        count = 0
        for s in self.all_services:
            # Segment filter
            if filter_mode == "Running Only" and s.status != "running":
                continue
            if filter_mode == "Stopped Only" and s.status != "stopped":
                continue
            if filter_mode == "Critical IT Only" and not s.is_critical:
                continue

            # Search text query
            if query:
                match = (
                    query in s.name.lower() or
                    query in s.display_name.lower() or
                    query in s.status.lower() or
                    query in s.start_type.lower() or
                    query in str(s.pid or "")
                )
                if not match:
                    continue

            tag = "running" if s.status == "running" else "stopped"
            tag_text = "STANDARD"
            if s.is_critical:
                tag = "critical_running" if s.status == "running" else "critical_stopped"
                tag_text = "⭐ CRITICAL"

            self.tree.insert(
                "",
                "end",
                values=(
                    tag_text,
                    s.name,
                    s.display_name,
                    s.status.upper(),
                    s.start_type.capitalize(),
                    s.pid or "--"
                ),
                tags=(tag,)
            )
            count += 1

        self.count_label.configure(text=f"Displaying {count} of {len(self.all_services)} services")

    def _on_service_selected(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        vals = self.tree.item(selected[0], "values")
        if vals:
            s_name = vals[1]
            svc = next((s for s in self.all_services if s.name == s_name), None)
            if svc:
                self.selected_service = svc
                crit_tag = " [CRITICAL IT INFRASTRUCTURE]" if svc.is_critical else ""
                self.sel_title.configure(text=f"SELECTED SERVICE: {svc.name} ({svc.display_name}){crit_tag}")
                desc_text = svc.description if svc.description else "No extended description provided by service binary."
                self.sel_desc.configure(text=f"• Status: {svc.status.upper()} | Startup Mode: {svc.start_type.capitalize()} | PID: {svc.pid or '--'}\n• Description: {desc_text}")

    def _quick_restart(self, s_name: str, friendly_name: str):
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title=f"Restart {friendly_name}",
            message=f"Are you sure you want to restart the '{friendly_name}' service ({s_name})?",
            warning_detail="This will cycle the service process to resolve hung queues or stuck operations.",
            confirm_text="Restart Service",
            on_confirm=lambda: self._execute_service_action(s_name, "restart")
        )

    def _on_restart_clicked(self):
        if not self.selected_service:
            return
        self._quick_restart(self.selected_service.name, self.selected_service.display_name)

    def _on_start_clicked(self):
        if not self.selected_service:
            return
        self._execute_service_action(self.selected_service.name, "start")

    def _on_stop_clicked(self):
        if not self.selected_service:
            return
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title=f"Stop {self.selected_service.name}",
            message=f"Are you sure you want to stop '{self.selected_service.display_name}'?",
            warning_detail="WARNING: Stopping background services may cause dependent applications to fail.",
            confirm_text="Stop Service",
            is_destructive=True,
            on_confirm=lambda: self._execute_service_action(self.selected_service.name, "stop")
        )

    def _execute_service_action(self, s_name: str, action: str):
        def worker():
            if action == "restart":
                res = restart_windows_service(s_name)
            elif action == "start":
                res = start_windows_service(s_name)
            elif action == "stop":
                res = stop_windows_service(s_name)
            else:
                return

            def ui_update():
                self.refresh_services()
            try:
                self.after(0, ui_update)
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()
