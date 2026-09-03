"""
Windows Event Log View
Provides safe, read-only event log inspection, authentication auditing,
service crash tracking, and event detail analysis.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.event_analyzer import EventQueryResult, WindowsEvent, query_event_logs
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger
from utils.privileges import is_running_as_admin

logger = get_logger()


class EventsView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.current_events: List[WindowsEvent] = []
        self.filtered_events: List[WindowsEvent] = []
        self.is_admin = is_running_as_admin()

        self._create_header()
        self._create_info_banner()
        self._create_filter_bar()
        self._create_main_content()

    def _create_header(self):
        """Top title and query button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 8), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Windows Event Log Analyzer",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.query_btn = ctk.CTkButton(
            header_frame,
            text="Query Event Logs",
            width=150,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.run_query
        )
        self.query_btn.grid(row=0, column=1, sticky="e")

    def _create_info_banner(self):
        """Privilege indicator and read-only notice banner."""
        self.banner = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.banner.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner.grid_columnconfigure(1, weight=0)

        left_box = ctk.CTkFrame(self.banner, fg_color="transparent")
        left_box.grid(row=0, column=0, padx=14, pady=10, sticky="w")

        if self.is_admin:
            status_title = "AUDIT MODE: ADMINISTRATOR PRIVILEGES ACTIVE"
            status_desc = "Full access to Security (Logon 4624/4625), System, and Application event logs. Strictly read-only."
            badge_status = "PASS"
            badge_text = "ADMIN ELEVATED"
            banner_bg = ("#DCFCE7", "#064E3B")
        else:
            status_title = "AUDIT MODE: STANDARD USER"
            status_desc = "System and Application logs are available. Security log (Logon 4624/4625) requires Administrator rights."
            badge_status = "WARNING"
            badge_text = "STANDARD USER"
            banner_bg = ("#FEF3C7", "#78350F")

        self.banner.configure(fg_color=banner_bg)

        self.banner_title = ctk.CTkLabel(
            left_box,
            text=status_title,
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        )
        self.banner_title.grid(row=0, column=0, sticky="w")

        self.banner_desc = ctk.CTkLabel(
            left_box,
            text=status_desc,
            font=ctk.CTkFont(size=11),
            anchor="w"
        )
        self.banner_desc.grid(row=1, column=0, sticky="w")

        self.banner_badge = StatusBadge(self.banner, status=badge_status, width=120)
        self.banner_badge.set_status(badge_status, custom_text=badge_text)
        self.banner_badge.grid(row=0, column=1, padx=14, pady=10, sticky="e")

    def _create_filter_bar(self):
        """Controls for category, time range, max count, and search."""
        filter_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        filter_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        filter_frame.grid_columnconfigure(5, weight=1)

        # Category Dropdown
        ctk.CTkLabel(filter_frame, text="Category:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12, 4), pady=10, sticky="w")
        
        self.category_map = {
            "All Errors & Warnings": "all",
            "Service Failures (7000-7043)": "service_failures",
            "System & Kernel Errors": "system_errors",
            "Application Crashes (1000/1002)": "app_crashes",
            "Failed Logins (4625 - Admin)": "failed_logins",
            "Successful Logins (4624 - Admin)": "successful_logins",
            "Account Lockouts (4740 - Admin)": "account_lockouts",
        }

        self.category_menu = ctk.CTkOptionMenu(
            filter_frame,
            values=list(self.category_map.keys()),
            command=lambda choice: self.run_query(),
            width=210,
            height=30
        )
        self.category_menu.set("Service Failures (7000-7043)")
        self.category_menu.grid(row=0, column=1, padx=4, pady=10, sticky="w")

        # Time Range
        ctk.CTkLabel(filter_frame, text="Time Window:", font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=(10, 4), pady=10, sticky="w")
        self.time_map = {
            "Last 24 Hours": 24,
            "Last 7 Days": 168,
            "Last 30 Days": 720,
        }
        self.time_menu = ctk.CTkOptionMenu(
            filter_frame,
            values=list(self.time_map.keys()),
            command=lambda choice: self.run_query(),
            width=120,
            height=30
        )
        self.time_menu.set("Last 7 Days")
        self.time_menu.grid(row=0, column=3, padx=4, pady=10, sticky="w")

        # Search Filter
        ctk.CTkLabel(filter_frame, text="Search:", font=ctk.CTkFont(size=12)).grid(row=0, column=4, padx=(10, 4), pady=10, sticky="w")
        self.search_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="Filter events by ID, Provider, or keyword...",
            height=30
        )
        self.search_entry.grid(row=0, column=5, padx=(4, 12), pady=10, sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda event: self._apply_search_filter())

    def _create_main_content(self):
        """Split layout: Event Treeview (top) and Detail Inspector (bottom)."""
        content_frame = ctk.CTkFrame(self, fg_color="transparent")
        content_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(0, weight=3)
        content_frame.grid_rowconfigure(1, weight=2)

        # 1. Event Table
        table_box = ctk.CTkFrame(content_frame, corner_radius=10, fg_color=("#111827", "#0F172A"))
        table_box.grid(row=0, column=0, pady=(0, 10), sticky="nsew")
        table_box.grid_columnconfigure(0, weight=1)
        table_box.grid_rowconfigure(0, weight=1)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Event.Treeview",
            background="#0F172A",
            foreground="#F8FAFC",
            fieldbackground="#0F172A",
            rowheight=24,
            font=("Segoe UI", 9)
        )
        style.configure(
            "Event.Treeview.Heading",
            background="#1E293B",
            foreground="#94A3B8",
            font=("Segoe UI", 9, "bold"),
            relief="flat"
        )
        style.map("Event.Treeview.Heading", background=[("active", "#334155")])
        style.map("Event.Treeview", background=[("selected", "#2563EB")])

        columns = ("time", "id", "channel", "level", "category", "provider")
        self.tree = ttk.Treeview(
            table_box,
            columns=columns,
            show="headings",
            selectmode="browse",
            style="Event.Treeview"
        )

        self.tree.heading("time", text="Timestamp", anchor="w")
        self.tree.heading("id", text="Event ID", anchor="center")
        self.tree.heading("channel", text="Log Channel", anchor="w")
        self.tree.heading("level", text="Level", anchor="center")
        self.tree.heading("category", text="Category", anchor="w")
        self.tree.heading("provider", text="Source / Provider", anchor="w")

        self.tree.column("time", width=140, minwidth=130, anchor="w")
        self.tree.column("id", width=70, minwidth=60, anchor="center")
        self.tree.column("channel", width=90, minwidth=80, anchor="w")
        self.tree.column("level", width=85, minwidth=75, anchor="center")
        self.tree.column("category", width=140, minwidth=110, anchor="w")
        self.tree.column("provider", width=220, minwidth=150, anchor="w")

        v_scroll = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        # Color tags
        self.tree.tag_configure("error", foreground="#F87171")
        self.tree.tag_configure("warning", foreground="#FBBF24")
        self.tree.tag_configure("info", foreground="#60A5FA")
        self.tree.tag_configure("success", foreground="#34D399")

        self.tree.bind("<<TreeviewSelect>>", self._on_event_selected)

        # 2. Detail Inspector
        detail_box = ctk.CTkFrame(content_frame, corner_radius=10, fg_color=("#111827", "#0F172A"))
        detail_box.grid(row=1, column=0, sticky="nsew")
        detail_box.grid_columnconfigure(0, weight=1)
        detail_box.grid_rowconfigure(1, weight=1)

        detail_header = ctk.CTkLabel(
            detail_box,
            text="EVENT DETAILS & DIAGNOSTIC MESSAGE",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#94A3B8"
        )
        detail_header.grid(row=0, column=0, padx=12, pady=(8, 4), sticky="w")

        self.detail_text = ctk.CTkTextbox(
            detail_box,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#E2E8F0",
            fg_color="#090D16",
            corner_radius=6,
            wrap="word"
        )
        self.detail_text.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        self.detail_text.insert("1.0", "Select any event from the table above to view full technical message details.")

    def run_query(self):
        """Queries event logs in background thread."""
        cat_key = self.category_map.get(self.category_menu.get(), "all")
        hours = self.time_map.get(self.time_menu.get(), 168)

        self.query_btn.configure(state="disabled", text="Querying...")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", "Querying Windows Event Log (Please wait 1-3 seconds)...")

        def worker():
            res = query_event_logs(category=cat_key, time_range_hours=hours, max_events=100)
            try:
                self.after(0, lambda: self._apply_query_result(res))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_query_result(self, res: EventQueryResult):
        self.query_btn.configure(state="normal", text="Query Event Logs")
        self.current_events = res.events

        if res.admin_warning:
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("1.0", f"[ATTENTION]: {res.admin_warning}\n\nTo view Security audit logs, right-click the application and select 'Run as Administrator'.")

        self._apply_search_filter()

    def _apply_search_filter(self):
        query = self.search_entry.get().strip().lower()

        filtered = []
        for e in self.current_events:
            if query:
                combined = f"{e.event_id} {e.log_name} {e.level} {e.category} {e.provider_name} {e.message} {e.user_or_account}".lower()
                if query not in combined:
                    continue
            filtered.append(e)

        self.filtered_events = filtered
        self._populate_tree(filtered)

    def _populate_tree(self, events: List[WindowsEvent]):
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not events:
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("1.0", "No matching events found for the selected category and time window.")
            return

        for e in events:
            # Tag determination
            lvl_lower = e.level.lower()
            if "error" in lvl_lower or "critical" in lvl_lower or e.event_id == 4625:
                tag = "error"
            elif "warning" in lvl_lower:
                tag = "warning"
            elif e.event_id == 4624:
                tag = "success"
            else:
                tag = "info"

            self.tree.insert(
                "",
                "end",
                values=(
                    e.time_created,
                    e.event_id,
                    e.log_name,
                    e.level,
                    e.category,
                    e.provider_name
                ),
                tags=(tag,)
            )

        # Select first item by default
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self._display_event_detail(events[0])

    def _on_event_selected(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        item_idx = self.tree.index(selected_items[0])
        if 0 <= item_idx < len(self.filtered_events):
            self._display_event_detail(self.filtered_events[item_idx])

    def _display_event_detail(self, e: WindowsEvent):
        self.detail_text.delete("1.0", "end")
        header = f"=== EVENT ID {e.event_id} [{e.category.upper()}] ===\n"
        header += f"Log Channel:  {e.log_name}\n"
        header += f"Severity:     {e.level}\n"
        header += f"Timestamp:    {e.time_created}\n"
        header += f"Provider:     {e.provider_name}\n"
        if e.user_or_account:
            header += f"User / SID:   {e.user_or_account}\n"
        header += "-" * 60 + "\n\n"
        header += f"{e.message}\n"

        self.detail_text.insert("1.0", header)
