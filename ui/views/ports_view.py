"""
Ports & Connections View
Displays active TCP/UDP sockets, listening endpoints, established sessions,
and owning Windows process metadata.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import List, Optional

from core.port_scanner import SocketConnection, get_active_connections, get_listening_summary
from ui.components.info_card import InfoCard
from utils.logger import get_logger

logger = get_logger()


class PortsView(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.all_connections: List[SocketConnection] = []
        self.filtered_connections: List[SocketConnection] = []

        self._create_header()
        self._create_summary_bar()
        self._create_filter_bar()
        self._create_table_view()

        # Load data on view load
        self.refresh_connections()

    def _create_header(self):
        """Top title and refresh button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Ports & Active Socket Connections",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.refresh_btn = ctk.CTkButton(
            header_frame,
            text="Refresh Sockets",
            width=130,
            command=self.refresh_connections
        )
        self.refresh_btn.grid(row=0, column=1, sticky="e")

    def _create_summary_bar(self):
        """Metric summary cards."""
        summary_frame = ctk.CTkFrame(self, fg_color="transparent")
        summary_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="ew")
        summary_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_total = InfoCard(summary_frame, title="Total Sockets", value="--", subtitle="All endpoints")
        self.card_total.grid(row=0, column=0, padx=(0, 5), sticky="ew")

        self.card_listen = InfoCard(summary_frame, title="Listening Ports", value="--", subtitle="Open server sockets", accent_color="#10B981")
        self.card_listen.grid(row=0, column=1, padx=5, sticky="ew")

        self.card_estab = InfoCard(summary_frame, title="Established", value="--", subtitle="Active sessions", accent_color="#3B82F6")
        self.card_estab.grid(row=0, column=2, padx=5, sticky="ew")

        self.card_proc = InfoCard(summary_frame, title="Active Processes", value="--", subtitle="Owning network apps")
        self.card_proc.grid(row=0, column=3, padx=(5, 0), sticky="ew")

    def _create_filter_bar(self):
        """Search and dropdown filter bar."""
        filter_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        filter_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        filter_frame.grid_columnconfigure(1, weight=1)

        # Search box
        ctk.CTkLabel(filter_frame, text="Search:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12, 6), pady=10, sticky="w")
        
        self.search_entry = ctk.CTkEntry(
            filter_frame,
            placeholder_text="Filter by Process (e.g. chrome, svchost), Port (e.g. 445), IP, or Tag...",
            height=30
        )
        self.search_entry.grid(row=0, column=1, padx=6, pady=10, sticky="ew")
        self.search_entry.bind("<KeyRelease>", lambda event: self._apply_filters())

        # Protocol filter
        ctk.CTkLabel(filter_frame, text="Proto:", font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=(10, 4), pady=10, sticky="w")
        self.proto_menu = ctk.CTkOptionMenu(
            filter_frame,
            values=["All Protocols", "TCP Only", "UDP Only"],
            command=lambda choice: self._apply_filters(),
            width=110,
            height=30
        )
        self.proto_menu.set("All Protocols")
        self.proto_menu.grid(row=0, column=3, padx=4, pady=10, sticky="w")

        # State filter
        ctk.CTkLabel(filter_frame, text="State:", font=ctk.CTkFont(size=12)).grid(row=0, column=4, padx=(10, 4), pady=10, sticky="w")
        self.state_menu = ctk.CTkOptionMenu(
            filter_frame,
            values=["All States", "Listening", "Established", "Time_Wait", "Close_Wait"],
            command=lambda choice: self._apply_filters(),
            width=115,
            height=30
        )
        self.state_menu.set("All States")
        self.state_menu.grid(row=0, column=5, padx=(4, 12), pady=10, sticky="w")

    def _create_table_view(self):
        """Table view for connection entries using stylized ttk.Treeview."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#111827", "#0F172A"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)
        table_container.grid_rowconfigure(0, weight=1)

        # Style Treeview for dark mode
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Treeview",
            background="#0F172A",
            foreground="#F8FAFC",
            fieldbackground="#0F172A",
            rowheight=26,
            font=("Segoe UI", 10)
        )
        style.configure(
            "Treeview.Heading",
            background="#1E293B",
            foreground="#94A3B8",
            font=("Segoe UI", 10, "bold"),
            relief="flat"
        )
        style.map("Treeview.Heading", background=[("active", "#334155")])
        style.map("Treeview", background=[("selected", "#2563EB")])

        # Columns
        columns = ("proto", "local", "remote", "state", "proc", "pid", "tag")
        self.tree = ttk.Treeview(
            table_container,
            columns=columns,
            show="headings",
            selectmode="browse"
        )

        # Headings
        self.tree.heading("proto", text="Protocol", anchor="center")
        self.tree.heading("local", text="Local Address:Port", anchor="w")
        self.tree.heading("remote", text="Remote Address:Port", anchor="w")
        self.tree.heading("state", text="State", anchor="center")
        self.tree.heading("proc", text="Process Name", anchor="w")
        self.tree.heading("pid", text="PID", anchor="center")
        self.tree.heading("tag", text="Service / Tag", anchor="w")

        # Column widths
        self.tree.column("proto", width=70, minwidth=60, anchor="center")
        self.tree.column("local", width=180, minwidth=140, anchor="w")
        self.tree.column("remote", width=180, minwidth=140, anchor="w")
        self.tree.column("state", width=110, minwidth=90, anchor="center")
        self.tree.column("proc", width=160, minwidth=120, anchor="w")
        self.tree.column("pid", width=70, minwidth=60, anchor="center")
        self.tree.column("tag", width=160, minwidth=100, anchor="w")

        # Scrollbars
        v_scroll = ttk.Scrollbar(table_container, orient="vertical", command=self.tree.yview)
        h_scroll = ttk.Scrollbar(table_container, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")
        h_scroll.grid(row=1, column=0, sticky="ew")

        # Table row tags for color coding
        self.tree.tag_configure("listening", foreground="#34D399")
        self.tree.tag_configure("established", foreground="#60A5FA")
        self.tree.tag_configure("timewait", foreground="#FBBF24")
        self.tree.tag_configure("udp", foreground="#C084FC")
        self.tree.tag_configure("default", foreground="#E2E8F0")

        # Bottom record count label
        self.count_label = ctk.CTkLabel(
            self,
            text="Displaying 0 sockets",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=4, column=0, padx=14, pady=(0, 5), sticky="w")

    def refresh_connections(self):
        """Scans active sockets in background thread."""
        self.refresh_btn.configure(state="disabled", text="Scanning...")

        def worker():
            conns = get_active_connections()
            summary = get_listening_summary()
            try:
                self.after(0, lambda: self._apply_data(conns, summary))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_data(self, connections: List[SocketConnection], summary: dict):
        self.all_connections = connections
        self.refresh_btn.configure(state="normal", text="Refresh Sockets")

        # Update summary cards
        self.card_total.update_content(value=str(summary["total_sockets"]), subtitle="Total endpoints")
        self.card_listen.update_content(value=str(summary["listening_tcp"]), subtitle="Listening TCP ports")
        self.card_estab.update_content(value=str(summary["established_sessions"]), subtitle="Active connections")
        self.card_proc.update_content(value=str(summary["active_processes"]), subtitle="Unique processes")

        self._apply_filters()

    def _apply_filters(self):
        search_query = self.search_entry.get().strip().lower()
        proto_filter = self.proto_menu.get().lower()
        state_filter = self.state_menu.get().lower()

        filtered = []
        for c in self.all_connections:
            # Protocol match
            if proto_filter == "tcp only" and c.protocol != "TCP":
                continue
            if proto_filter == "udp only" and c.protocol != "UDP":
                continue

            # State match
            if state_filter == "listening" and c.state not in ["LISTENING", "ACTIVE (UDP)"]:
                continue
            if state_filter == "established" and c.state != "ESTABLISHED":
                continue
            if state_filter == "time_wait" and c.state != "TIME_WAIT":
                continue
            if state_filter == "close_wait" and c.state != "CLOSE_WAIT":
                continue

            # Search text match (process, pid, local port, remote port, IP, tag)
            if search_query:
                combined_str = f"{c.process_name} {c.pid} {c.local_port} {c.remote_port} {c.local_address} {c.remote_address} {c.service_tag} {c.state}".lower()
                if search_query not in combined_str:
                    continue

            filtered.append(c)

        self.filtered_connections = filtered
        self._populate_tree(filtered)

    def _populate_tree(self, connections: List[SocketConnection]):
        # Clear existing rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        for c in connections:
            local_str = f"{c.local_address}:{c.local_port}"
            remote_str = f"{c.remote_address}:{c.remote_port}" if c.remote_port else c.remote_address
            pid_str = str(c.pid) if c.pid is not None else "--"

            # Determine color tag
            if c.state == "LISTENING":
                tag = "listening"
            elif c.state == "ESTABLISHED":
                tag = "established"
            elif c.state == "TIME_WAIT":
                tag = "timewait"
            elif c.protocol == "UDP":
                tag = "udp"
            else:
                tag = "default"

            self.tree.insert(
                "",
                "end",
                values=(
                    c.protocol,
                    local_str,
                    remote_str,
                    c.state,
                    c.process_name,
                    pid_str,
                    c.service_tag
                ),
                tags=(tag,)
            )

        self.count_label.configure(
            text=f"Displaying {len(connections)} of {len(self.all_connections)} active socket connections"
        )
