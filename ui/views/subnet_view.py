"""
Subnet IP Scanner & LAN Device Mapper View
High-speed multithreaded ARP/ICMP subnet discovery, OUI hardware vendor identification,
and interactive local network device inspection.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.subnet_scanner import (
    DiscoveredDevice,
    SubnetScanResult,
    detect_default_subnet,
    scan_subnet,
)
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class SubnetView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.last_result: Optional[SubnetScanResult] = None
        self.devices: List[DiscoveredDevice] = []
        self.selected_device: Optional[DiscoveredDevice] = None
        self.is_scanning = False

        self._create_header()
        self._create_controls_section()
        self._create_summary_cards()
        self._create_table_section()
        self._create_device_inspector()

        # Initial auto-detection
        self._auto_detect_subnet()

    def _create_header(self):
        """Top title."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Subnet IP Scanner & LAN Device Mapper",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

    def _create_controls_section(self):
        """Target CIDR entry, auto-detect button, scan button, and progress bar."""
        ctrl_box = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        ctrl_box.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        ctrl_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl_box,
            text="Target Subnet CIDR:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, padx=(14, 6), pady=(12, 6), sticky="w")

        self.cidr_entry = ctk.CTkEntry(
            ctrl_box,
            placeholder_text="e.g. 192.168.1.0/24",
            width=180,
            height=30
        )
        self.cidr_entry.grid(row=0, column=1, padx=6, pady=(12, 6), sticky="w")

        btn_box = ctk.CTkFrame(ctrl_box, fg_color="transparent")
        btn_box.grid(row=0, column=2, padx=(6, 14), pady=(12, 6), sticky="e")

        self.detect_btn = ctk.CTkButton(
            btn_box,
            text="Auto-Detect",
            width=100,
            height=30,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._auto_detect_subnet
        )
        self.detect_btn.pack(side="left", padx=(0, 6))

        self.scan_btn = ctk.CTkButton(
            btn_box,
            text="Start Subnet Sweep",
            width=150,
            height=30,
            fg_color="#059669",
            hover_color="#047857",
            command=self._start_scan
        )
        self.scan_btn.pack(side="left")

        # Progress bar
        self.prog_bar = ctk.CTkProgressBar(ctrl_box, height=8, corner_radius=4)
        self.prog_bar.set(0.0)
        self.prog_bar.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 12), sticky="ew")

    def _create_summary_cards(self):
        """4 Overview Stat Cards."""
        cards_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cards_frame.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="ew")
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_active = InfoCard(cards_frame, title="Active Devices Found", value="0", subtitle="Discovered on LAN")
        self.card_active.grid(row=0, column=0, padx=(12, 4), pady=12, sticky="ew")

        self.card_total = InfoCard(cards_frame, title="Total Subnet Hosts", value="0", subtitle="Scanned IP addresses")
        self.card_total.grid(row=0, column=1, padx=4, pady=12, sticky="ew")

        self.card_gw = InfoCard(cards_frame, title="Default Gateway", value="--", subtitle="Local subnet router")
        self.card_gw.grid(row=0, column=2, padx=4, pady=12, sticky="ew")

        self.card_time = InfoCard(cards_frame, title="Sweep Duration", value="--", subtitle="High-speed sweep")
        self.card_time.grid(row=0, column=3, padx=(4, 12), pady=12, sticky="ew")

    def _create_table_section(self):
        """Table of Discovered Devices."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        # Toolbar
        tb = ctk.CTkFrame(table_container, fg_color="transparent")
        tb.grid(row=0, column=0, padx=12, pady=(10, 6), sticky="ew")
        tb.grid_columnconfigure(1, weight=1)

        self.seg_filter = ctk.CTkSegmentedButton(
            tb,
            values=["All Devices", "Gateways / PC", "Known Vendors", "Randomized / Mobile"],
            command=lambda v: self._apply_filters()
        )
        self.seg_filter.set("All Devices")
        self.seg_filter.grid(row=0, column=0, sticky="w")

        self.search_entry = ctk.CTkEntry(
            tb,
            placeholder_text="Search IP, MAC, Vendor, Hostname...",
            width=230,
            height=28
        )
        self.search_entry.grid(row=0, column=1, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

        # Treeview Box
        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=1, column=0, padx=10, pady=(0, 6), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        cols = ("role", "ip", "mac", "vendor", "hostname", "ping")
        self.tree = ttk.Treeview(
            tree_box,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=9
        )

        self.tree.heading("role", text="Role / Status", anchor="center")
        self.tree.heading("ip", text="IP Address", anchor="w")
        self.tree.heading("mac", text="Physical MAC Address", anchor="w")
        self.tree.heading("vendor", text="Hardware Vendor (OUI)", anchor="w")
        self.tree.heading("hostname", text="Resolved Hostname", anchor="w")
        self.tree.heading("ping", text="Ping RTT", anchor="center")

        self.tree.column("role", width=120, minwidth=100, anchor="center")
        self.tree.column("ip", width=125, minwidth=110, anchor="w")
        self.tree.column("mac", width=145, minwidth=130, anchor="w")
        self.tree.column("vendor", width=190, minwidth=150, anchor="w")
        self.tree.column("hostname", width=180, minwidth=140, anchor="w")
        self.tree.column("ping", width=80, minwidth=70, anchor="center")

        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        self.tree.tag_configure("gateway", foreground="#3B82F6")
        self.tree.tag_configure("self", foreground="#10B981")
        self.tree.tag_configure("active", foreground="#F3F4F6")

        self.tree.bind("<<TreeviewSelect>>", self._on_device_selected)

        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 devices",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=2, column=0, padx=14, pady=(0, 8), sticky="w")

    def _create_device_inspector(self):
        """Selected device details and quick copy/ping."""
        self.insp_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.insp_frame.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.insp_frame.grid_columnconfigure(0, weight=1)

        self.insp_title = ctk.CTkLabel(
            self.insp_frame,
            text="SELECTED DEVICE: NONE (CLICK A ROW ABOVE)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        self.insp_title.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.insp_details = ctk.CTkLabel(
            self.insp_frame,
            text="Select any active network endpoint above to view vendor metadata, MAC address, and hostname.",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#D1D5DB"),
            anchor="w"
        )
        self.insp_details.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

    def _auto_detect_subnet(self):
        """Detects the default gateway's active subnet."""
        try:
            sub, my_ip, gw = detect_default_subnet()
            self.cidr_entry.delete(0, "end")
            self.cidr_entry.insert(0, sub)
            self.card_gw.update_content(value=gw or "--", subtitle="Subnet Router")
        except Exception as e:
            logger.error(f"Error auto-detecting subnet: {e}")

    def _start_scan(self):
        if self.is_scanning:
            return

        cidr = self.cidr_entry.get().strip()
        if not cidr:
            return

        self.is_scanning = True
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.prog_bar.set(0.0)

        def progress_cb(done, total):
            pct = done / max(1, total)
            try:
                self.after(0, lambda: self.prog_bar.set(pct))
            except Exception:
                pass

        def worker():
            res = scan_subnet(cidr, progress_callback=progress_cb)

            def ui_update():
                self.last_result = res
                self.devices = res.devices

                self.card_active.update_content(value=str(res.active_hosts_found), subtitle="Active Endpoints")
                self.card_total.update_content(value=str(res.total_hosts_scanned), subtitle=f"CIDR: {res.subnet_cidr}")
                self.card_time.update_content(value=f"{res.scan_duration_sec:.1f}s", subtitle="Multithreaded")

                self._apply_filters()
                self.scan_btn.configure(state="normal", text="Start Subnet Sweep")
                self.is_scanning = False

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
        for d in self.devices:
            if mode == "Gateways / PC" and not (d.is_gateway or d.is_self):
                continue
            if mode == "Known Vendors" and ("Generic" in d.vendor or "Unknown" in d.vendor or "Randomized" in d.vendor):
                continue
            if mode == "Randomized / Mobile" and "Randomized" not in d.vendor:
                continue

            if query:
                match = (
                    query in d.ip.lower() or
                    query in d.mac.lower() or
                    query in d.vendor.lower() or
                    query in d.hostname.lower()
                )
                if not match:
                    continue

            tag = "active"
            if d.is_gateway:
                tag = "gateway"
            elif d.is_self:
                tag = "self"

            role_badge = d.status.upper()
            self.tree.insert(
                "",
                "end",
                values=(
                    role_badge,
                    d.ip,
                    d.mac,
                    d.vendor,
                    d.hostname,
                    f"{d.latency_ms:.1f} ms" if d.latency_ms > 0 else "< 1 ms"
                ),
                tags=(tag,)
            )
            count += 1

        self.count_label.configure(text=f"Displaying {count} of {len(self.devices)} devices")

    def _on_device_selected(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals:
            target_ip = vals[1]
            dev = next((d for d in self.devices if d.ip == target_ip), None)
            if dev:
                self.selected_device = dev
                self.insp_title.configure(text=f"DEVICE: {dev.ip} [{dev.status.upper()}]")
                self.insp_details.configure(text=f"• Hardware MAC: {dev.mac} | Manufacturer: {dev.vendor}\n• Hostname: {dev.hostname} | Ping Latency: {dev.latency_ms:.1f} ms")
