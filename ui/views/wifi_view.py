"""
Wi-Fi Signal & Wireless Channel Analyzer View
Displays live connected Wi-Fi telemetry, nearby Access Point discovery table,
signal strength meters (dBm), and channel congestion recommendations.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.wifi_analyzer import (
    ConnectedWifiInfo,
    DiscoveredAccessPoint,
    WifiScanReport,
    run_full_wifi_scan,
)
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class WifiView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.all_aps: List[DiscoveredAccessPoint] = []
        self.is_scanning = False

        self._create_header()
        self._create_active_connection_section()
        self._create_advisor_section()
        self._create_table_section()

        # Load initial Wi-Fi scan on creation
        self.refresh_wifi_data()

    def _create_header(self):
        """Top title and scan button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Wi-Fi Signal & Channel Analyzer",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.scan_btn = ctk.CTkButton(
            header_frame,
            text="Scan Wi-Fi Networks",
            width=160,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.refresh_wifi_data
        )
        self.scan_btn.grid(row=0, column=1, sticky="e")

    def _create_active_connection_section(self):
        """Active connected Wi-Fi card with signal meter and link speed."""
        conn_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        conn_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        conn_frame.grid_columnconfigure(0, weight=1)
        conn_frame.grid_columnconfigure(1, weight=1)
        conn_frame.grid_columnconfigure(2, weight=1)

        # Header inside card
        header_box = ctk.CTkFrame(conn_frame, fg_color="transparent")
        header_box.grid(row=0, column=0, columnspan=3, padx=14, pady=(12, 6), sticky="ew")
        header_box.grid_columnconfigure(0, weight=1)

        self.conn_title_label = ctk.CTkLabel(
            header_box,
            text="ACTIVE CONNECTION: CONNECTING...",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#1E40AF", "#60A5FA"),
            anchor="w"
        )
        self.conn_title_label.grid(row=0, column=0, sticky="w")

        self.conn_badge = StatusBadge(header_box, status="PENDING", width=110, height=26)
        self.conn_badge.grid(row=0, column=1, sticky="e")

        # Row 1: Signal Gauge
        sig_box = ctk.CTkFrame(conn_frame, fg_color="transparent")
        sig_box.grid(row=1, column=0, columnspan=3, padx=14, pady=(0, 12), sticky="ew")
        sig_box.grid_columnconfigure(0, weight=1)

        self.sig_label = ctk.CTkLabel(
            sig_box,
            text="Signal Strength: --% (-- dBm)",
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w"
        )
        self.sig_label.grid(row=0, column=0, sticky="w")

        self.sig_bar = ctk.CTkProgressBar(sig_box, height=10, corner_radius=5)
        self.sig_bar.set(0.0)
        self.sig_bar.grid(row=1, column=0, pady=(4, 0), sticky="ew")

        # Row 2 & 3: Info Cards
        self.card_ssid = InfoCard(conn_frame, title="SSID Name", value="--", subtitle="Network Name")
        self.card_ssid.grid(row=2, column=0, padx=(12, 6), pady=4, sticky="ew")

        self.card_bssid = InfoCard(conn_frame, title="Access Point (BSSID)", value="--", subtitle="AP Radio MAC")
        self.card_bssid.grid(row=2, column=1, padx=6, pady=4, sticky="ew")

        self.card_channel = InfoCard(conn_frame, title="Channel & Band", value="--", subtitle="Frequency")
        self.card_channel.grid(row=2, column=2, padx=(6, 12), pady=4, sticky="ew")

        self.card_radio = InfoCard(conn_frame, title="Radio & Security", value="--", subtitle="Protocol / Cipher")
        self.card_radio.grid(row=3, column=0, padx=(12, 6), pady=(4, 12), sticky="ew")

        self.card_speed = InfoCard(conn_frame, title="Link Rates", value="--", subtitle="Rx / Tx Speed")
        self.card_speed.grid(row=3, column=1, padx=6, pady=(4, 12), sticky="ew")

        self.card_adapter = InfoCard(conn_frame, title="Wi-Fi Interface", value="--", subtitle="Hardware Adapter")
        self.card_adapter.grid(row=3, column=2, padx=(6, 12), pady=(4, 12), sticky="ew")

    def _create_advisor_section(self):
        """Channel optimization advisor and overlap warnings."""
        self.advisor_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#DBEAFE", "#1E3A8A"))
        self.advisor_frame.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="ew")
        self.advisor_frame.grid_columnconfigure(0, weight=1)

        self.advisor_title = ctk.CTkLabel(
            self.advisor_frame,
            text="CHANNEL OPTIMIZATION & INTERFERENCE ADVISOR",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        self.advisor_title.grid(row=0, column=0, padx=14, pady=(10, 2), sticky="w")

        self.advisor_desc = ctk.CTkLabel(
            self.advisor_frame,
            text="Analyzing nearby wireless access points for channel overlap and interference...",
            font=ctk.CTkFont(size=12),
            text_color=("#1E3A8A", "#BFDBFE"),
            anchor="w",
            wraplength=700,
            justify="left"
        )
        self.advisor_desc.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

    def _create_table_section(self):
        """Discovered nearby access points table."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        # Toolbar above table
        top_bar = ctk.CTkFrame(table_container, fg_color="transparent")
        top_bar.grid(row=0, column=0, padx=14, pady=(10, 6), sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top_bar,
            text="DISCOVERED NEARBY ACCESS POINTS (BSSIDs)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        ).grid(row=0, column=0, sticky="w")

        self.search_entry = ctk.CTkEntry(
            top_bar,
            placeholder_text="Search SSID, BSSID, Channel...",
            width=220,
            height=28
        )
        self.search_entry.grid(row=0, column=2, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_search())

        # Treeview Box
        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        columns = ("status", "ssid", "bssid", "signal", "channel", "band", "radio", "security")
        self.tree = ttk.Treeview(
            tree_box,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=8
        )

        self.tree.heading("status", text="State", anchor="center")
        self.tree.heading("ssid", text="SSID (Network Name)", anchor="w")
        self.tree.heading("bssid", text="BSSID (AP MAC)", anchor="w")
        self.tree.heading("signal", text="Signal (dBm)", anchor="center")
        self.tree.heading("channel", text="Channel", anchor="center")
        self.tree.heading("band", text="Band", anchor="center")
        self.tree.heading("radio", text="Radio", anchor="center")
        self.tree.heading("security", text="Authentication", anchor="w")

        self.tree.column("status", width=80, minwidth=70, anchor="center")
        self.tree.column("ssid", width=170, minwidth=130, anchor="w")
        self.tree.column("bssid", width=140, minwidth=120, anchor="w")
        self.tree.column("signal", width=110, minwidth=90, anchor="center")
        self.tree.column("channel", width=70, minwidth=60, anchor="center")
        self.tree.column("band", width=80, minwidth=70, anchor="center")
        self.tree.column("radio", width=80, minwidth=70, anchor="center")
        self.tree.column("security", width=130, minwidth=110, anchor="w")

        # Scrollbar
        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        # Treeview tags
        self.tree.tag_configure("connected", foreground="#10B981")
        self.tree.tag_configure("open_warning", foreground="#EF4444")
        self.tree.tag_configure("normal", foreground="#E5E7EB")

        # Bottom record count label
        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 access points",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=2, column=0, padx=14, pady=(0, 6), sticky="w")

    def refresh_wifi_data(self):
        """Scans Wi-Fi networks and updates UI immediately."""
        try:
            self.scan_btn.configure(state="disabled", text="Scanning...")
            report = run_full_wifi_scan()
            self._apply_report(report)
        except Exception as e:
            logger.error(f"Error scanning Wi-Fi: {e}", exc_info=True)
        finally:
            try:
                self.scan_btn.configure(state="normal", text="Scan Wi-Fi Networks")
            except Exception:
                pass

    def _apply_report(self, report: WifiScanReport):
        self.all_aps = report.discovered_aps

        # 1. Update Active Connection Card
        conn = report.connected_info
        if conn and conn.state == "connected":
            self.conn_title_label.configure(
                text=f"ACTIVE CONNECTION: {conn.ssid}",
                text_color=("#166534", "#34D399")
            )
            self.conn_badge.set_status("PASS", custom_text="CONNECTED")

            sig_pct = conn.signal_percent
            dbm = conn.signal_dbm
            self.sig_label.configure(text=f"Signal Strength: {sig_pct}% ({dbm} dBm)")
            self.sig_bar.set(min(1.0, max(0.0, sig_pct / 100.0)))
            if sig_pct >= 70:
                self.sig_bar.configure(progress_color="#10B981")
            elif sig_pct >= 40:
                self.sig_bar.configure(progress_color="#F59E0B")
            else:
                self.sig_bar.configure(progress_color="#EF4444")

            self.card_ssid.update_content(value=conn.ssid, subtitle=f"Profile: {conn.ssid}")
            self.card_bssid.update_content(value=conn.bssid, subtitle="Connected AP BSSID")
            self.card_channel.update_content(value=f"Channel {conn.channel}", subtitle=conn.band)
            self.card_radio.update_content(value=conn.radio_type, subtitle=f"{conn.auth} ({conn.cipher})")
            self.card_speed.update_content(value=f"{conn.rx_rate_mbps:.1f} Mbps", subtitle=f"Tx: {conn.tx_rate_mbps:.1f} Mbps")
            self.card_adapter.update_content(value=conn.interface_name, subtitle=conn.adapter_description[:25])
        else:
            self.conn_title_label.configure(
                text="ACTIVE CONNECTION: NOT CONNECTED TO WI-FI",
                text_color=("#991B1B", "#FCA5A5")
            )
            self.conn_badge.set_status("FAIL", custom_text="DISCONNECTED")
            self.sig_label.configure(text="Signal Strength: 0% (-100 dBm)")
            self.sig_bar.set(0.0)
            self.card_ssid.update_content(value="--", subtitle="No active Wi-Fi connection")

        # 2. Update Channel Advisor Box
        ch24 = report.band_24_counts
        ch5 = report.band_5_counts
        best24 = report.best_24_channel

        ch24_str = ", ".join([f"Ch {k} ({v} APs)" for k, v in ch24.items()]) or "None"
        ch5_str = ", ".join([f"Ch {k} ({v} APs)" for k, v in ch5.items()]) or "None"

        lines = [
            f"• 2.4 GHz Channel Activity: {ch24_str}",
            f"• 5 GHz Channel Activity: {ch5_str}",
            f"• Recommended 2.4 GHz Non-Overlapping Channel: Channel {best24} (Cleanest channel among 1, 6, 11)"
        ]

        if report.overlap_warnings:
            lines.append("• ⚠️ CHANNEL OVERLAP WARNINGS:")
            for w in report.overlap_warnings[:2]:
                lines.append(f"   - {w}")

        self.advisor_desc.configure(text="\n".join(lines))

        # 3. Populate AP Table
        self._apply_search()

    def _apply_search(self):
        query = self.search_entry.get().strip().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)

        count = 0
        for ap in self.all_aps:
            if query:
                match = (
                    query in ap.ssid.lower() or
                    query in ap.bssid.lower() or
                    query in str(ap.channel) or
                    query in ap.band.lower() or
                    query in ap.auth.lower()
                )
                if not match:
                    continue

            tag = "normal"
            state_text = "Discovered"
            if ap.is_connected:
                tag = "connected"
                state_text = "CONNECTED"
            elif ap.security_rating == "WARNING_OPEN":
                tag = "open_warning"
                state_text = "OPEN / NO PWD"

            self.tree.insert(
                "",
                "end",
                values=(
                    state_text,
                    ap.ssid,
                    ap.bssid,
                    f"{ap.signal_percent}% ({ap.signal_dbm} dBm)",
                    ap.channel,
                    ap.band,
                    ap.radio_type,
                    f"{ap.auth} ({ap.encryption})"
                ),
                tags=(tag,)
            )
            count += 1

        self.count_label.configure(text=f"Displaying {count} of {len(self.all_aps)} discovered access points")
