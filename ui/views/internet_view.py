"""
Internet & DNS Health View
Presents the automated 6-stage connectivity health ladder with interactive cards,
live progress, status badges, and actionable IT diagnosis.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.dns_internet import (
    ConnectivityStageResult,
    InternetHealthReport,
    check_adapter_stage,
    check_dns_stage,
    check_gateway_stage,
    check_https_stage,
    check_internet_ip_stage,
    check_latency_stage,
    run_internet_health_check,
)
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class StageCard(ctk.CTkFrame):
    """
    Card representing a single stage in the connectivity ladder.
    """
    def __init__(self, master, stage_num: int, title: str, subtitle: str, **kwargs):
        super().__init__(master, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"), **kwargs)

        self.grid_columnconfigure(1, weight=1)
        self.stage_num = stage_num

        # Stage Number circle/pill
        num_frame = ctk.CTkFrame(self, width=34, height=34, corner_radius=17, fg_color=("#3B82F6", "#1D4ED8"))
        num_frame.grid(row=0, column=0, rowspan=2, padx=(14, 12), pady=12, sticky="w")
        num_frame.grid_propagate(False)
        num_label = ctk.CTkLabel(num_frame, text=str(stage_num), font=ctk.CTkFont(size=14, weight="bold"), text_color="#FFFFFF")
        num_label.place(relx=0.5, rely=0.5, anchor="center")

        # Stage Title & Subtitle
        self.title_label = ctk.CTkLabel(
            self,
            text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
            anchor="w"
        )
        self.title_label.grid(row=0, column=1, padx=(0, 10), pady=(12, 2), sticky="w")

        self.details_label = ctk.CTkLabel(
            self,
            text=subtitle,
            font=ctk.CTkFont(size=12),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w",
            wraplength=480,
            justify="left"
        )
        self.details_label.grid(row=1, column=1, padx=(0, 10), pady=(0, 12), sticky="w")

        # Status Badge on right
        self.badge = StatusBadge(self, status="PENDING")
        self.badge.grid(row=0, column=2, rowspan=2, padx=14, pady=12, sticky="e")

    def set_result(self, result: ConnectivityStageResult):
        """Updates card with diagnostic result."""
        self.badge.set_status(result.verdict)
        summary_text = f"{result.summary} — {result.details}" if result.details else result.summary
        if result.failure_diagnosis and result.verdict in ["FAIL", "WARNING"]:
            summary_text += f"\n[DIAGNOSIS]: {result.failure_diagnosis}"
        self.details_label.configure(text=summary_text)

    def set_running(self):
        """Sets status to running/testing."""
        self.badge.set_status("RUNNING")
        self.details_label.configure(text="Executing diagnostic test...")


class InternetView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.stage_cards: Dict[int, StageCard] = {}
        self.is_running = False

        self._create_header()
        self._create_verdict_banner()
        self._create_ladder_section()
        self._create_quick_tools()

        # Run initial test on load
        self.run_full_diagnostics()

    def _create_header(self):
        """Top title and run button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Internet & DNS Connectivity Ladder",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.run_btn = ctk.CTkButton(
            header_frame,
            text="Run Full Diagnostics",
            width=170,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.run_full_diagnostics
        )
        self.run_btn.grid(row=0, column=1, sticky="e")

    def _create_verdict_banner(self):
        """Summary verdict and diagnosis banner."""
        self.banner = ctk.CTkFrame(self, corner_radius=12, fg_color=("#DBEAFE", "#1E3A8A"))
        self.banner.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="ew")
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner.grid_columnconfigure(1, weight=0)

        left_box = ctk.CTkFrame(self.banner, fg_color="transparent")
        left_box.grid(row=0, column=0, padx=16, pady=14, sticky="w")

        self.banner_title = ctk.CTkLabel(
            left_box,
            text="CONNECTIVITY STATUS: TESTING...",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        self.banner_title.grid(row=0, column=0, sticky="w")

        self.banner_desc = ctk.CTkLabel(
            left_box,
            text="Executing sequential 6-stage network triage ladder...",
            font=ctk.CTkFont(size=12),
            text_color=("#1E3A8A", "#BFDBFE"),
            anchor="w",
            wraplength=600,
            justify="left"
        )
        self.banner_desc.grid(row=1, column=0, pady=(2, 0), sticky="w")

        self.overall_badge = StatusBadge(self.banner, status="PENDING", width=110, height=32)
        self.overall_badge.grid(row=0, column=1, padx=16, pady=14, sticky="e")

    def _create_ladder_section(self):
        """Builds the 6 stage cards."""
        ladder_frame = ctk.CTkFrame(self, fg_color="transparent")
        ladder_frame.grid(row=2, column=0, padx=10, pady=(0, 15), sticky="ew")
        ladder_frame.grid_columnconfigure(0, weight=1)

        stages_meta = [
            (1, "Stage 1: Network Adapter & Link", "Checks physical connection, operational state, and IP assignment."),
            (2, "Stage 2: Default Gateway Reachability", "Pings the local router to test local subnet delivery."),
            (3, "Stage 3: Public IP Routing (Internet Gateway)", "Pings 8.8.8.8 / 1.1.1.1 to confirm packets exit to the WAN."),
            (4, "Stage 4: DNS Domain Resolution", "Resolves public domain names (google.com, cloudflare.com)."),
            (5, "Stage 5: Secure Web Handshake (HTTPS / TLS 443)", "Establishes a complete TLS encrypted connection on port 443."),
            (6, "Stage 6: Latency & Response Quality", "Measures average ping response latency and packet loss."),
        ]

        for num, title, subtitle in stages_meta:
            card = StageCard(ladder_frame, stage_num=num, title=title, subtitle=subtitle)
            card.grid(row=num - 1, column=0, pady=4, sticky="ew")
            self.stage_cards[num] = card

    def _create_quick_tools(self):
        """Quick individual stage retest buttons."""
        quick_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        quick_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")
        quick_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        ctk.CTkLabel(
            quick_frame,
            text="INDIVIDUAL STAGE QUICK TESTS",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        ).grid(row=0, column=0, columnspan=4, padx=14, pady=(10, 6), sticky="w")

        ctk.CTkButton(
            quick_frame,
            text="Test Gateway Only",
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=lambda: self._run_single_stage(2, check_gateway_stage)
        ).grid(row=1, column=0, padx=6, pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="Test Public IP Routing",
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=lambda: self._run_single_stage(3, check_internet_ip_stage)
        ).grid(row=1, column=1, padx=6, pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="Test DNS Resolution",
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=lambda: self._run_single_stage(4, check_dns_stage)
        ).grid(row=1, column=2, padx=6, pady=(0, 12), sticky="ew")

        ctk.CTkButton(
            quick_frame,
            text="Test HTTPS Port 443",
            height=28,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=lambda: self._run_single_stage(5, check_https_stage)
        ).grid(row=1, column=3, padx=6, pady=(0, 12), sticky="ew")

    def run_full_diagnostics(self):
        """Runs the 6-stage connectivity ladder in a background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.run_btn.configure(state="disabled", text="Testing...")
        self.overall_badge.set_status("RUNNING", custom_text="TESTING...")
        self.banner_title.configure(text="CONNECTIVITY STATUS: RUNNING DIAGNOSTICS...")
        self.banner_desc.configure(text="Testing stages sequentially from local adapter to HTTPS...")

        # Reset all cards to pending
        for card in self.stage_cards.values():
            card.badge.set_status("PENDING")

        def progress_cb(stage_idx: int, stage_res: ConnectivityStageResult):
            try:
                self.after(0, lambda: self.stage_cards[stage_idx].set_result(stage_res))
            except (RuntimeError, tk.TclError):
                pass

        def worker():
            report = run_internet_health_check(progress_callback=progress_cb)
            try:
                self.after(0, lambda: self._apply_report(report))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_report(self, report: InternetHealthReport):
        self.is_running = False
        self.run_btn.configure(state="normal", text="Run Full Diagnostics")

        # Update banner
        if report.overall_status == "HEALTHY":
            self.overall_badge.set_status("PASS", custom_text="HEALTHY")
            self.banner.configure(fg_color=("#DCFCE7", "#064E3B"))
            self.banner_title.configure(
                text=f"STATUS: ALL SYSTEMS OPERATIONAL ({report.passed_count}/6 PASS)",
                text_color=("#166534", "#6EE7B7")
            )
        elif report.overall_status == "DEGRADED":
            self.overall_badge.set_status("WARNING", custom_text="DEGRADED")
            self.banner.configure(fg_color=("#FEF3C7", "#78350F"))
            self.banner_title.configure(
                text=f"STATUS: CONNECTION DEGRADED ({report.warning_count} Warnings)",
                text_color=("#92400E", "#FCD34D")
            )
        else:
            self.overall_badge.set_status("FAIL", custom_text="OFFLINE")
            self.banner.configure(fg_color=("#FEE2E2", "#7F1D1D"))
            self.banner_title.configure(
                text=f"STATUS: INTERNET OFFLINE ({report.failed_count} Failures)",
                text_color=("#991B1B", "#FCA5A5")
            )

        self.banner_desc.configure(text=f"{report.summary_verdict}\nRecommended: {report.recommended_action}")

    def _run_single_stage(self, stage_num: int, check_fn):
        """Runs a single stage test independently."""
        card = self.stage_cards.get(stage_num)
        if card:
            card.set_running()

        def worker():
            res = check_fn()
            try:
                if card:
                    self.after(0, lambda: card.set_result(res))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()
