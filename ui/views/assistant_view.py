"""
Troubleshooting Assistant View
Interactive Rule-Based IT Support problem-solving wizard.
Provides root-cause analysis and step-by-step remediation plans for common network problems.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.troubleshooting import (
    FindingItem,
    TroubleshootScenarioResult,
    diagnose_no_internet,
    diagnose_slow_network,
    diagnose_website_issue,
    diagnose_wifi_no_internet,
)
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class AssistantView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.is_running = False

        self._create_header()
        self._create_scenario_selector()
        self._create_verdict_banner()
        self._create_results_section()

    def _create_header(self):
        """Top title and action button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="IT Support Troubleshooting Assistant",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.diagnose_btn = ctk.CTkButton(
            header_frame,
            text="Run Diagnosis",
            width=150,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.run_diagnosis
        )
        self.diagnose_btn.grid(row=0, column=1, sticky="e")

    def _create_scenario_selector(self):
        """Selector bar for troubleshooting scenarios and custom targets."""
        selector_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        selector_frame.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="ew")
        selector_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            selector_frame,
            text="Select Problem Scenario:",
            font=ctk.CTkFont(size=12, weight="bold")
        ).grid(row=0, column=0, padx=(14, 8), pady=12, sticky="w")

        self.scenarios = [
            "No Internet Access (Full Stack Triage)",
            "Wi-Fi Connected but No Internet",
            "Cannot Access a Specific Website / Host",
            "Slow Network / High Latency & Jitter"
        ]

        self.scenario_menu = ctk.CTkOptionMenu(
            selector_frame,
            values=self.scenarios,
            command=self._on_scenario_changed,
            height=32
        )
        self.scenario_menu.set(self.scenarios[0])
        self.scenario_menu.grid(row=0, column=1, padx=8, pady=12, sticky="ew")

        # Custom Target Host box (for website check)
        self.target_frame = ctk.CTkFrame(selector_frame, fg_color="transparent")
        self.target_frame.grid(row=0, column=2, padx=(8, 14), pady=12, sticky="e")

        self.target_label = ctk.CTkLabel(self.target_frame, text="Target Host:", font=ctk.CTkFont(size=12))
        self.target_label.pack(side="left", padx=(0, 6))

        self.target_entry = ctk.CTkEntry(self.target_frame, placeholder_text="e.g. github.com", width=180, height=32)
        self.target_entry.insert(0, "github.com")
        self.target_entry.pack(side="left")

        # Hide target entry by default until scenario 3 is picked
        self.target_frame.grid_remove()

    def _on_scenario_changed(self, choice: str):
        if "Specific Website" in choice:
            self.target_frame.grid()
        else:
            self.target_frame.grid_remove()

    def _create_verdict_banner(self):
        """Hero root-cause diagnosis banner."""
        self.banner = ctk.CTkFrame(self, corner_radius=12, fg_color=("#DBEAFE", "#1E3A8A"))
        self.banner.grid(row=2, column=0, padx=10, pady=(0, 15), sticky="ew")
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner.grid_columnconfigure(1, weight=0)

        left_box = ctk.CTkFrame(self.banner, fg_color="transparent")
        left_box.grid(row=0, column=0, padx=16, pady=14, sticky="w")

        self.banner_title = ctk.CTkLabel(
            left_box,
            text="DIAGNOSIS: READY",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        self.banner_title.grid(row=0, column=0, sticky="w")

        self.banner_cause = ctk.CTkLabel(
            left_box,
            text="Select a problem scenario above and click 'Run Diagnosis' to execute rule-based decision trees.",
            font=ctk.CTkFont(size=13),
            text_color=("#1E3A8A", "#BFDBFE"),
            anchor="w",
            wraplength=600,
            justify="left"
        )
        self.banner_cause.grid(row=1, column=0, pady=(4, 0), sticky="w")

        self.verdict_badge = StatusBadge(self.banner, status="INFO", custom_text="READY", width=130, height=32)
        self.verdict_badge.grid(row=0, column=1, padx=16, pady=14, sticky="e")

    def _create_results_section(self):
        """Split layout: Confirmed Facts (left) and Remediation Plan (right)."""
        results_frame = ctk.CTkFrame(self, fg_color="transparent")
        results_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        results_frame.grid_columnconfigure(0, weight=1)
        results_frame.grid_columnconfigure(1, weight=1)

        # 1. Left: Confirmed Diagnostic Facts
        self.facts_container = ctk.CTkFrame(results_frame, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.facts_container.grid(row=0, column=0, padx=(0, 6), sticky="nsew")
        self.facts_container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.facts_container,
            text="CONFIRMED TELEMETRY FINDINGS",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA")
        ).grid(row=0, column=0, padx=14, pady=(12, 8), sticky="w")

        self.facts_list_frame = ctk.CTkFrame(self.facts_container, fg_color="transparent")
        self.facts_list_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="nsew")
        self.facts_list_frame.grid_columnconfigure(0, weight=1)

        # 2. Right: Actionable Remediation Plan
        self.plan_container = ctk.CTkFrame(results_frame, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.plan_container.grid(row=0, column=1, padx=(6, 0), sticky="nsew")
        self.plan_container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.plan_container,
            text="IT SUPPORT REMEDIATION PLAN",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#059669", "#34D399")
        ).grid(row=0, column=0, padx=14, pady=(12, 8), sticky="w")

        self.plan_list_frame = ctk.CTkFrame(self.plan_container, fg_color="transparent")
        self.plan_list_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="nsew")
        self.plan_list_frame.grid_columnconfigure(0, weight=1)

    def run_diagnosis(self):
        """Executes the selected troubleshooting scenario in background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.diagnose_btn.configure(state="disabled", text="Diagnosing...")
        self.verdict_badge.set_status("RUNNING", custom_text="DIAGNOSING...")
        self.banner_title.configure(text="DIAGNOSIS: EXECUTING DECISION TREES...")
        self.banner_cause.configure(text="Gathering live telemetry and testing network failure paths...")

        scenario_choice = self.scenario_menu.get()
        target_val = self.target_entry.get().strip() or "github.com"

        def worker():
            if "No Internet Access" in scenario_choice:
                result = diagnose_no_internet()
            elif "Wi-Fi Connected" in scenario_choice:
                result = diagnose_wifi_no_internet()
            elif "Specific Website" in scenario_choice:
                result = diagnose_website_issue(target_val)
            else:
                result = diagnose_slow_network()

            try:
                self.after(0, lambda: self._apply_result(result))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_result(self, result: TroubleshootScenarioResult):
        self.is_running = False
        self.diagnose_btn.configure(state="normal", text="Run Diagnosis")

        # 1. Update Banner
        if result.overall_verdict == "RESOLVED_ONLINE":
            self.verdict_badge.set_status("PASS", custom_text="NO ISSUE FOUND")
            self.banner.configure(fg_color=("#DCFCE7", "#064E3B"))
            self.banner_title.configure(
                text="DIAGNOSTIC RESULT: NETWORK FULLY OPERATIONAL",
                text_color=("#166534", "#6EE7B7")
            )
            self.banner_cause.configure(
                text=result.probable_root_cause,
                text_color=("#14532D", "#D1FAE5")
            )
        elif result.overall_verdict == "WARNING_DEGRADED":
            self.verdict_badge.set_status("WARNING", custom_text="DEGRADED")
            self.banner.configure(fg_color=("#FEF3C7", "#78350F"))
            self.banner_title.configure(
                text="DIAGNOSTIC RESULT: DEGRADED PERFORMANCE DETECTED",
                text_color=("#92400E", "#FCD34D")
            )
            self.banner_cause.configure(
                text=result.probable_root_cause,
                text_color=("#78350F", "#FEF3C7")
            )
        else:
            self.verdict_badge.set_status("FAIL", custom_text="FAILURE DETECTED")
            self.banner.configure(fg_color=("#FEE2E2", "#7F1D1D"))
            self.banner_title.configure(
                text="DIAGNOSTIC RESULT: ROOT CAUSE IDENTIFIED",
                text_color=("#991B1B", "#FCA5A5")
            )
            self.banner_cause.configure(
                text=result.probable_root_cause,
                text_color=("#7F1D1D", "#FEE2E2")
            )

        # 2. Render Confirmed Facts
        for widget in self.facts_list_frame.winfo_children():
            widget.destroy()

        for i, fact in enumerate(result.confirmed_facts):
            item_box = ctk.CTkFrame(self.facts_list_frame, corner_radius=6, fg_color=("#F3F4F6", "#0F172A"))
            item_box.grid(row=i, column=0, pady=3, sticky="ew")
            item_box.grid_columnconfigure(0, weight=1)

            top = ctk.CTkFrame(item_box, fg_color="transparent")
            top.grid(row=0, column=0, padx=10, pady=(6, 2), sticky="ew")
            top.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                top,
                text=fact.title,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color=("#111827", "#F9FAFB")
            ).grid(row=0, column=0, sticky="w")

            StatusBadge(top, status=fact.status, width=70, height=22).grid(row=0, column=1, sticky="e")

            ctk.CTkLabel(
                item_box,
                text=fact.description,
                font=ctk.CTkFont(size=11),
                text_color=("#4B5563", "#9CA3AF"),
                anchor="w",
                wraplength=380,
                justify="left"
            ).grid(row=1, column=0, padx=10, pady=(0, 6), sticky="w")

        # 3. Render Remediation Plan
        for widget in self.plan_list_frame.winfo_children():
            widget.destroy()

        for j, step in enumerate(result.remediation_steps):
            step_box = ctk.CTkFrame(self.plan_list_frame, corner_radius=6, fg_color=("#F3F4F6", "#0F172A"))
            step_box.grid(row=j, column=0, pady=3, sticky="ew")
            step_box.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                step_box,
                text=step,
                font=ctk.CTkFont(size=12),
                text_color=("#1E293B", "#E2E8F0"),
                anchor="w",
                wraplength=390,
                justify="left"
            ).pack(padx=10, pady=8, fill="x")
