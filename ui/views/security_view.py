"""
Security Checks View
Displays host defensive posture baseline audit, compliance score,
remediation recommendations, and individual security control cards.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.security_checks import SecurityAuditReport, SecurityCheckItem, run_security_audit
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class SecurityCheckCard(ctk.CTkFrame):
    """
    Card displaying a single security check, finding details, and remediation steps.
    """
    def __init__(self, master, check: SecurityCheckItem, **kwargs):
        super().__init__(master, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"), **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.check_id = check.check_id
        self.category = check.category
        self.verdict = check.verdict

        # Row 0: Category & Name + Status Badge
        top_row = ctk.CTkFrame(self, fg_color="transparent")
        top_row.grid(row=0, column=0, columnspan=2, padx=14, pady=(12, 4), sticky="ew")
        top_row.grid_columnconfigure(0, weight=1)

        title_box = ctk.CTkFrame(top_row, fg_color="transparent")
        title_box.grid(row=0, column=0, sticky="w")

        cat_badge = ctk.CTkLabel(
            title_box,
            text=check.category.upper(),
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=("#2563EB", "#60A5FA")
        )
        cat_badge.grid(row=0, column=0, sticky="w")

        self.title_label = ctk.CTkLabel(
            title_box,
            text=check.name,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#111827", "#F9FAFB")
        )
        self.title_label.grid(row=1, column=0, pady=(1, 0), sticky="w")

        self.badge = StatusBadge(top_row, status=check.verdict)
        self.badge.grid(row=0, column=1, sticky="e")

        # Row 1: Summary line
        self.summary_label = ctk.CTkLabel(
            self,
            text=check.summary,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#374151", "#E5E7EB"),
            anchor="w",
            wraplength=600,
            justify="left"
        )
        self.summary_label.grid(row=1, column=0, columnspan=2, padx=14, pady=(0, 4), sticky="w")

        # Row 2: Technical details
        self.details_label = ctk.CTkLabel(
            self,
            text=check.details,
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w",
            wraplength=600,
            justify="left"
        )
        self.details_label.grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 10), sticky="w")

        # Row 3: Remediation advice (if check is WARNING or FAIL)
        if check.remediation:
            rem_frame = ctk.CTkFrame(self, corner_radius=6, fg_color=("#FEE2E2", "#3B1219") if check.verdict == "FAIL" else ("#FEF3C7", "#3B2807"))
            rem_frame.grid(row=3, column=0, columnspan=2, padx=14, pady=(0, 12), sticky="ew")
            rem_frame.grid_columnconfigure(0, weight=1)

            rem_title = "ACTION REQUIRED" if check.verdict == "FAIL" else "RECOMMENDATION"
            rem_color = "#DC2626" if check.verdict == "FAIL" else "#D97706"

            ctk.CTkLabel(
                rem_frame,
                text=f"{rem_title}:",
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=rem_color,
                anchor="w"
            ).grid(row=0, column=0, padx=10, pady=(6, 2), sticky="w")

            ctk.CTkLabel(
                rem_frame,
                text=check.remediation,
                font=ctk.CTkFont(size=11),
                text_color=("#7F1D1D", "#FCA5A5") if check.verdict == "FAIL" else ("#78350F", "#FCD34D"),
                anchor="w",
                wraplength=580,
                justify="left"
            ).grid(row=1, column=0, padx=10, pady=(0, 8), sticky="w")


class SecurityView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.all_cards: List[SecurityCheckCard] = []
        self.is_running = False

        self._create_header()
        self._create_posture_banner()
        self._create_filter_bar()
        self._create_cards_container()

    def _create_header(self):
        """Top title and audit button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Host Security Baseline & Defensive Audit",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.audit_btn = ctk.CTkButton(
            header_frame,
            text="Run Security Audit",
            width=160,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.run_audit
        )
        self.audit_btn.grid(row=0, column=1, sticky="e")

    def _create_posture_banner(self):
        """Top security posture summary and score banner."""
        self.banner = ctk.CTkFrame(self, corner_radius=12, fg_color=("#DBEAFE", "#1E3A8A"))
        self.banner.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="ew")
        self.banner.grid_columnconfigure(0, weight=1)
        self.banner.grid_columnconfigure(1, weight=0)

        left_box = ctk.CTkFrame(self.banner, fg_color="transparent")
        left_box.grid(row=0, column=0, padx=16, pady=14, sticky="w")

        self.banner_title = ctk.CTkLabel(
            left_box,
            text="SECURITY POSTURE: READY TO AUDIT",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        self.banner_title.grid(row=0, column=0, sticky="w")

        self.banner_desc = ctk.CTkLabel(
            left_box,
            text="Click 'Run Security Audit' to check Firewall profiles, Antivirus, UAC, Admin accounts, SMBv1, and RDP.",
            font=ctk.CTkFont(size=12),
            text_color=("#1E3A8A", "#BFDBFE"),
            anchor="w",
            wraplength=550,
            justify="left"
        )
        self.banner_desc.grid(row=1, column=0, pady=(2, 0), sticky="w")

        # Right score badge
        self.posture_badge = StatusBadge(self.banner, status="INFO", custom_text="READY", width=130, height=34)
        self.posture_badge.grid(row=0, column=1, padx=16, pady=14, sticky="e")

    def _create_filter_bar(self):
        """Filter segment bar."""
        filter_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        filter_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        filter_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(filter_frame, text="Filter Checks:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(12, 6), pady=8, sticky="w")

        self.filter_menu = ctk.CTkSegmentedButton(
            filter_frame,
            values=["All Checks", "Warnings / Failures", "Network Defense", "Access Control", "Protocol Hardening"],
            command=self._apply_filter
        )
        self.filter_menu.set("All Checks")
        self.filter_menu.grid(row=0, column=1, padx=(6, 12), pady=8, sticky="ew")

    def _create_cards_container(self):
        """Container for dynamic security check cards."""
        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.cards_frame.grid_columnconfigure(0, weight=1)

    def run_audit(self):
        """Runs the defensive security audit in background thread."""
        if self.is_running:
            return

        self.is_running = True
        self.audit_btn.configure(state="disabled", text="Auditing...")
        self.posture_badge.set_status("RUNNING", custom_text="AUDITING...")
        self.banner_title.configure(text="SECURITY POSTURE: AUDITING HOST DEFENSES...")

        def worker():
            report = run_security_audit()
            try:
                self.after(0, lambda: self._apply_report(report))
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_report(self, report: SecurityAuditReport):
        self.is_running = False
        self.audit_btn.configure(state="normal", text="Run Security Audit")

        # Update Banner
        if report.overall_posture == "SECURE":
            self.posture_badge.set_status("PASS", custom_text=f"SECURE ({report.score_percent}%)")
            self.banner.configure(fg_color=("#DCFCE7", "#064E3B"))
            self.banner_title.configure(
                text=f"POSTURE: SECURE BASELINE ({report.passed_count}/{report.total_checks} PASSED)",
                text_color=("#166534", "#6EE7B7")
            )
        elif report.overall_posture == "NEEDS_ATTENTION":
            self.posture_badge.set_status("WARNING", custom_text=f"WARNING ({report.score_percent}%)")
            self.banner.configure(fg_color=("#FEF3C7", "#78350F"))
            self.banner_title.configure(
                text=f"POSTURE: NEEDS ATTENTION ({report.warning_count} Warnings)",
                text_color=("#92400E", "#FCD34D")
            )
        else:
            self.posture_badge.set_status("FAIL", custom_text=f"AT RISK ({report.score_percent}%)")
            self.banner.configure(fg_color=("#FEE2E2", "#7F1D1D"))
            self.banner_title.configure(
                text=f"POSTURE: AT RISK ({report.failed_count} Critical Failures)",
                text_color=("#991B1B", "#FCA5A5")
            )

        self.banner_desc.configure(
            text=f"{report.summary_verdict}\nDefensive Score: {report.score_percent}% | Passed: {report.passed_count} | Warnings: {report.warning_count} | Failures: {report.failed_count}"
        )

        # Build cards
        for widget in self.cards_frame.winfo_children():
            widget.destroy()

        self.all_cards = []
        for i, check in enumerate(report.checks):
            card = SecurityCheckCard(self.cards_frame, check=check)
            card.grid(row=i, column=0, pady=4, sticky="ew")
            self.all_cards.append(card)

        self._apply_filter(self.filter_menu.get())

    def _apply_filter(self, choice: str):
        for card in self.all_cards:
            if choice == "All Checks":
                card.grid()
            elif choice == "Warnings / Failures":
                if card.verdict in ["WARNING", "FAIL"]:
                    card.grid()
                else:
                    card.grid_remove()
            elif choice == card.category:
                card.grid()
            else:
                card.grid_remove()
