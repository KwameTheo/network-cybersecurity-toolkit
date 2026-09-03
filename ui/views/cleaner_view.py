"""
System Cleanup & Disk Space Triage View
Analyzes disk partition capacity, calculates reclaimable waste in temporary caches,
and provides safe, selective 1-click cleanup with confirmation dialogs.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.system_cleaner import (
    CleanupCategoryInfo,
    CleanupExecutionResult,
    DiskSpaceSummary,
    analyze_disk_space,
    execute_disk_cleanup,
)
from ui.components.confirmation_dialog import ConfirmationDialog
from ui.components.info_card import InfoCard
from ui.components.log_console import LogConsole
from utils.logger import get_logger

logger = get_logger()


class CleanerView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.summary: Optional[DiskSpaceSummary] = None
        self.checkboxes: Dict[str, ctk.CTkCheckBox] = {}
        self.card_widgets: Dict[str, InfoCard] = {}
        self.is_cleaning = False

        self._create_header()
        self._create_drive_gauge_section()
        self._create_categories_section()
        self._create_console_section()

        # Initial analysis load
        self.run_analysis()

    def _create_header(self):
        """Top title and action toolbar."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="System Cleanup & Disk Space Triage",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        self.analyze_btn = ctk.CTkButton(
            btn_box,
            text="Analyze Disk Waste",
            width=150,
            fg_color="#374151",
            hover_color="#4B5563",
            command=self.run_analysis
        )
        self.analyze_btn.pack(side="left", padx=(0, 6))

        self.clean_btn = ctk.CTkButton(
            btn_box,
            text="Clean Selected Junk",
            width=160,
            fg_color="#059669",
            hover_color="#047857",
            command=self._confirm_cleanup
        )
        self.clean_btn.pack(side="left")

    def _create_drive_gauge_section(self):
        """Drive C: capacity bar and storage overview."""
        gauge_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        gauge_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        gauge_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        # Title and reclaimable banner
        top_bar = ctk.CTkFrame(gauge_frame, fg_color="transparent")
        top_bar.grid(row=0, column=0, columnspan=4, padx=14, pady=(12, 6), sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        self.drive_title_label = ctk.CTkLabel(
            top_bar,
            text="SYSTEM DRIVE (C:) STORAGE CAPACITY",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#1E40AF", "#60A5FA"),
            anchor="w"
        )
        self.drive_title_label.grid(row=0, column=0, sticky="w")

        self.reclaimable_label = ctk.CTkLabel(
            top_bar,
            text="Reclaimable Waste: Calculating...",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#10B981",
            anchor="e"
        )
        self.reclaimable_label.grid(row=0, column=1, sticky="e")

        # Capacity Progress Bar
        self.drive_bar = ctk.CTkProgressBar(gauge_frame, height=12, corner_radius=6)
        self.drive_bar.set(0.0)
        self.drive_bar.grid(row=1, column=0, columnspan=4, padx=14, pady=(0, 12), sticky="ew")

        # 4 Stat Cards
        self.card_total_space = InfoCard(gauge_frame, title="Total Disk Capacity", value="--", subtitle="Drive C:")
        self.card_total_space.grid(row=2, column=0, padx=(12, 4), pady=(0, 12), sticky="ew")

        self.card_used_space = InfoCard(gauge_frame, title="Used Space", value="--", subtitle="Installed & data")
        self.card_used_space.grid(row=2, column=1, padx=4, pady=(0, 12), sticky="ew")

        self.card_free_space = InfoCard(gauge_frame, title="Free Space Available", value="--", subtitle="Available storage")
        self.card_free_space.grid(row=2, column=2, padx=4, pady=(0, 12), sticky="ew")

        self.card_waste = InfoCard(gauge_frame, title="Reclaimable Cache", value="--", subtitle="Safe to clean")
        self.card_waste.grid(row=2, column=3, padx=(4, 12), pady=(0, 12), sticky="ew")

    def _create_categories_section(self):
        """Cleanup categories with checkboxes and size badges."""
        cat_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cat_frame.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="ew")
        cat_frame.grid_columnconfigure((0, 1, 2), weight=1)

        ctk.CTkLabel(
            cat_frame,
            text="SELECT RECLAIMABLE JUNK CATEGORIES TO PRUNE",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        ).grid(row=0, column=0, columnspan=3, padx=14, pady=(12, 6), sticky="w")

        # Define 6 Category Slots
        cat_keys = [
            ("user_temp", "User Temp Files", "Installer & scratch files", 1, 0),
            ("system_temp", "Windows System Temp", "OS background temp files", 1, 1),
            ("win_update_cache", "Windows Update Cache", "Downloaded patch files", 1, 2),
            ("crash_dumps", "WER Crash Dumps", "Memory crash minidumps", 2, 0),
            ("user_crash_dumps", "User App Crash Dumps", "Application crash logs", 2, 1),
            ("thumbnail_cache", "Explorer Thumbnails", "Cached preview database", 2, 2),
        ]

        for key, name, subtitle, r, c in cat_keys:
            box = ctk.CTkFrame(cat_frame, corner_radius=8, fg_color=("#F3F4F6", "#111827"))
            box.grid(row=r, column=c, padx=6, pady=6, sticky="ew")
            box.grid_columnconfigure(0, weight=1)

            chk = ctk.CTkCheckBox(box, text=name, font=ctk.CTkFont(size=12, weight="bold"), onvalue=True, offvalue=False)
            chk.select()
            chk.grid(row=0, column=0, padx=10, pady=(8, 2), sticky="w")
            self.checkboxes[key] = chk

            lbl = ctk.CTkLabel(box, text="-- MB (0 files)", font=ctk.CTkFont(size=11), text_color=("#059669", "#34D399"), anchor="w")
            lbl.grid(row=1, column=0, padx=10, pady=(0, 8), sticky="w")
            self.card_widgets[key] = lbl

    def _create_console_section(self):
        """Cleanup logs output console."""
        self.console = LogConsole(self, title="CLEANUP & PRUNING LOG CONSOLE", height=150)
        self.console.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="ew")

    def run_analysis(self):
        """Calculates disk waste and updates all UI gauges."""
        self.analyze_btn.configure(state="disabled", text="Analyzing...")
        self.console.set_text("[*] Analyzing Drive C: capacity and calculating temporary file waste across all categories...\n")

        try:
            summary = analyze_disk_space()
            self._apply_summary(summary)
        except Exception as e:
            logger.error(f"Error in disk analysis: {e}", exc_info=True)
        finally:
            try:
                self.analyze_btn.configure(state="normal", text="Analyze Disk Waste")
            except Exception:
                pass

    def _apply_summary(self, summary: DiskSpaceSummary):
        self.summary = summary

        # 1. Update Drive Gauge
        pct = summary.percent_used
        self.drive_title_label.configure(text=f"SYSTEM DRIVE (C:) CAPACITY — {pct:.1f}% USED")
        self.reclaimable_label.configure(text=f"Reclaimable Waste: {summary.total_reclaimable_mb:.1f} MB ({summary.total_reclaimable_gb:.2f} GB)")

        self.drive_bar.set(min(1.0, max(0.0, pct / 100.0)))
        if pct > 90:
            self.drive_bar.configure(progress_color="#EF4444")
        elif pct > 75:
            self.drive_bar.configure(progress_color="#F59E0B")
        else:
            self.drive_bar.configure(progress_color="#3B82F6")

        self.card_total_space.update_content(value=f"{summary.total_gb:.1f} GB", subtitle="Drive C: Total")
        self.card_used_space.update_content(value=f"{summary.used_gb:.1f} GB", subtitle=f"{pct:.1f}% Used")
        self.card_free_space.update_content(value=f"{summary.free_gb:.1f} GB", subtitle="Available Space")
        self.card_waste.update_content(value=f"{summary.total_reclaimable_mb:.1f} MB", subtitle=f"{summary.total_reclaimable_gb:.2f} GB Reclaimable")

        # 2. Update Category Badges
        cat_map = {c.key: c for c in summary.categories}
        for key, lbl in self.card_widgets.items():
            if key in cat_map:
                c = cat_map[key]
                lbl.configure(text=f"{c.total_mb:.2f} MB ({c.file_count:,} files)")

        # Log summary
        lines = [
            f"[+] Disk Analysis Complete:",
            f"    - Drive C: Capacity: {summary.total_gb:.1f} GB (Used: {summary.used_gb:.1f} GB, Free: {summary.free_gb:.1f} GB)",
            f"    - Total Reclaimable Waste: {summary.total_reclaimable_mb:.2f} MB ({summary.total_reclaimable_gb:.2f} GB)",
            f"    - Ready to prune! Select categories above and click 'Clean Selected Junk'."
        ]
        self.console.set_text("\n".join(lines) + "\n")

    def _confirm_cleanup(self):
        selected_keys = [k for k, chk in self.checkboxes.items() if chk.get()]
        if not selected_keys:
            self.console.set_text("[!] No categories selected for cleanup. Check at least one box above.\n")
            return

        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title="Clean System Junk",
            message=f"Prune temporary files across {len(selected_keys)} selected categories?",
            warning_detail="This will delete obsolete temporary files, update download caches, and crash dumps. Active locked files will be skipped safely.",
            confirm_text="Prune Junk Files",
            on_confirm=lambda: self._execute_cleanup(selected_keys)
        )

    def _execute_cleanup(self, selected_keys: List[str]):
        if self.is_cleaning:
            return

        self.is_cleaning = True
        self.clean_btn.configure(state="disabled", text="Pruning Files...")
        self.console.set_text("[*] Executing safe system disk cleanup...\n")

        def worker():
            res = execute_disk_cleanup(selected_keys)

            def ui_update():
                self.console.set_text("\n".join(res.logs) + "\n")
                self.clean_btn.configure(state="normal", text="Clean Selected Junk")
                self.is_cleaning = False
                self.run_analysis()

            try:
                self.after(0, ui_update)
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()
