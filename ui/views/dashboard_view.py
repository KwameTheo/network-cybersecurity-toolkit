"""
Dashboard View
Displays host specifications, hardware utilization, privilege status, and system uptime.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from core.system_info import SystemInfo, collect_system_info
from ui.components.info_card import InfoCard
from utils.logger import get_logger

logger = get_logger()


class DashboardView(ctk.CTkScrollableFrame):
    """
    Main system dashboard view presenting hardware, OS, and status metrics.
    """
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # Build UI layout
        self._create_header()
        self._create_banner()
        self._create_utilization_section()
        self._create_specs_grid()

        # Load initial data in background thread
        self.refresh_data()

    def _create_header(self):
        """Creates top title and refresh button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 15), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="System Overview & Host Diagnostics",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.refresh_btn = ctk.CTkButton(
            header_frame,
            text="Refresh System Info",
            width=150,
            command=self.refresh_data
        )
        self.refresh_btn.grid(row=0, column=1, sticky="e")

    def _create_banner(self):
        """Creates the hero status banner with host name and privilege level."""
        self.banner_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#DBEAFE", "#1E3A8A"))
        self.banner_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 15), sticky="ew")
        self.banner_frame.grid_columnconfigure(0, weight=1)
        self.banner_frame.grid_columnconfigure(1, weight=0)

        # Left info inside banner
        banner_left = ctk.CTkFrame(self.banner_frame, fg_color="transparent")
        banner_left.grid(row=0, column=0, padx=16, pady=14, sticky="w")

        self.host_label = ctk.CTkLabel(
            banner_left,
            text="HOST: Loading...",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#1E40AF", "#93C5FD"),
            anchor="w"
        )
        self.host_label.grid(row=0, column=0, sticky="w")

        self.user_os_label = ctk.CTkLabel(
            banner_left,
            text="User: -- | OS: --",
            font=ctk.CTkFont(size=13),
            text_color=("#1E3A8A", "#BFDBFE"),
            anchor="w"
        )
        self.user_os_label.grid(row=1, column=0, pady=(2, 0), sticky="w")

        # Right privilege badge inside banner
        self.badge_btn = ctk.CTkButton(
            self.banner_frame,
            text="Checking Privileges...",
            font=ctk.CTkFont(size=12, weight="bold"),
            fg_color="#4B5563",
            hover=False,
            height=32,
            corner_radius=8
        )
        self.badge_btn.grid(row=0, column=1, padx=16, pady=14, sticky="e")

    def _create_utilization_section(self):
        """Creates live utilization gauges for CPU and RAM."""
        util_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        util_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=(0, 15), sticky="ew")
        util_frame.grid_columnconfigure(0, weight=1)
        util_frame.grid_columnconfigure(1, weight=1)

        # Section Header
        util_title = ctk.CTkLabel(
            util_frame,
            text="RESOURCE UTILIZATION",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        )
        util_title.grid(row=0, column=0, columnspan=2, padx=16, pady=(12, 8), sticky="w")

        # CPU Utilization
        cpu_box = ctk.CTkFrame(util_frame, fg_color="transparent")
        cpu_box.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="ew")
        cpu_box.grid_columnconfigure(0, weight=1)

        self.cpu_util_label = ctk.CTkLabel(
            cpu_box,
            text="CPU Usage: --%",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        self.cpu_util_label.grid(row=0, column=0, sticky="w")

        self.cpu_bar = ctk.CTkProgressBar(cpu_box, height=12, corner_radius=6)
        self.cpu_bar.set(0.0)
        self.cpu_bar.grid(row=1, column=0, pady=(6, 0), sticky="ew")

        # RAM Utilization
        ram_box = ctk.CTkFrame(util_frame, fg_color="transparent")
        ram_box.grid(row=1, column=1, padx=16, pady=(0, 16), sticky="ew")
        ram_box.grid_columnconfigure(0, weight=1)

        self.ram_util_label = ctk.CTkLabel(
            ram_box,
            text="RAM Usage: --% (-- / -- GB)",
            font=ctk.CTkFont(size=14, weight="bold"),
            anchor="w"
        )
        self.ram_util_label.grid(row=0, column=0, sticky="w")

        self.ram_bar = ctk.CTkProgressBar(ram_box, height=12, corner_radius=6)
        self.ram_bar.set(0.0)
        self.ram_bar.grid(row=1, column=0, pady=(6, 0), sticky="ew")

    def _create_specs_grid(self):
        """Creates detailed metric cards in a 2-column grid."""
        self.card_edition = InfoCard(self, title="Windows Edition", value="--", subtitle="Edition & build info")
        self.card_edition.grid(row=3, column=0, padx=(10, 5), pady=5, sticky="ew")

        self.card_cpu = InfoCard(self, title="Processor (CPU)", value="--", subtitle="Cores & threads")
        self.card_cpu.grid(row=3, column=1, padx=(5, 10), pady=5, sticky="ew")

        self.card_ram = InfoCard(self, title="System Memory (RAM)", value="--", subtitle="Physical memory available")
        self.card_ram.grid(row=4, column=0, padx=(10, 5), pady=5, sticky="ew")

        self.card_arch = InfoCard(self, title="System Architecture", value="--", subtitle="Platform architecture")
        self.card_arch.grid(row=4, column=1, padx=(5, 10), pady=5, sticky="ew")

        self.card_uptime = InfoCard(self, title="System Uptime", value="--", subtitle="Time since last boot")
        self.card_uptime.grid(row=5, column=0, padx=(10, 5), pady=5, sticky="ew")

        self.card_python = InfoCard(self, title="Python Runtime", value="--", subtitle="Interpreter version")
        self.card_python.grid(row=5, column=1, padx=(5, 10), pady=5, sticky="ew")

    def refresh_data(self):
        """Triggers data collection in a background thread to prevent UI freezing."""
        self.refresh_btn.configure(state="disabled", text="Refreshing...")

        def worker():
            try:
                info = collect_system_info()
                try:
                    self.after(0, lambda: self._apply_data(info))
                except (RuntimeError, tk.TclError):
                    pass
            except Exception as e:
                logger.error(f"Error in Dashboard refresh: {e}", exc_info=True)
                try:
                    self.after(0, lambda: self.refresh_btn.configure(state="normal", text="Refresh System Info"))
                except (RuntimeError, tk.TclError):
                    pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_data(self, info: SystemInfo):
        """Applies collected SystemInfo dataclass to GUI widgets."""
        # Banner updates
        self.host_label.configure(text=f"HOST: {info.computer_name}")
        self.user_os_label.configure(text=f"User: {info.username}  |  OS: {info.os_edition}")

        if info.is_admin:
            self.badge_btn.configure(
                text="ADMINISTRATOR (ELEVATED)",
                fg_color="#059669",
                hover_color="#059669"
            )
        else:
            self.badge_btn.configure(
                text="STANDARD USER",
                fg_color="#D97706",
                hover_color="#D97706"
            )

        # Live Gauges
        cpu_val = info.cpu_usage_percent
        self.cpu_util_label.configure(text=f"CPU Usage: {cpu_val:.1f}%")
        self.cpu_bar.set(min(1.0, max(0.0, cpu_val / 100.0)))
        if cpu_val > 85:
            self.cpu_bar.configure(progress_color="#EF4444")
        elif cpu_val > 60:
            self.cpu_bar.configure(progress_color="#F59E0B")
        else:
            self.cpu_bar.configure(progress_color="#3B82F6")

        ram_val = info.ram_usage_percent
        self.ram_util_label.configure(
            text=f"RAM Usage: {ram_val:.1f}% ({info.ram_used_gb:.1f} / {info.ram_total_gb:.1f} GB)"
        )
        self.ram_bar.set(min(1.0, max(0.0, ram_val / 100.0)))
        if ram_val > 85:
            self.ram_bar.configure(progress_color="#EF4444")
        elif ram_val > 60:
            self.ram_bar.configure(progress_color="#F59E0B")
        else:
            self.ram_bar.configure(progress_color="#10B981")

        # Cards
        self.card_edition.update_content(
            value=info.os_edition,
            subtitle=f"Build: {info.os_build}"
        )
        self.card_cpu.update_content(
            value=info.cpu_model,
            subtitle=f"{info.cpu_physical_cores} Physical Cores / {info.cpu_logical_cores} Logical Threads"
        )
        self.card_ram.update_content(
            value=f"{info.ram_total_gb:.1f} GB Total",
            subtitle=f"{info.ram_available_gb:.1f} GB Available ({100 - info.ram_usage_percent:.1f}% free)"
        )
        self.card_arch.update_content(
            value=info.architecture,
            subtitle=f"OS Platform: {info.os_name}"
        )
        self.card_uptime.update_content(
            value=info.uptime_formatted,
            subtitle=f"Boot: {info.boot_time}"
        )
        self.card_python.update_content(
            value=f"Python {info.python_version}",
            subtitle="Virtual Environment Active"
        )

        self.refresh_btn.configure(state="normal", text="Refresh System Info")
