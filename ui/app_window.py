"""
Main Application Window
Provides the main application shell, sidebar navigation, theme management,
and dynamic view switching.
"""

import customtkinter as ctk
from typing import Dict
from ui.views.assistant_view import AssistantView
from ui.views.dashboard_view import DashboardView
from ui.views.events_view import EventsView
from ui.views.internet_view import InternetView
from ui.views.network_view import NetworkView
from ui.views.ports_view import PortsView
from ui.views.reports_view import ReportsView
from ui.views.security_view import SecurityView
from ui.views.wifi_view import WifiView
from utils.logger import get_logger

logger = get_logger()

# Set global appearance mode and color theme
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class AppWindow(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Network & Cybersecurity IT Support Toolkit")
        self.geometry("1120x740")
        self.minsize(980, 620)

        # Configure 2-column grid: Sidebar (col 0), Content area (col 1)
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.views: Dict[str, ctk.CTkFrame] = {}
        self.nav_buttons: Dict[str, ctk.CTkButton] = {}

        self._create_sidebar()
        self._create_content_area()
        self._init_views()

        # Select Dashboard by default
        self.select_view("dashboard")
        logger.info("Main application window initialized.")

    def _create_sidebar(self):
        """Builds the left navigation sidebar."""
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(9, weight=1)  # Spacer push to bottom

        # App Brand Header
        logo_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="NETSEC TOOLKIT",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=("#2563EB", "#60A5FA")
        )
        logo_label.grid(row=0, column=0, padx=20, pady=(20, 2), sticky="w")

        subtitle_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="IT Diagnostics & Security Suite",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF")
        )
        subtitle_label.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="w")

        # Navigation definitions: (key, label, icon/symbol)
        nav_items = [
            ("dashboard", "Dashboard", 2),
            ("network", "Network Diagnostics", 3),
            ("wifi", "Wi-Fi Analyzer", 4),
            ("ports", "Ports & Connections", 5),
            ("internet", "Internet & DNS Health", 6),
            ("security", "Security Checks", 7),
            ("events", "Event Log Analyzer", 8),
            ("assistant", "Troubleshooting Wizard", 9),
            ("reports", "Generate Reports", 10),
        ]

        for key, label, row_idx in nav_items:
            btn = ctk.CTkButton(
                self.sidebar_frame,
                text=label,
                font=ctk.CTkFont(size=13),
                anchor="w",
                height=36,
                corner_radius=8,
                fg_color="transparent",
                text_color=("#1F2937", "#E5E7EB"),
                hover_color=("#D1D5DB", "#374151"),
                command=lambda k=key: self.select_view(k)
            )
            btn.grid(row=row_idx, column=0, padx=12, pady=4, sticky="ew")
            self.nav_buttons[key] = btn

        # Theme Selector at bottom
        theme_label = ctk.CTkLabel(
            self.sidebar_frame,
            text="Appearance Mode:",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        theme_label.grid(row=10, column=0, padx=20, pady=(10, 2), sticky="w")

        self.theme_menu = ctk.CTkOptionMenu(
            self.sidebar_frame,
            values=["Dark", "Light", "System"],
            command=self._change_appearance_mode,
            height=28
        )
        self.theme_menu.set("Dark")
        self.theme_menu.grid(row=11, column=0, padx=20, pady=(0, 16), sticky="ew")

    def _create_content_area(self):
        """Creates container frame for dynamic view switching."""
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=0, column=1, padx=15, pady=15, sticky="nsew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

    def _init_views(self):
        """Instantiates all application views and places them in the container."""
        # Phase 2: Complete Dashboard
        self.views["dashboard"] = DashboardView(self.content_frame)

        # Phase 3: Complete Network Diagnostics
        self.views["network"] = NetworkView(self.content_frame)

        # Advanced Feature 1: Wi-Fi Signal & Channel Analyzer
        self.views["wifi"] = WifiView(self.content_frame)

        # Phase 4: Complete Ports & Connections
        self.views["ports"] = PortsView(self.content_frame)

        # Phase 5: Complete Internet & DNS Health
        self.views["internet"] = InternetView(self.content_frame)

        # Phase 6: Complete Event Log Analyzer
        self.views["events"] = EventsView(self.content_frame)

        # Phase 7: Complete Security Checks
        self.views["security"] = SecurityView(self.content_frame)

        # Phase 8: Complete Troubleshooting Assistant
        self.views["assistant"] = AssistantView(self.content_frame)

        # Phase 9: Complete Report Generator & Database
        self.views["reports"] = ReportsView(self.content_frame)

        for view in self.views.values():
            view.grid(row=0, column=0, sticky="nsew")
            view.grid_remove()  # Hide until activated

    def select_view(self, view_key: str):
        """Switches the visible view and highlights the active sidebar button."""
        if view_key not in self.views:
            return

        # Update button highlights
        for key, btn in self.nav_buttons.items():
            if key == view_key:
                btn.configure(fg_color=("#2563EB", "#1D4ED8"), text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=("#1F2937", "#E5E7EB"))

        # Hide all views and reveal selected
        for key, view in self.views.items():
            if key == view_key:
                view.grid()
            else:
                view.grid_remove()

        logger.debug(f"Switched view to: {view_key}")

    def _change_appearance_mode(self, new_mode: str):
        ctk.set_appearance_mode(new_mode)
