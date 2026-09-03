"""
StatusBadge Component
A polished badge widget displaying PASS, WARNING, FAIL, or PENDING indicators.
"""

import customtkinter as ctk
from typing import Optional


class StatusBadge(ctk.CTkButton):
    """
    Colored badge widget for test status.
    """
    COLORS = {
        "PASS": {"fg": "#059669", "text": "#FFFFFF", "label": "PASS"},
        "WARNING": {"fg": "#D97706", "text": "#FFFFFF", "label": "WARNING"},
        "FAIL": {"fg": "#DC2626", "text": "#FFFFFF", "label": "FAIL"},
        "RUNNING": {"fg": "#2563EB", "text": "#FFFFFF", "label": "TESTING..."},
        "PENDING": {"fg": "#4B5563", "text": "#E5E7EB", "label": "PENDING"},
        "SKIPPED": {"fg": "#374151", "text": "#9CA3AF", "label": "SKIPPED"},
        "INFO": {"fg": "#2563EB", "text": "#FFFFFF", "label": "INFO"},
    }

    def __init__(self, master, status: str = "PENDING", custom_text: Optional[str] = None, width: int = 90, height: int = 26, **kwargs):
        config = self.COLORS.get(status.upper(), self.COLORS["PENDING"])
        display_label = custom_text or config["label"]
        super().__init__(
            master,
            text=display_label,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color=config["fg"],
            text_color=config["text"],
            hover=False,
            width=width,
            height=height,
            corner_radius=6,
            **kwargs
        )
        self.status = status.upper()

    def set_status(self, new_status: str, custom_text: Optional[str] = None):
        """Updates badge status and styling."""
        status_key = new_status.upper()
        config = self.COLORS.get(status_key, self.COLORS["PENDING"])
        self.status = status_key
        self.configure(
            text=custom_text or config["label"],
            fg_color=config["fg"],
            text_color=config["text"]
        )
