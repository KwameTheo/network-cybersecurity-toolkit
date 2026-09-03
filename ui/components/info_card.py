"""
InfoCard Component
A polished card widget for displaying a single metric or system attribute.
"""

import customtkinter as ctk
from typing import Optional


class InfoCard(ctk.CTkFrame):
    """
    Card displaying a category title, main value, and secondary subtitle/badge.
    """
    def __init__(
        self,
        master,
        title: str,
        value: str = "--",
        subtitle: Optional[str] = None,
        accent_color: Optional[str] = None,
        **kwargs
    ):
        super().__init__(master, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"), **kwargs)

        self.grid_columnconfigure(0, weight=1)

        # Title / Label
        self.title_label = ctk.CTkLabel(
            self,
            text=title.upper(),
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.title_label.grid(row=0, column=0, padx=14, pady=(12, 4), sticky="w")

        # Main Value
        self.value_label = ctk.CTkLabel(
            self,
            text=value,
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=accent_color or ("#111827", "#F9FAFB"),
            anchor="w",
            wraplength=260
        )
        self.value_label.grid(row=1, column=0, padx=14, pady=2, sticky="w")

        # Subtitle / Extra context
        self.subtitle_label = None
        if subtitle:
            self.subtitle_label = ctk.CTkLabel(
                self,
                text=subtitle,
                font=ctk.CTkFont(size=12),
                text_color=("#4B5563", "#9CA3AF"),
                anchor="w"
            )
            self.subtitle_label.grid(row=2, column=0, padx=14, pady=(2, 12), sticky="w")
        else:
            self.value_label.grid_configure(pady=(2, 12))

    def update_content(self, value: str, subtitle: Optional[str] = None, accent_color: Optional[str] = None):
        """Updates the card values dynamically."""
        self.value_label.configure(text=value)
        if accent_color:
            self.value_label.configure(text_color=accent_color)
        if subtitle and self.subtitle_label:
            self.subtitle_label.configure(text=subtitle)
