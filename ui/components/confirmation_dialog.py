"""
Confirmation Dialog Component
A safety modal for confirming disruptive network operations (DHCP release/renew, DNS flush).
"""

import customtkinter as ctk
from typing import Callable, Optional


class ConfirmationDialog(ctk.CTkToplevel):
    def __init__(
        self,
        parent,
        title: str,
        message: str,
        warning_detail: str,
        confirm_text: str = "Proceed",
        cancel_text: str = "Cancel",
        on_confirm: Optional[Callable[[], None]] = None,
        is_destructive: bool = False
    ):
        super().__init__(parent)
        self.title(title)
        self.geometry("460x240")
        self.resizable(False, False)

        # Make dialog modal (blocks interaction with parent window)
        self.transient(parent)
        self.grab_set()

        self.on_confirm = on_confirm
        self.result = False

        # Center on parent window
        self.update_idletasks()
        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - 230
            y = parent.winfo_y() + (parent.winfo_height() // 2) - 120
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

        self._build_ui(title, message, warning_detail, confirm_text, cancel_text, is_destructive)

    def _build_ui(
        self,
        title: str,
        message: str,
        warning_detail: str,
        confirm_text: str,
        cancel_text: str,
        is_destructive: bool
    ):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self, corner_radius=0, fg_color=("#F3F4F6", "#1F2937"))
        container.grid(row=0, column=0, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)

        # Title / Warning Header
        header_color = "#DC2626" if is_destructive else "#D97706"
        header = ctk.CTkLabel(
            container,
            text=f"ATTENTION: {title.upper()}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=header_color,
            anchor="w"
        )
        header.grid(row=0, column=0, padx=20, pady=(16, 6), sticky="w")

        # Main Question
        msg_label = ctk.CTkLabel(
            container,
            text=message,
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=("#111827", "#F9FAFB"),
            anchor="w",
            wraplength=410,
            justify="left"
        )
        msg_label.grid(row=1, column=0, padx=20, pady=(0, 6), sticky="w")

        # Warning / Technical Context
        detail_label = ctk.CTkLabel(
            container,
            text=warning_detail,
            font=ctk.CTkFont(size=12),
            text_color=("#4B5563", "#9CA3AF"),
            anchor="w",
            wraplength=410,
            justify="left"
        )
        detail_label.grid(row=2, column=0, padx=20, pady=(0, 16), sticky="w")

        # Action Buttons
        btn_frame = ctk.CTkFrame(container, fg_color="transparent")
        btn_frame.grid(row=3, column=0, padx=20, pady=(0, 16), sticky="e")

        cancel_btn = ctk.CTkButton(
            btn_frame,
            text=cancel_text,
            width=90,
            fg_color="#4B5563",
            hover_color="#6B7280",
            command=self._on_cancel
        )
        cancel_btn.pack(side="left", padx=(0, 10))

        confirm_btn_color = "#DC2626" if is_destructive else "#2563EB"
        confirm_hover = "#B91C1C" if is_destructive else "#1D4ED8"
        confirm_btn = ctk.CTkButton(
            btn_frame,
            text=confirm_text,
            width=110,
            fg_color=confirm_btn_color,
            hover_color=confirm_hover,
            command=self._on_confirm
        )
        confirm_btn.pack(side="left")

    def _on_confirm(self):
        self.result = True
        self.destroy()
        if self.on_confirm:
            self.on_confirm()

    def _on_cancel(self):
        self.result = False
        self.destroy()
