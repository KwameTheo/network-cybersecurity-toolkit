"""
Certificate of Authenticity & Intellectual Property Dialog
Displays verifiable creator credentials, copyright statements, and cryptographic provenance seals.

Copyright (c) 2026 Kwame_Theo. All Rights Reserved.
"""

import customtkinter as ctk
from core.integrity_guard import get_certificate_of_authenticity, verify_application_integrity


class ProvenanceDialog(ctk.CTkToplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Authenticity & Copyright Certificate")
        self.geometry("560x440")
        self.resizable(False, False)

        # Modal configuration
        self.transient(parent)
        self.grab_set()

        # Center on parent window
        self.update_idletasks()
        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - 280
            y = parent.winfo_y() + (parent.winfo_height() // 2) - 220
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

        self._build_ui()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        cert = get_certificate_of_authenticity()
        integrity = verify_application_integrity()

        container = ctk.CTkFrame(self, corner_radius=0, fg_color=("#F3F4F6", "#0F172A"))
        container.grid(row=0, column=0, sticky="nsew", padx=16, pady=16)
        container.grid_columnconfigure(0, weight=1)

        # Header Badge
        header_frame = ctk.CTkFrame(container, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 8), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="OFFICIAL CERTIFICATE OF AUTHENTICITY",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        status_tag = "VERIFIED GENUINE" if integrity.is_valid else "TAMPER DETECTED"
        status_color = "#10B981" if integrity.is_valid else "#EF4444"
        badge = ctk.CTkLabel(
            header_frame,
            text=f"[{status_tag}]",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=status_color
        )
        badge.grid(row=0, column=1, sticky="e")

        # Content Card
        card = ctk.CTkFrame(container, corner_radius=8, fg_color=("#E5E7EB", "#1E293B"))
        card.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        card.grid_columnconfigure(1, weight=1)

        rows = [
            ("Author & Sole Creator:", cert["author"]),
            ("Legal Copyright:", cert["copyright"]),
            ("Software Product:", f"{cert['product_name']} (v{cert['product_version']})"),
            ("Origin UUID:", cert["origin_uuid"]),
            ("Signature Watermark:", cert["signature_watermark"]),
            ("HMAC-SHA256 Build Seal:", cert["digital_seal_sha256"]),
            ("Legal License Status:", cert["legal_status"]),
        ]

        for i, (k, v) in enumerate(rows):
            ctk.CTkLabel(
                card,
                text=k,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=("#4B5563", "#94A3B8"),
                anchor="w"
            ).grid(row=i, column=0, padx=(12, 8), pady=4, sticky="w")

            val_label = ctk.CTkLabel(
                card,
                text=v,
                font=ctk.CTkFont(size=10, family="Consolas" if ("UUID" in k or "Seal" in k or "Watermark" in k) else "Segoe UI"),
                text_color=("#111827", "#F8FAFC"),
                anchor="w",
                wraplength=340,
                justify="left"
            )
            val_label.grid(row=i, column=1, padx=(0, 12), pady=4, sticky="w")

        # Legal Notice
        notice_label = ctk.CTkLabel(
            container,
            text=cert["ip_protection_notice"],
            font=ctk.CTkFont(size=10, slant="italic"),
            text_color=("#6B7280", "#94A3B8"),
            anchor="w",
            wraplength=500,
            justify="left"
        )
        notice_label.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="w")

        # Close Button
        btn = ctk.CTkButton(
            container,
            text="Close Certificate",
            width=140,
            height=30,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.destroy
        )
        btn.grid(row=3, column=0, padx=10, pady=(0, 6), sticky="e")
