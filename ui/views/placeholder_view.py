"""
Placeholder View Component
Used for upcoming phases before their detailed modules are implemented.
"""

import customtkinter as ctk


class PlaceholderView(ctk.CTkFrame):
    def __init__(self, master, title: str, phase_number: int, description: str, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        container = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        container.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        container.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            container,
            text=f"PHASE {phase_number}: {title.upper()}",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=("#2563EB", "#60A5FA")
        ).pack(pady=(40, 10))

        ctk.CTkLabel(
            container,
            text=description,
            font=ctk.CTkFont(size=14),
            text_color=("#4B5563", "#9CA3AF"),
            wraplength=500
        ).pack(pady=10)

        ctk.CTkLabel(
            container,
            text="Ready to build in subsequent phase.",
            font=ctk.CTkFont(size=12, slant="italic"),
            text_color=("#9CA3AF", "#6B7280")
        ).pack(pady=(20, 40))
