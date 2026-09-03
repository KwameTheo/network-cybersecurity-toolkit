"""
LogConsole Component
A sleek, monospaced terminal/console widget for displaying live command output
with Copy and Clear capabilities.
"""

import customtkinter as ctk
import tkinter.messagebox as messagebox


class LogConsole(ctk.CTkFrame):
    """
    Terminal output widget with auto-scroll and toolbar.
    """
    def __init__(self, master, title: str = "COMMAND OUTPUT", height: int = 220, **kwargs):
        super().__init__(master, corner_radius=10, fg_color=("#111827", "#0F172A"), **kwargs)

        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(1, weight=1)

        # Header toolbar
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, columnspan=2, padx=12, pady=(8, 4), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        self.title_label = ctk.CTkLabel(
            header_frame,
            text=f"TERMINAL // {title.upper()}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color="#94A3B8",
            anchor="w"
        )
        self.title_label.grid(row=0, column=0, sticky="w")

        btn_box = ctk.CTkFrame(header_frame, fg_color="transparent")
        btn_box.grid(row=0, column=1, sticky="e")

        self.copy_btn = ctk.CTkButton(
            btn_box,
            text="Copy",
            width=60,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            command=self.copy_to_clipboard
        )
        self.copy_btn.pack(side="left", padx=4)

        self.clear_btn = ctk.CTkButton(
            btn_box,
            text="Clear",
            width=60,
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#334155",
            hover_color="#475569",
            command=self.clear
        )
        self.clear_btn.pack(side="left", padx=4)

        # Monospaced Textbox
        self.textbox = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#E2E8F0",
            fg_color="#090D16",
            corner_radius=6,
            height=height,
            wrap="word"
        )
        self.textbox.grid(row=1, column=0, columnspan=2, padx=10, pady=(0, 10), sticky="nsew")

    def append_text(self, text: str):
        """Appends text to the terminal and automatically scrolls to the bottom."""
        self.textbox.insert("end", text)
        self.textbox.see("end")

    def set_text(self, text: str):
        """Replaces the entire console text."""
        self.clear()
        self.append_text(text)

    def clear(self):
        """Clears all text from the console."""
        self.textbox.delete("1.0", "end")

    def get_text(self) -> str:
        """Returns all text currently in the console."""
        return self.textbox.get("1.0", "end-1c")

    def copy_to_clipboard(self):
        """Copies console contents to Windows clipboard."""
        text = self.get_text().strip()
        if text:
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()
            # Brief visual feedback
            self.copy_btn.configure(text="Copied!", fg_color="#059669")
            self.after(1500, lambda: self.copy_btn.configure(text="Copy", fg_color="#334155"))
