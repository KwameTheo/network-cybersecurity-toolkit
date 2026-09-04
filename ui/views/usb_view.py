"""
USB Device History & Forensic Audit View
Audits historical USB storage artifacts from the Windows Registry (USBSTOR),
inspects serial numbers for DLP forensics, and tracks live connected USB peripherals.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.usb_forensics import (
    USBForensicsSummary,
    USBStorageDeviceRecord,
    run_usb_forensic_audit,
)
from ui.components.info_card import InfoCard
from ui.components.status_badge import StatusBadge
from utils.logger import get_logger

logger = get_logger()


class UsbView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.summary: Optional[USBForensicsSummary] = None
        self.storage_devices: List[USBStorageDeviceRecord] = []
        self.peripherals: List[Dict[str, str]] = []
        self.selected_item: Optional[Dict[str, str]] = None
        self.is_scanning = False

        self._create_header()
        self._create_summary_cards()
        self._create_filter_toolbar()
        self._create_table_section()
        self._create_inspector_section()

        # Initial audit
        self.refresh_audit()

    def _create_header(self):
        """Top title and refresh button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="USB Device History & Digital Forensics Audit",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.scan_btn = ctk.CTkButton(
            header_frame,
            text="Scan USB Artifacts",
            width=150,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self.refresh_audit
        )
        self.scan_btn.grid(row=0, column=1, sticky="e")

    def _create_summary_cards(self):
        """4 Overview Stat Cards."""
        cards_frame = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        cards_frame.grid(row=1, column=0, padx=10, pady=(0, 12), sticky="ew")
        cards_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self.card_hist = InfoCard(cards_frame, title="Historical USB Storage", value="0", subtitle="Preserved in USBSTOR")
        self.card_hist.grid(row=0, column=0, padx=(12, 4), pady=12, sticky="ew")

        self.card_live_stor = InfoCard(cards_frame, title="Active USB Drives", value="0", subtitle="Mounted storage")
        self.card_live_stor.grid(row=0, column=1, padx=4, pady=12, sticky="ew")

        self.card_periph = InfoCard(cards_frame, title="Connected Peripherals", value="0", subtitle="Webcams, Hubs, Input")
        self.card_periph.grid(row=0, column=2, padx=4, pady=12, sticky="ew")

        self.card_status = InfoCard(cards_frame, title="Forensic DLP Status", value="INDEXED", subtitle="Registry audited")
        self.card_status.grid(row=0, column=3, padx=(4, 12), pady=12, sticky="ew")

    def _create_filter_toolbar(self):
        """Segmented tabs and search entry."""
        toolbar = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        toolbar.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        toolbar.grid_columnconfigure(1, weight=1)

        self.seg_view = ctk.CTkSegmentedButton(
            toolbar,
            values=["USB Storage History (USBSTOR)", "Live Connected Peripherals (PnP)"],
            command=lambda v: self._apply_filters()
        )
        self.seg_view.set("USB Storage History (USBSTOR)")
        self.seg_view.grid(row=0, column=0, padx=(12, 6), pady=8, sticky="w")

        self.search_entry = ctk.CTkEntry(
            toolbar,
            placeholder_text="Search Device Name, Serial Number, Vendor...",
            width=270,
            height=28
        )
        self.search_entry.grid(row=0, column=1, padx=(6, 12), pady=8, sticky="e")
        self.search_entry.bind("<KeyRelease>", lambda e: self._apply_filters())

    def _create_table_section(self):
        """USB Artifacts Treeview Table."""
        table_container = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        table_container.grid(row=3, column=0, padx=10, pady=(0, 10), sticky="nsew")
        table_container.grid_columnconfigure(0, weight=1)

        tree_box = ctk.CTkFrame(table_container, corner_radius=6, fg_color=("#111827", "#0F172A"))
        tree_box.grid(row=0, column=0, padx=10, pady=(10, 6), sticky="nsew")
        tree_box.grid_columnconfigure(0, weight=1)
        tree_box.grid_rowconfigure(0, weight=1)

        cols = ("cat", "name", "mfg", "serial", "vid_pid")
        self.tree = ttk.Treeview(
            tree_box,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=9
        )

        self.tree.heading("cat", text="Category", anchor="center")
        self.tree.heading("name", text="Device Friendly Name", anchor="w")
        self.tree.heading("mfg", text="Manufacturer / Brand", anchor="w")
        self.tree.heading("serial", text="Hardware Serial / Instance ID", anchor="w")
        self.tree.heading("vid_pid", text="VID / PID", anchor="center")

        self.tree.column("cat", width=120, minwidth=100, anchor="center")
        self.tree.column("name", width=220, minwidth=180, anchor="w")
        self.tree.column("mfg", width=170, minwidth=140, anchor="w")
        self.tree.column("serial", width=220, minwidth=170, anchor="w")
        self.tree.column("vid_pid", width=100, minwidth=80, anchor="center")

        v_scroll = ttk.Scrollbar(tree_box, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=v_scroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scroll.grid(row=0, column=1, sticky="ns")

        self.tree.tag_configure("storage_connected", foreground="#4ADE80")  # Bright green for active connected drives
        self.tree.tag_configure("storage_history", foreground="#93C5FD")    # Soft blue for historical artifacts
        self.tree.tag_configure("pnp", foreground="#38BDF8")

        self.tree.bind("<<TreeviewSelect>>", self._on_device_selected)

        self.count_label = ctk.CTkLabel(
            table_container,
            text="Displaying 0 USB device artifacts",
            font=ctk.CTkFont(size=11),
            text_color=("#6B7280", "#9CA3AF"),
            anchor="w"
        )
        self.count_label.grid(row=1, column=0, padx=14, pady=(0, 8), sticky="w")

    def _create_inspector_section(self):
        """Selected device metadata inspector."""
        self.insp_frame = ctk.CTkFrame(self, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        self.insp_frame.grid(row=4, column=0, padx=10, pady=(0, 10), sticky="ew")
        self.insp_frame.grid_columnconfigure(0, weight=1)

        self.insp_title = ctk.CTkLabel(
            self.insp_frame,
            text="SELECTED USB ARTIFACT: NONE (CLICK A ROW ABOVE)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#2563EB", "#60A5FA"),
            anchor="w"
        )
        self.insp_title.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="w")

        self.insp_details = ctk.CTkLabel(
            self.insp_frame,
            text="Select any USB storage or peripheral record above to view complete serial numbers and registry paths for forensic analysis.",
            font=ctk.CTkFont(size=11),
            text_color=("#4B5563", "#D1D5DB"),
            anchor="w"
        )
        self.insp_details.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")

    def refresh_audit(self):
        """Executes full USB forensics query and updates UI."""
        self.scan_btn.configure(state="disabled", text="Auditing...")

        def worker():
            res = run_usb_forensic_audit()

            def ui_update():
                self.summary = res
                self.storage_devices = res.storage_devices
                self.peripherals = res.connected_peripherals

                self.card_hist.update_content(value=str(res.total_historical_storage_devices), subtitle="Historical in USBSTOR")
                self.card_live_stor.update_content(value=str(res.currently_connected_storage_devices), subtitle="Currently plugged in")
                self.card_periph.update_content(value=str(res.currently_connected_usb_peripherals), subtitle="Active USB class devices")

                self._apply_filters()
                self.scan_btn.configure(state="normal", text="Scan USB Artifacts")

            try:
                self.after(0, ui_update)
            except (RuntimeError, tk.TclError):
                pass

        threading.Thread(target=worker, daemon=True).start()

    def _apply_filters(self):
        mode = self.seg_view.get()
        query = self.search_entry.get().strip().lower()

        for item in self.tree.get_children():
            self.tree.delete(item)

        count = 0
        if "USBSTOR" in mode:
            for s in self.storage_devices:
                if query:
                    match = (
                        query in s.device_name.lower() or
                        query in s.manufacturer.lower() or
                        query in s.serial_number.lower() or
                        query in s.vendor_id.lower() or
                        query in s.product_id.lower()
                    )
                    if not match:
                        continue

                tag = "storage_connected" if s.is_connected else "storage_history"
                cat_label = f"🟢 {s.device_type} (Active)" if s.is_connected else f"{s.device_type} (Historical)"

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        cat_label,
                        s.device_name,
                        s.manufacturer,
                        s.serial_number,
                        f"{s.vendor_id}:{s.product_id}"
                    ),
                    tags=(tag,)
                )
                count += 1
            connected_count = sum(1 for s in self.storage_devices if s.is_connected)
            self.count_label.configure(text=f"Displaying {count} of {len(self.storage_devices)} USB storage artifacts ({connected_count} currently plugged in)")
        else:
            for p in self.peripherals:
                name = p.get("name", "")
                cat = p.get("category", "USB Peripheral")
                mfg = p.get("vendor", "")
                inst = p.get("instance_id", "")
                vid = p.get("vendor_id", "--")
                pid = p.get("product_id", "--")

                if query:
                    match = (
                        query in name.lower() or
                        query in mfg.lower() or
                        query in inst.lower() or
                        query in vid.lower() or
                        query in pid.lower() or
                        query in cat.lower()
                    )
                    if not match:
                        continue

                self.tree.insert(
                    "",
                    "end",
                    values=(
                        cat,
                        name,
                        mfg,
                        inst,
                        f"{vid}:{pid}"
                    ),
                    tags=("pnp",)
                )
                count += 1
            self.count_label.configure(text=f"Displaying {count} of {len(self.peripherals)} live USB class devices (controllers, hubs, storage & peripherals)")

    def _on_device_selected(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if vals:
            cat = vals[0]
            name = vals[1]
            mfg = vals[2]
            serial_or_inst = vals[3]
            vid_pid = vals[4]

            self.insp_title.configure(text=f"USB ARTIFACT: {name}")
            self.insp_details.configure(text=f"• Type / Status: {cat}\n• Serial / Instance: {serial_or_inst}\n• Brand / Manufacturer: {mfg} | Hardware VID:PID: {vid_pid}")
