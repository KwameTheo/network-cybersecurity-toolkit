"""
Network Diagnostics View
Provides adapter inspection, Ping, Traceroute, DNS lookup, and safe DHCP/DNS cache controls.
"""

import threading
import tkinter as tk
import customtkinter as ctk
from typing import Dict, List, Optional

from core.network_diagnostics import (
    NetworkAdapter,
    dns_lookup,
    flush_dns_cache,
    get_network_adapters,
    get_primary_adapter,
    ping_target,
    release_dhcp_lease,
    renew_dhcp_lease,
    traceroute_target,
)
from ui.components.confirmation_dialog import ConfirmationDialog
from ui.components.info_card import InfoCard
from ui.components.log_console import LogConsole
from utils.logger import get_logger

logger = get_logger()


class NetworkView(ctk.CTkScrollableFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self.grid_columnconfigure(0, weight=1)

        self.adapters: List[NetworkAdapter] = []
        self.selected_adapter: Optional[NetworkAdapter] = None

        self._create_header()
        self._create_adapter_section()
        self._create_tools_tabview()

        # Load adapters on startup
        self.refresh_adapters()

    def _create_header(self):
        """Creates top title and refresh button."""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        header_frame.grid_columnconfigure(0, weight=1)

        title_label = ctk.CTkLabel(
            header_frame,
            text="Network Diagnostics & Connectivity Tools",
            font=ctk.CTkFont(size=22, weight="bold"),
            anchor="w"
        )
        title_label.grid(row=0, column=0, sticky="w")

        self.refresh_adp_btn = ctk.CTkButton(
            header_frame,
            text="Refresh Adapters",
            width=140,
            command=self.refresh_adapters
        )
        self.refresh_adp_btn.grid(row=0, column=1, sticky="e")

    def _create_adapter_section(self):
        """Creates adapter selection dropdown and status cards."""
        adp_container = ctk.CTkFrame(self, corner_radius=12, fg_color=("#E5E7EB", "#1F2937"))
        adp_container.grid(row=1, column=0, padx=10, pady=(0, 15), sticky="ew")
        adp_container.grid_columnconfigure(0, weight=1)
        adp_container.grid_columnconfigure(1, weight=1)
        adp_container.grid_columnconfigure(2, weight=1)

        # Dropdown selection bar
        top_bar = ctk.CTkFrame(adp_container, fg_color="transparent")
        top_bar.grid(row=0, column=0, columnspan=3, padx=14, pady=(12, 10), sticky="ew")
        top_bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top_bar,
            text="Select Network Interface:",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=("#6B7280", "#9CA3AF")
        ).grid(row=0, column=0, padx=(0, 10), sticky="w")

        self.adapter_menu = ctk.CTkOptionMenu(
            top_bar,
            values=["Scanning adapters..."],
            command=self._on_adapter_selected,
            height=30
        )
        self.adapter_menu.grid(row=0, column=1, sticky="ew")

        # Cards Grid: row 1 and row 2
        self.card_ipv4 = InfoCard(adp_container, title="IPv4 Address", value="--", subtitle="Subnet: --")
        self.card_ipv4.grid(row=1, column=0, padx=(12, 6), pady=6, sticky="ew")

        self.card_gateway = InfoCard(adp_container, title="Default Gateway", value="--", subtitle="Router IP")
        self.card_gateway.grid(row=1, column=1, padx=6, pady=6, sticky="ew")

        self.card_dns = InfoCard(adp_container, title="DNS Servers", value="--", subtitle="Resolver addresses")
        self.card_dns.grid(row=1, column=2, padx=(6, 12), pady=6, sticky="ew")

        self.card_mac = InfoCard(adp_container, title="MAC Address", value="--", subtitle="Physical hardware address")
        self.card_mac.grid(row=2, column=0, padx=(12, 6), pady=(6, 12), sticky="ew")

        self.card_dhcp = InfoCard(adp_container, title="DHCP Status", value="--", subtitle="Automatic IP assignment")
        self.card_dhcp.grid(row=2, column=1, padx=6, pady=(6, 12), sticky="ew")

        self.card_status = InfoCard(adp_container, title="Link Status", value="--", subtitle="Operational state")
        self.card_status.grid(row=2, column=2, padx=(6, 12), pady=(6, 12), sticky="ew")

    def _create_tools_tabview(self):
        """Creates tabbed interface for Ping, DNS/Traceroute, and Adapter Controls."""
        self.tabview = ctk.CTkTabview(self, corner_radius=12)
        self.tabview.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="nsew")

        # Tabs
        self.tab_ping = self.tabview.add("Ping Diagnostic")
        self.tab_dns_trace = self.tabview.add("DNS & Traceroute")
        self.tab_controls = self.tabview.add("Adapter Controls (DHCP / DNS Flush)")

        self._build_ping_tab()
        self._build_dns_trace_tab()
        self._build_controls_tab()

    # =========================================================================
    # TAB 1: PING TOOL
    # =========================================================================
    def _build_ping_tab(self):
        self.tab_ping.grid_columnconfigure(0, weight=1)

        # Control Bar
        ctrl_frame = ctk.CTkFrame(self.tab_ping, fg_color="transparent")
        ctrl_frame.grid(row=0, column=0, padx=10, pady=(10, 10), sticky="ew")
        ctrl_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl_frame, text="Target Host / IP:", font=ctk.CTkFont(size=12, weight="bold")).grid(row=0, column=0, padx=(0, 8), sticky="w")
        
        self.ping_target_entry = ctk.CTkEntry(ctrl_frame, placeholder_text="e.g. 8.8.8.8, 1.1.1.1, or google.com", height=32)
        self.ping_target_entry.insert(0, "8.8.8.8")
        self.ping_target_entry.grid(row=0, column=1, padx=5, sticky="ew")

        ctk.CTkLabel(ctrl_frame, text="Count:", font=ctk.CTkFont(size=12)).grid(row=0, column=2, padx=(10, 5), sticky="w")
        self.ping_count_menu = ctk.CTkOptionMenu(ctrl_frame, values=["2", "4", "8", "10"], width=70, height=32)
        self.ping_count_menu.set("4")
        self.ping_count_menu.grid(row=0, column=3, padx=5, sticky="w")

        self.ping_btn = ctk.CTkButton(
            ctrl_frame,
            text="Ping Target",
            width=110,
            height=32,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._run_ping
        )
        self.ping_btn.grid(row=0, column=4, padx=(10, 0), sticky="e")

        # Quick shortcuts
        quick_frame = ctk.CTkFrame(self.tab_ping, fg_color="transparent")
        quick_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="w")

        ctk.CTkLabel(quick_frame, text="Quick Targets:", font=ctk.CTkFont(size=11, weight="bold"), text_color=("#6B7280", "#9CA3AF")).pack(side="left", padx=(0, 8))
        
        self.quick_gw_btn = ctk.CTkButton(
            quick_frame,
            text="Ping Default Gateway",
            height=24,
            font=ctk.CTkFont(size=11),
            fg_color="#374151",
            hover_color="#4B5563",
            command=self._quick_ping_gateway
        )
        self.quick_gw_btn.pack(side="left", padx=4)

        for label, val in [("Google DNS (8.8.8.8)", "8.8.8.8"), ("Cloudflare (1.1.1.1)", "1.1.1.1"), ("Localhost (127.0.0.1)", "127.0.0.1")]:
            ctk.CTkButton(
                quick_frame,
                text=label,
                height=24,
                font=ctk.CTkFont(size=11),
                fg_color="#374151",
                hover_color="#4B5563",
                command=lambda v=val: self._set_ping_target_and_run(v)
            ).pack(side="left", padx=4)

        # Output Console
        self.ping_console = LogConsole(self.tab_ping, title="PING RESULTS (ICMP ECHO)", height=180)
        self.ping_console.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")

    def _quick_ping_gateway(self):
        gw = self.card_gateway.value_label.cget("text")
        if gw and gw != "--" and gw != "Not Configured":
            self._set_ping_target_and_run(gw)
        else:
            self.ping_console.set_text("[ERROR] No valid Default Gateway is configured on the selected adapter.")

    def _set_ping_target_and_run(self, target: str):
        self.ping_target_entry.delete(0, "end")
        self.ping_target_entry.insert(0, target)
        self._run_ping()

    def _run_ping(self):
        target = self.ping_target_entry.get().strip()
        if not target:
            self.ping_console.set_text("[ERROR] Please enter a target IP address or hostname to ping.")
            return

        count = int(self.ping_count_menu.get())
        self.ping_btn.configure(state="disabled", text="Pinging...")
        self.ping_console.set_text(f"[*] Sending {count} ICMP Echo requests to '{target}'...\n")

        def worker():
            res = ping_target(target, count=count)
            def update_ui():
                self.ping_console.set_text(res.raw_output)
                if res.success:
                    summary = f"\n[SUCCESS] Packets: Sent={res.sent}, Received={res.received}, Loss={res.loss_percent:.1f}%\n"
                    if res.avg_rtt_ms is not None:
                        summary += f"[LATENCY] Min={res.min_rtt_ms}ms, Max={res.max_rtt_ms}ms, Avg={res.avg_rtt_ms}ms\n"
                    self.ping_console.append_text(summary)
                else:
                    self.ping_console.append_text(f"\n[FAILED] {res.error_message or 'Host unreachable.'}\n")
                self.ping_btn.configure(state="normal", text="Ping Target")

            self.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # TAB 2: DNS & TRACEROUTE
    # =========================================================================
    def _build_dns_trace_tab(self):
        self.tab_dns_trace.grid_columnconfigure(0, weight=1)
        self.tab_dns_trace.grid_columnconfigure(1, weight=1)

        # Left Column: DNS Lookup
        dns_box = ctk.CTkFrame(self.tab_dns_trace, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        dns_box.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="nsew")
        dns_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(dns_box, text="DNS RESOLVER (NSLOOKUP)", font=ctk.CTkFont(size=12, weight="bold"), text_color=("#6B7280", "#9CA3AF")).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 8), sticky="w")

        ctk.CTkLabel(dns_box, text="Domain / IP:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=(12, 6), sticky="w")
        self.dns_entry = ctk.CTkEntry(dns_box, placeholder_text="e.g. google.com or 8.8.8.8", height=30)
        self.dns_entry.insert(0, "google.com")
        self.dns_entry.grid(row=1, column=1, padx=(0, 12), sticky="ew")

        self.dns_btn = ctk.CTkButton(
            dns_box,
            text="Lookup DNS Record",
            height=30,
            fg_color="#059669",
            hover_color="#047857",
            command=self._run_dns
        )
        self.dns_btn.grid(row=2, column=0, columnspan=2, padx=12, pady=10, sticky="ew")

        self.dns_console = LogConsole(dns_box, title="DNS RECORD OUTPUT", height=140)
        self.dns_console.grid(row=3, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")

        # Right Column: Traceroute
        trace_box = ctk.CTkFrame(self.tab_dns_trace, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        trace_box.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="nsew")
        trace_box.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(trace_box, text="TRACEROUTE (TRACERT)", font=ctk.CTkFont(size=12, weight="bold"), text_color=("#6B7280", "#9CA3AF")).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 8), sticky="w")

        ctk.CTkLabel(trace_box, text="Target Host:", font=ctk.CTkFont(size=12)).grid(row=1, column=0, padx=(12, 6), sticky="w")
        self.trace_entry = ctk.CTkEntry(trace_box, placeholder_text="e.g. 8.8.8.8 or cloudflare.com", height=30)
        self.trace_entry.insert(0, "1.1.1.1")
        self.trace_entry.grid(row=1, column=1, padx=(0, 12), sticky="ew")

        self.trace_btn = ctk.CTkButton(
            trace_box,
            text="Run Traceroute",
            height=30,
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._run_traceroute
        )
        self.trace_btn.grid(row=2, column=0, columnspan=2, padx=12, pady=10, sticky="ew")

        self.trace_console = LogConsole(trace_box, title="HOP-BY-HOP ROUTE", height=140)
        self.trace_console.grid(row=3, column=0, columnspan=2, padx=12, pady=(0, 12), sticky="ew")

    def _run_dns(self):
        target = self.dns_entry.get().strip()
        if not target:
            self.dns_console.set_text("[ERROR] Please enter a domain or IP to resolve.")
            return

        self.dns_btn.configure(state="disabled", text="Resolving...")
        self.dns_console.set_text(f"[*] Querying DNS records for '{target}'...\n")

        def worker():
            res = dns_lookup(target)
            def update_ui():
                self.dns_console.set_text(res.raw_output)
                if res.addresses:
                    summary = f"\n[RESOLVED ADDRESSES]: {', '.join(res.addresses)}\n[CANONICAL NAME]: {res.canonical_name}\n"
                    self.dns_console.append_text(summary)
                self.dns_btn.configure(state="normal", text="Lookup DNS Record")

            self.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    def _run_traceroute(self):
        target = self.trace_entry.get().strip()
        if not target:
            self.trace_console.set_text("[ERROR] Please enter a target host for traceroute.")
            return

        self.trace_btn.configure(state="disabled", text="Tracing Hops (Please wait)...")
        self.trace_console.set_text(f"[*] Tracing route to {target} (max 30 hops)...\nThis operation takes 10-30 seconds depending on distance.\n\n")

        def worker():
            res = traceroute_target(target)
            def update_ui():
                self.trace_console.set_text(res.raw_output)
                if res.success:
                    self.trace_console.append_text(f"\n[COMPLETE] Trace finished. {len(res.hops)} hops discovered.\n")
                else:
                    self.trace_console.append_text(f"\n[ERROR] {res.error_message}\n")
                self.trace_btn.configure(state="normal", text="Run Traceroute")

            self.after(0, update_ui)

        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # TAB 3: ADAPTER CONTROLS (DHCP / DNS FLUSH)
    # =========================================================================
    def _build_controls_tab(self):
        self.tab_controls.grid_columnconfigure(0, weight=1)
        self.tab_controls.grid_columnconfigure(1, weight=1)
        self.tab_controls.grid_columnconfigure(2, weight=1)

        # Card 1: Flush DNS
        card1 = ctk.CTkFrame(self.tab_controls, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        card1.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="nsew")
        card1.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card1, text="FLUSH DNS CACHE", font=ctk.CTkFont(size=13, weight="bold"), text_color=("#2563EB", "#60A5FA")).pack(padx=14, pady=(14, 4), anchor="w")
        ctk.CTkLabel(card1, text="Clears the local Windows DNS client resolver cache. Use when websites fail to load after DNS changes.", font=ctk.CTkFont(size=11), text_color=("#4B5563", "#9CA3AF"), wraplength=240, justify="left").pack(padx=14, pady=(0, 12), anchor="w")

        ctk.CTkButton(
            card1,
            text="Flush DNS (ipconfig /flushdns)",
            fg_color="#2563EB",
            hover_color="#1D4ED8",
            command=self._confirm_flush_dns
        ).pack(padx=14, pady=(0, 14), fill="x")

        # Card 2: Release DHCP
        card2 = ctk.CTkFrame(self.tab_controls, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        card2.grid(row=0, column=1, padx=5, pady=10, sticky="nsew")
        card2.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card2, text="RELEASE DHCP LEASE", font=ctk.CTkFont(size=13, weight="bold"), text_color="#EF4444").pack(padx=14, pady=(14, 4), anchor="w")
        ctk.CTkLabel(card2, text="Relinquishes the current IP address configuration. CAUTION: Temporarily disconnects the PC from network.", font=ctk.CTkFont(size=11), text_color=("#4B5563", "#9CA3AF"), wraplength=240, justify="left").pack(padx=14, pady=(0, 12), anchor="w")

        ctk.CTkButton(
            card2,
            text="Release Lease (ipconfig /release)",
            fg_color="#DC2626",
            hover_color="#B91C1C",
            command=self._confirm_release_dhcp
        ).pack(padx=14, pady=(0, 14), fill="x")

        # Card 3: Renew DHCP
        card3 = ctk.CTkFrame(self.tab_controls, corner_radius=10, fg_color=("#E5E7EB", "#1F2937"))
        card3.grid(row=0, column=2, padx=(5, 10), pady=10, sticky="nsew")
        card3.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(card3, text="RENEW DHCP LEASE", font=ctk.CTkFont(size=13, weight="bold"), text_color="#10B981").pack(padx=14, pady=(14, 4), anchor="w")
        ctk.CTkLabel(card3, text="Requests a fresh IP address and configuration parameters from your local DHCP server/router.", font=ctk.CTkFont(size=11), text_color=("#4B5563", "#9CA3AF"), wraplength=240, justify="left").pack(padx=14, pady=(0, 12), anchor="w")

        ctk.CTkButton(
            card3,
            text="Renew Lease (ipconfig /renew)",
            fg_color="#059669",
            hover_color="#047857",
            command=self._confirm_renew_dhcp
        ).pack(padx=14, pady=(0, 14), fill="x")

        # Output Console for Controls
        self.control_console = LogConsole(self.tab_controls, title="COMMAND LOG (IPCONFIG CONTROLS)", height=150)
        self.control_console.grid(row=1, column=0, columnspan=3, padx=10, pady=(0, 10), sticky="ew")

    def _confirm_flush_dns(self):
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title="Flush DNS Cache",
            message="Are you sure you want to flush the Windows DNS Resolver Cache?",
            warning_detail="This will clear all cached domain lookups. It is safe and does not disconnect active connections.",
            confirm_text="Flush Cache",
            on_confirm=self._execute_flush_dns
        )

    def _execute_flush_dns(self):
        self.control_console.set_text("[*] Running 'ipconfig /flushdns'...\n")
        def worker():
            res = flush_dns_cache()
            self.after(0, lambda: self.control_console.set_text(res.stdout or res.stderr))
        threading.Thread(target=worker, daemon=True).start()

    def _confirm_release_dhcp(self):
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title="Release DHCP Lease",
            message="Release active DHCP lease on all network interfaces?",
            warning_detail="WARNING: Your computer will immediately lose its IP address and network connection until you perform a DHCP Renew.",
            confirm_text="Release IP",
            is_destructive=True,
            on_confirm=self._execute_release_dhcp
        )

    def _execute_release_dhcp(self):
        self.control_console.set_text("[*] Releasing DHCP lease (ipconfig /release)...\n")
        def worker():
            res = release_dhcp_lease()
            def ui_update():
                self.control_console.set_text(res.stdout or res.stderr)
                self.refresh_adapters()
            self.after(0, ui_update)
        threading.Thread(target=worker, daemon=True).start()

    def _confirm_renew_dhcp(self):
        ConfirmationDialog(
            parent=self.winfo_toplevel(),
            title="Renew DHCP Lease",
            message="Request a new DHCP lease from the router?",
            warning_detail="This requests updated network configuration from your DHCP server. May take several seconds.",
            confirm_text="Renew Lease",
            on_confirm=self._execute_renew_dhcp
        )

    def _execute_renew_dhcp(self):
        self.control_console.set_text("[*] Requesting new DHCP lease (ipconfig /renew)...\n")
        def worker():
            res = renew_dhcp_lease()
            def ui_update():
                self.control_console.set_text(res.stdout or res.stderr)
                self.refresh_adapters()
            self.after(0, ui_update)
        threading.Thread(target=worker, daemon=True).start()

    # =========================================================================
    # Adapter Refresh & Selection Handling
    # =========================================================================
    def refresh_adapters(self):
        """Scans network adapters and updates UI immediately."""
        try:
            self.refresh_adp_btn.configure(state="disabled", text="Scanning...")
            adapters = get_network_adapters()
            self._apply_adapters(adapters)
        except Exception as e:
            logger.error(f"Error refreshing adapters: {e}", exc_info=True)
        finally:
            try:
                self.refresh_adp_btn.configure(state="normal", text="Refresh Adapters")
            except Exception:
                pass

    def _apply_adapters(self, adapters: List[NetworkAdapter]):
        self.adapters = adapters
        self.refresh_adp_btn.configure(state="normal", text="Refresh Adapters")

        if not adapters:
            self.adapter_menu.configure(values=["No network adapters detected."])
            self.adapter_menu.set("No network adapters detected.")
            return

        # Format menu labels: "Wi-Fi (192.168.1.102) [Connected]"
        menu_items = []
        for a in adapters:
            ip_display = a.ipv4 if a.ipv4 != "Not Assigned" else "No IP"
            status_tag = "Connected" if a.is_up else "Disconnected"
            menu_items.append(f"{a.name} ({ip_display}) [{status_tag}]")

        self.adapter_menu.configure(values=menu_items)
        
        # Select first connected adapter by default
        selected_idx = 0
        for i, a in enumerate(adapters):
            if a.is_up and a.ipv4 != "Not Assigned":
                selected_idx = i
                break

        self.adapter_menu.set(menu_items[selected_idx])
        self._update_adapter_cards(adapters[selected_idx])

    def _on_adapter_selected(self, choice: str):
        # Find adapter by matching name
        for a in self.adapters:
            if choice.startswith(a.name):
                self._update_adapter_cards(a)
                break

    def _update_adapter_cards(self, adapter: NetworkAdapter):
        self.selected_adapter = adapter

        # Card 1: IPv4
        self.card_ipv4.update_content(
            value=adapter.ipv4,
            subtitle=f"Subnet Mask: {adapter.subnet_mask}"
        )

        # Card 2: Gateway
        gw_val = adapter.default_gateway if adapter.default_gateway else "Not Configured"
        self.card_gateway.update_content(
            value=gw_val,
            subtitle="Default Gateway"
        )

        # Card 3: DNS
        dns_str = ", ".join(adapter.dns_servers) if adapter.dns_servers else "Not Configured"
        self.card_dns.update_content(
            value=dns_str,
            subtitle=f"{len(adapter.dns_servers)} configured DNS server(s)"
        )

        # Card 4: MAC
        self.card_mac.update_content(
            value=adapter.mac_address,
            subtitle=adapter.description
        )

        # Card 5: DHCP
        if adapter.dhcp_enabled is True:
            dhcp_status = "Enabled (Dynamic IP)"
        elif adapter.dhcp_enabled is False:
            dhcp_status = "Disabled (Static IP)"
        else:
            dhcp_status = "Unknown / Virtual"
        self.card_dhcp.update_content(
            value=dhcp_status,
            subtitle="Assignment Protocol"
        )

        # Card 6: Status
        status_color = "#10B981" if adapter.is_up else "#EF4444"
        self.card_status.update_content(
            value=adapter.status,
            subtitle=f"Interface: {adapter.name}",
            accent_color=status_color
        )
