"""
IT Support Troubleshooting Engine (Rule-Based Expert System)
Evaluates network telemetry against diagnostic decision trees to isolate root causes
for common IT support scenarios and generates step-by-step remediation plans.
"""

import datetime
import ipaddress
import socket
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from core.dns_internet import (
    check_adapter_stage,
    check_dns_stage,
    check_gateway_stage,
    check_https_stage,
    check_internet_ip_stage,
    check_latency_stage,
)
from core.network_diagnostics import (
    dns_lookup,
    get_network_adapters,
    get_primary_adapter,
    ping_target,
)
from utils.logger import get_logger
from utils.validators import validate_target

logger = get_logger()


@dataclass
class FindingItem:
    status: str  # "PASS", "FAIL", "WARNING", "INFO"
    title: str
    description: str


@dataclass
class TroubleshootScenarioResult:
    scenario_id: str
    scenario_name: str
    timestamp: str
    overall_verdict: str  # "RESOLVED_ONLINE", "ISSUE_DETECTED", "WARNING_DEGRADED"
    confirmed_facts: List[FindingItem]
    probable_root_cause: str
    remediation_steps: List[str]
    raw_telemetry: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# SCENARIO 1: NO INTERNET ACCESS
# =========================================================================

def diagnose_no_internet() -> TroubleshootScenarioResult:
    """Diagnoses general 'No Internet' reports across the full OSI stack."""
    logger.info("Running troubleshooting scenario: No Internet Connection...")
    facts: List[FindingItem] = []
    remediation: List[str] = []
    telemetry: Dict[str, Any] = {}

    # 1. Adapter
    adp_res = check_adapter_stage()
    facts.append(FindingItem(
        status=adp_res.verdict,
        title="Network Adapter & IP Assignment",
        description=f"{adp_res.summary} ({adp_res.details})"
    ))
    if adp_res.verdict == "FAIL":
        return TroubleshootScenarioResult(
            scenario_id="no_internet",
            scenario_name="No Internet Access",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Physical network disconnection or disabled network adapter.",
            remediation_steps=[
                "1. Check physical Ethernet cable connection or ensure Wi-Fi is toggled ON in Windows Settings.",
                "2. Open Network Connections (ncpa.cpl) and ensure your adapter is not Disabled.",
                "3. Reinstall or update the network adapter driver in Device Manager (devmgmt.msc)."
            ],
            raw_telemetry=telemetry
        )

    # 2. Gateway
    gw_res = check_gateway_stage()
    facts.append(FindingItem(
        status=gw_res.verdict,
        title="Default Gateway (Router) Reachability",
        description=gw_res.summary
    ))
    if gw_res.verdict == "FAIL":
        return TroubleshootScenarioResult(
            scenario_id="no_internet",
            scenario_name="No Internet Access",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Computer cannot reach the local default gateway (router).",
            remediation_steps=[
                "1. Power cycle the local router/gateway (wait 30 seconds and plug back in).",
                "2. Run 'ipconfig /release' and 'ipconfig /renew' to acquire a fresh IP lease.",
                "3. Verify your computer's IP and the gateway IP belong to the same subnet (e.g. 192.168.1.x)."
            ],
            raw_telemetry=telemetry
        )

    # 3. Public IP
    ip_res = check_internet_ip_stage()
    facts.append(FindingItem(
        status=ip_res.verdict,
        title="Public IP Routing (WAN Gateway)",
        description=ip_res.summary
    ))
    if ip_res.verdict == "FAIL":
        return TroubleshootScenarioResult(
            scenario_id="no_internet",
            scenario_name="No Internet Access",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Local router is reachable, but outbound WAN connection to the ISP is down.",
            remediation_steps=[
                "1. Check modem status lights (look for red or blinking WAN/Internet indicators).",
                "2. Power cycle the broadband modem and router.",
                "3. Contact your Internet Service Provider (ISP) to check for a service outage in your area."
            ],
            raw_telemetry=telemetry
        )

    # 4. DNS
    dns_res = check_dns_stage()
    facts.append(FindingItem(
        status=dns_res.verdict,
        title="DNS Domain Resolution",
        description=dns_res.summary
    ))
    if dns_res.verdict == "FAIL":
        return TroubleshootScenarioResult(
            scenario_id="no_internet",
            scenario_name="No Internet Access",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Internet IP routing is active, but DNS name resolution is failing completely.",
            remediation_steps=[
                "1. Flush the local DNS cache using 'ipconfig /flushdns'.",
                "2. Change your adapter's DNS server to public resolvers: Primary 8.8.8.8, Secondary 1.1.1.1.",
                "3. Verify no proxy or VPN software is intercepting DNS requests."
            ],
            raw_telemetry=telemetry
        )

    # 5. HTTPS
    https_res = check_https_stage()
    facts.append(FindingItem(
        status=https_res.verdict,
        title="Secure Web Handshake (HTTPS / Port 443)",
        description=https_res.summary
    ))

    # Success / Healthy
    return TroubleshootScenarioResult(
        scenario_id="no_internet",
        scenario_name="No Internet Access",
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        overall_verdict="RESOLVED_ONLINE",
        confirmed_facts=facts,
        probable_root_cause="No network layer failure detected. All 5 connectivity stages passed successfully.",
        remediation_steps=[
            "1. Network and internet connectivity are fully operational.",
            "2. If a specific application is failing, check that application's proxy or login settings.",
            "3. Clear browser cache and cookies in the affected browser."
        ],
        raw_telemetry=telemetry
    )


# =========================================================================
# SCENARIO 2: WI-FI CONNECTED BUT NO INTERNET
# =========================================================================

def diagnose_wifi_no_internet() -> TroubleshootScenarioResult:
    """Diagnoses the classic 'Wi-Fi Connected but No Internet' issue."""
    logger.info("Running troubleshooting scenario: Wi-Fi Connected but No Internet...")
    facts: List[FindingItem] = []
    adp = get_primary_adapter()

    if not adp or not adp.is_up:
        facts.append(FindingItem("FAIL", "Wi-Fi Interface State", "No active Wi-Fi or network interface found."))
        return TroubleshootScenarioResult(
            scenario_id="wifi_no_internet",
            scenario_name="Wi-Fi Connected but No Internet",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Wi-Fi adapter is disconnected or turned off.",
            remediation_steps=[
                "1. Turn Wi-Fi OFF and back ON in Windows Settings.",
                "2. Reconnect to your wireless SSID and re-enter the WPA2/WPA3 password."
            ],
            raw_telemetry={}
        )

    # Check for APIPA
    if adp.ipv4.startswith("169.254.") or adp.ipv4 == "Not Assigned":
        facts.append(FindingItem("FAIL", "IP Configuration", f"Assigned APIPA address ({adp.ipv4}). DHCP server did not respond."))
        return TroubleshootScenarioResult(
            scenario_id="wifi_no_internet",
            scenario_name="Wi-Fi Connected but No Internet",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="DHCP Lease Failure: The Wi-Fi access point accepted the password, but the router's DHCP server failed to assign an IP address.",
            remediation_steps=[
                "1. Run 'ipconfig /release' followed by 'ipconfig /renew'.",
                "2. Restart the Wi-Fi router to clear exhausted DHCP IP address pools.",
                "3. If managing a corporate network, check if the DHCP server scope is full."
            ],
            raw_telemetry={"adapter": adp.to_dict()}
        )

    facts.append(FindingItem("PASS", "Wi-Fi IP Configuration", f"Valid IP assigned ({adp.ipv4}) on interface '{adp.name}'."))

    # Check Gateway
    gw_ping = ping_target(adp.default_gateway, count=2, timeout_sec=2) if adp.default_gateway != "Not Configured" else None
    if not gw_ping or not gw_ping.success:
        facts.append(FindingItem("FAIL", "Gateway Communication", f"Cannot communicate with router at {adp.default_gateway}."))
        return TroubleshootScenarioResult(
            scenario_id="wifi_no_internet",
            scenario_name="Wi-Fi Connected but No Internet",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Wi-Fi link is active, but local packets are blocked or router is unresponsive.",
            remediation_steps=[
                "1. Move closer to the wireless access point to reduce signal attenuation.",
                "2. Restart your wireless router.",
                "3. Forget the Wi-Fi network in Windows Settings and reconnect."
            ],
            raw_telemetry={}
        )

    facts.append(FindingItem("PASS", "Gateway Communication", f"Router {adp.default_gateway} reachable (Avg RTT: {gw_ping.avg_rtt_ms}ms)."))

    # Check Public IP vs DNS
    wan_ping = ping_target("8.8.8.8", count=2, timeout_sec=2)
    dns_res = check_dns_stage()

    if wan_ping.success and dns_res.verdict == "FAIL":
        facts.append(FindingItem("PASS", "WAN IP Routing", "Outbound IP routing to 8.8.8.8 is working."))
        facts.append(FindingItem("FAIL", "DNS Resolution", "Domain resolution is failing."))
        return TroubleshootScenarioResult(
            scenario_id="wifi_no_internet",
            scenario_name="Wi-Fi Connected but No Internet",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="DNS Resolver Failure: You have active internet routing, but your assigned DNS server is down.",
            remediation_steps=[
                "1. Flush DNS cache via 'ipconfig /flushdns'.",
                "2. Change your Wi-Fi adapter IPv4 DNS server to 8.8.8.8 and 1.1.1.1.",
                "3. In Command Prompt, test 'nslookup google.com 8.8.8.8'."
            ],
            raw_telemetry={}
        )

    if not wan_ping.success:
        facts.append(FindingItem("FAIL", "WAN IP Routing", "Packets cannot leave the local network."))
        return TroubleshootScenarioResult(
            scenario_id="wifi_no_internet",
            scenario_name="Wi-Fi Connected but No Internet",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Router WAN Disconnection: The Wi-Fi router is working, but its internet connection to the ISP is down.",
            remediation_steps=[
                "1. Power cycle the broadband modem/fiber ONT and router.",
                "2. Check if other devices on the same Wi-Fi have internet access.",
                "3. Call your ISP to check for an outage."
            ],
            raw_telemetry={}
        )

    # All good
    facts.append(FindingItem("PASS", "Internet & DNS", "Full WAN routing and DNS operational."))
    return TroubleshootScenarioResult(
        scenario_id="wifi_no_internet",
        scenario_name="Wi-Fi Connected but No Internet",
        timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        overall_verdict="RESOLVED_ONLINE",
        confirmed_facts=facts,
        probable_root_cause="No Wi-Fi or Internet failure detected. Network is online.",
        remediation_steps=[
            "1. Wi-Fi and internet connectivity are healthy.",
            "2. If websites still fail, check for a captive portal (login splash page) in your browser.",
            "3. Disable third-party VPNs or antivirus web shields temporarily to test."
        ],
        raw_telemetry={}
    )


# =========================================================================
# SCENARIO 3: CANNOT ACCESS A SPECIFIC WEBSITE OR IP
# =========================================================================

def diagnose_website_issue(target_host: str) -> TroubleshootScenarioResult:
    """Diagnoses reachability and DNS issues for a specific website or IP."""
    logger.info(f"Running troubleshooting scenario: Cannot access website '{target_host}'...")
    facts: List[FindingItem] = []

    valid, clean_target, target_type = validate_target(target_host)
    if not valid:
        return TroubleshootScenarioResult(
            scenario_id="website_issue",
            scenario_name=f"Cannot Access '{target_host}'",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=[FindingItem("FAIL", "Input Validation", clean_target)],
            probable_root_cause="The entered hostname or IP address format is invalid.",
            remediation_steps=["Please enter a valid domain name (e.g. 'github.com') or IP address (e.g. '1.1.1.1')."],
            raw_telemetry={}
        )

    # Step 1: DNS Lookup
    resolved_ip = clean_target
    if target_type == "domain":
        dns_res = dns_lookup(clean_target)
        if dns_res.success and dns_res.addresses:
            resolved_ip = dns_res.addresses[0]
            facts.append(FindingItem("PASS", "DNS Resolution", f"Resolved '{clean_target}' -> {resolved_ip}"))
        else:
            facts.append(FindingItem("FAIL", "DNS Resolution", f"Could not resolve domain '{clean_target}' (NXDOMAIN or DNS timeout)."))
            return TroubleshootScenarioResult(
                scenario_id="website_issue",
                scenario_name=f"Cannot Access '{clean_target}'",
                timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                overall_verdict="ISSUE_DETECTED",
                confirmed_facts=facts,
                probable_root_cause=f"DNS lookup failed for '{clean_target}'. Either the domain does not exist, has expired, or DNS servers cannot find it.",
                remediation_steps=[
                    f"1. Check the spelling of '{clean_target}'.",
                    "2. Flush your DNS cache using 'ipconfig /flushdns'.",
                    f"3. Test if a public DNS resolver can find it: 'nslookup {clean_target} 8.8.8.8'."
                ],
                raw_telemetry={"dns_raw": dns_res.raw_output}
            )

    # Step 2: Ping Test (ICMP)
    ping_res = ping_target(resolved_ip, count=2, timeout_sec=2)
    if ping_res.success:
        facts.append(FindingItem("PASS", "ICMP Ping Reachability", f"Host {resolved_ip} replied to ping (Avg RTT: {ping_res.avg_rtt_ms}ms)."))
    else:
        facts.append(FindingItem("INFO", "ICMP Ping Reachability", f"Host {resolved_ip} did not respond to ICMP ping (Many web servers block ping for security)."))

    # Step 3: Direct TCP Socket on Port 443 (HTTPS) and Port 80 (HTTP)
    port_443_ok = False
    port_80_ok = False
    
    for port in [443, 80]:
        try:
            with socket.create_connection((resolved_ip, port), timeout=3):
                if port == 443:
                    port_443_ok = True
                else:
                    port_80_ok = True
        except Exception:
            pass

    if port_443_ok or port_80_ok:
        open_ports = []
        if port_443_ok:
            open_ports.append("HTTPS (443)")
        if port_80_ok:
            open_ports.append("HTTP (80)")
        facts.append(FindingItem("PASS", "Web Port Connection", f"Successfully established TCP socket on {', '.join(open_ports)}."))
        return TroubleshootScenarioResult(
            scenario_id="website_issue",
            scenario_name=f"Accessing '{clean_target}'",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="RESOLVED_ONLINE",
            confirmed_facts=facts,
            probable_root_cause=f"The remote server '{clean_target}' ({resolved_ip}) is online and accepting web traffic.",
            remediation_steps=[
                "1. The network and web server are responding properly.",
                "2. If the page fails to display in your browser, try in an Incognito/Private window (bypasses browser extensions).",
                "3. Clear browser cookies and cache for this specific site."
            ],
            raw_telemetry={"resolved_ip": resolved_ip, "port_443": port_443_ok, "port_80": port_80_ok}
        )
    else:
        facts.append(FindingItem("FAIL", "Web Port Connection", f"TCP connection to {resolved_ip} on port 80 and 443 timed out or was refused."))
        return TroubleshootScenarioResult(
            scenario_id="website_issue",
            scenario_name=f"Accessing '{clean_target}'",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause=f"The remote web server at {resolved_ip} is either offline, blocking your IP, or a firewall/proxy is dropping outbound port 80/443 traffic.",
            remediation_steps=[
                f"1. Check if '{clean_target}' is down for everyone on https://downforeveryoneorjustme.com.",
                "2. Check if your corporate firewall or VPN is blocking this destination.",
                "3. Test connecting from a mobile hotspot or secondary network."
            ],
            raw_telemetry={"resolved_ip": resolved_ip}
        )


# =========================================================================
# SCENARIO 4: SLOW NETWORK & HIGH LATENCY
# =========================================================================

def diagnose_slow_network() -> TroubleshootScenarioResult:
    """Diagnoses network bottlenecks by comparing Local LAN latency against WAN latency."""
    logger.info("Running troubleshooting scenario: Slow Network / High Latency...")
    facts: List[FindingItem] = []
    adp = get_primary_adapter()

    if not adp or not adp.is_up:
        facts.append(FindingItem("FAIL", "Adapter Link", "No active network adapter found."))
        return TroubleshootScenarioResult(
            scenario_id="slow_network",
            scenario_name="Slow Network / High Latency",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause="Network adapter is disconnected.",
            remediation_steps=["Check your physical or Wi-Fi connection."],
            raw_telemetry={}
        )

    # 1. Test Local Gateway Latency (6 packets)
    gw_res = ping_target(adp.default_gateway, count=6, timeout_sec=2) if adp.default_gateway != "Not Configured" else None
    gw_latency = gw_res.avg_rtt_ms if (gw_res and gw_res.success) else None
    gw_loss = gw_res.loss_percent if gw_res else 100.0

    # 2. Test Public WAN Latency (6 packets to Cloudflare 1.1.1.1)
    wan_res = ping_target("1.1.1.1", count=6, timeout_sec=2)
    wan_latency = wan_res.avg_rtt_ms if (wan_res and wan_res.success) else None
    wan_loss = wan_res.loss_percent if wan_res else 100.0

    facts.append(FindingItem(
        status="PASS" if gw_latency and gw_latency < 10 else "WARNING",
        title="Local Gateway (LAN) Latency",
        description=f"Router ({adp.default_gateway}): Avg RTT = {gw_latency or '--'}ms | Loss = {gw_loss:.1f}%"
    ))

    facts.append(FindingItem(
        status="PASS" if wan_latency and wan_latency < 100 else "WARNING",
        title="Public Internet (WAN) Latency",
        description=f"Internet (1.1.1.1): Avg RTT = {wan_latency or '--'}ms | Loss = {wan_loss:.1f}%"
    ))

    # Evaluate Local vs WAN bottleneck
    if gw_latency and gw_latency > 25 or gw_loss > 10:
        return TroubleshootScenarioResult(
            scenario_id="slow_network",
            scenario_name="Slow Network / High Latency",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="ISSUE_DETECTED",
            confirmed_facts=facts,
            probable_root_cause=f"Local LAN / Wi-Fi Bottleneck: Latency to your local router is unusually high ({gw_latency}ms). The slowdown is inside your local network, not your ISP.",
            remediation_steps=[
                "1. Move closer to the Wi-Fi router or switch from 2.4GHz to 5GHz/6GHz Wi-Fi.",
                "2. Connect via an Ethernet cable to rule out wireless interference.",
                "3. Check for heavy local network downloads (torrents, Steam updates, large backups) on your PC or other devices."
            ],
            raw_telemetry={"gw_latency": gw_latency, "gw_loss": gw_loss}
        )
    elif wan_latency and wan_latency > 150 or wan_loss > 10:
        return TroubleshootScenarioResult(
            scenario_id="slow_network",
            scenario_name="Slow Network / High Latency",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="WARNING_DEGRADED",
            confirmed_facts=facts,
            probable_root_cause=f"ISP / WAN Bottleneck: Your local Wi-Fi to router is fast ({gw_latency}ms), but latency to the internet is elevated ({wan_latency}ms).",
            remediation_steps=[
                "1. Restart your broadband modem and router.",
                "2. Run a speed test (e.g. fast.com or speedtest.net) to verify your ISP bandwidth.",
                "3. If latency remains high, contact your ISP to check line quality and SNR margins."
            ],
            raw_telemetry={"gw_latency": gw_latency, "wan_latency": wan_latency, "wan_loss": wan_loss}
        )
    else:
        return TroubleshootScenarioResult(
            scenario_id="slow_network",
            scenario_name="Slow Network / High Latency",
            timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            overall_verdict="RESOLVED_ONLINE",
            confirmed_facts=facts,
            probable_root_cause="Local and WAN latency are within normal operating thresholds (Low RTT and 0% loss).",
            remediation_steps=[
                "1. Network connection speed and responsiveness are optimal.",
                "2. If an individual app is slow, the bottleneck may be that remote service's servers."
            ],
            raw_telemetry={"gw_latency": gw_latency, "wan_latency": wan_latency}
        )
