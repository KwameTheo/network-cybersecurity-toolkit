"""
DNS & Internet Diagnostics Engine
Automated 6-stage sequential connectivity triage pipeline (The Connectivity Ladder).
Evaluates local link, gateway reachability, public routing, DNS resolution,
HTTPS TLS handshake, and latency quality.
"""

import datetime
import socket
import ssl
import time
from dataclasses import asdict, dataclass
from typing import Any, Callable, Dict, List, Optional

from core.network_diagnostics import get_network_adapters, get_primary_adapter, ping_target
from utils.logger import get_logger

logger = get_logger()


@dataclass
class ConnectivityStageResult:
    stage_number: int
    name: str
    verdict: str  # "PASS", "WARNING", "FAIL", "SKIPPED"
    summary: str
    details: str
    latency_ms: Optional[float] = None
    failure_diagnosis: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InternetHealthReport:
    timestamp: str
    overall_status: str  # "HEALTHY", "DEGRADED", "OFFLINE"
    stages: List[ConnectivityStageResult]
    passed_count: int
    failed_count: int
    warning_count: int
    summary_verdict: str
    recommended_action: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# INDIVIDUAL STAGE DIAGNOSTIC TESTS
# =========================================================================

def check_adapter_stage() -> ConnectivityStageResult:
    """Stage 1: Checks if local network adapter is connected with a valid IP."""
    adapter = get_primary_adapter()
    if not adapter or not adapter.is_up or adapter.ipv4 == "Not Assigned":
        return ConnectivityStageResult(
            stage_number=1,
            name="Network Adapter & Link",
            verdict="FAIL",
            summary="No connected network adapter found.",
            details="All network interfaces are disconnected or have no assigned IP.",
            failure_diagnosis="Check physical Ethernet cable or ensure Wi-Fi is toggled ON and connected to an SSID."
        )

    # Check for APIPA (169.254.x.x indicates DHCP server did not respond)
    if adapter.ipv4.startswith("169.254."):
        return ConnectivityStageResult(
            stage_number=1,
            name="Network Adapter & Link",
            verdict="WARNING",
            summary=f"APIPA Address Assigned ({adapter.ipv4})",
            details=f"Interface '{adapter.name}' is UP, but has an autoconfigured 169.254.x.x IP address.",
            failure_diagnosis="Your computer could not reach a DHCP server to receive an IP address. Check router DHCP settings."
        )

    return ConnectivityStageResult(
        stage_number=1,
        name="Network Adapter & Link",
        verdict="PASS",
        summary=f"Adapter Connected ({adapter.name})",
        details=f"Interface is UP with IPv4: {adapter.ipv4} | Subnet: {adapter.subnet_mask} | MAC: {adapter.mac_address}"
    )


def check_gateway_stage(gateway_ip: Optional[str] = None) -> ConnectivityStageResult:
    """Stage 2: Checks reachability to local Default Gateway (router)."""
    if not gateway_ip or gateway_ip == "Not Configured":
        adapter = get_primary_adapter()
        gateway_ip = adapter.default_gateway if adapter else None

    if not gateway_ip or gateway_ip == "Not Configured":
        return ConnectivityStageResult(
            stage_number=2,
            name="Default Gateway Reachability",
            verdict="FAIL",
            summary="No Default Gateway Configured",
            details="Network interface has no default gateway defined in routing table.",
            failure_diagnosis="Your router/gateway IP is missing. Check DHCP lease or static IP configuration."
        )

    ping_res = ping_target(gateway_ip, count=2, timeout_sec=2)
    if ping_res.success:
        return ConnectivityStageResult(
            stage_number=2,
            name="Default Gateway Reachability",
            verdict="PASS",
            summary=f"Gateway Reachable ({gateway_ip})",
            details=f"Router responded to ICMP Echo. Avg RTT: {ping_res.avg_rtt_ms or 1.0}ms | 0% loss.",
            latency_ms=ping_res.avg_rtt_ms
        )
    else:
        return ConnectivityStageResult(
            stage_number=2,
            name="Default Gateway Reachability",
            verdict="FAIL",
            summary=f"Gateway Unreachable ({gateway_ip})",
            details=f"Ping to local gateway {gateway_ip} timed out (100% packet loss).",
            failure_diagnosis="Computer cannot communicate with the local router. Check Wi-Fi signal, router power, or IP subnet mismatch."
        )


def check_internet_ip_stage() -> ConnectivityStageResult:
    """Stage 3: Tests public IP reachability (Internet Gateway Routing)."""
    public_targets = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    successful_pings = []

    for target in public_targets:
        res = ping_target(target, count=3, timeout_sec=2)
        if res.success and res.received > 0:
            successful_pings.append(res)
            break  # One success is sufficient

    if successful_pings:
        res = successful_pings[0]
        return ConnectivityStageResult(
            stage_number=3,
            name="Public IP Routing (Internet Gateway)",
            verdict="PASS",
            summary=f"Internet IP Reachable ({res.target})",
            details=f"Packets successfully route out of local network. Avg RTT: {res.avg_rtt_ms}ms.",
            latency_ms=res.avg_rtt_ms
        )
    else:
        return ConnectivityStageResult(
            stage_number=3,
            name="Public IP Routing (Internet Gateway)",
            verdict="FAIL",
            summary="Public IP Unreachable",
            details="Packets failed to reach public DNS IPs (8.8.8.8 / 1.1.1.1).",
            failure_diagnosis="Local gateway is functioning, but external WAN connection is down. Possible ISP outage or modem failure."
        )


def check_dns_stage() -> ConnectivityStageResult:
    """Stage 4: Tests DNS domain name resolution."""
    test_domains = ["google.com", "cloudflare.com", "microsoft.com"]
    resolved_count = 0
    resolved_details = []

    for domain in test_domains:
        try:
            start = time.perf_counter()
            ips = socket.gethostbyname_ex(domain)[2]
            elapsed = (time.perf_counter() - start) * 1000.0
            if ips:
                resolved_count += 1
                resolved_details.append(f"{domain} -> {ips[0]} ({elapsed:.1f}ms)")
        except Exception:
            continue

    if resolved_count >= 2:
        return ConnectivityStageResult(
            stage_number=4,
            name="DNS Domain Resolution",
            verdict="PASS",
            summary=f"DNS Working ({resolved_count}/{len(test_domains)} domains)",
            details="; ".join(resolved_details)
        )
    elif resolved_count == 1:
        return ConnectivityStageResult(
            stage_number=4,
            name="DNS Domain Resolution",
            verdict="WARNING",
            summary="DNS Degraded (Partial resolution)",
            details="; ".join(resolved_details),
            failure_diagnosis="Some DNS queries timed out. Primary DNS server may be experiencing delays."
        )
    else:
        return ConnectivityStageResult(
            stage_number=4,
            name="DNS Domain Resolution",
            verdict="FAIL",
            summary="DNS Resolution Failed",
            details="Failed to resolve google.com, cloudflare.com, and microsoft.com.",
            failure_diagnosis="Internet IP routing is active, but DNS server is not responding. Try flushing DNS or switching to 8.8.8.8 / 1.1.1.1."
        )


def check_https_stage() -> ConnectivityStageResult:
    """Stage 5: Tests end-to-end TLS / HTTPS handshake on Port 443."""
    host = "www.google.com"
    port = 443
    context = ssl.create_default_context()

    try:
        start_t = time.perf_counter()
        with socket.create_connection((host, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                elapsed = (time.perf_counter() - start_t) * 1000.0
                cipher = ssock.cipher()
                cipher_name = cipher[0] if cipher else "TLS"
                return ConnectivityStageResult(
                    stage_number=5,
                    name="Secure Web Handshake (HTTPS / TLS 443)",
                    verdict="PASS",
                    summary=f"HTTPS Connection Established ({elapsed:.1f}ms)",
                    details=f"Completed TLS handshake with {host}:{port} using {cipher_name}.",
                    latency_ms=round(elapsed, 1)
                )
    except Exception as e:
        return ConnectivityStageResult(
            stage_number=5,
            name="Secure Web Handshake (HTTPS / TLS 443)",
            verdict="FAIL",
            summary="HTTPS TLS Handshake Failed",
            details=f"Could not complete TLS handshake with {host}:443 ({str(e)})",
            failure_diagnosis="Outbound port 443 traffic or SSL/TLS certificates may be blocked by a corporate firewall or captive portal."
        )


def check_latency_stage() -> ConnectivityStageResult:
    """Stage 6: Measures connection response latency and quality."""
    res = ping_target("1.1.1.1", count=4, timeout_sec=2)
    if not res.success or res.avg_rtt_ms is None:
        res = ping_target("8.8.8.8", count=4, timeout_sec=2)

    if not res.success or res.avg_rtt_ms is None:
        return ConnectivityStageResult(
            stage_number=6,
            name="Latency & Connection Quality",
            verdict="FAIL",
            summary="High Packet Loss / Latency Test Failed",
            details="Could not establish consistent latency measurements.",
            failure_diagnosis="Severe connection instability or high packet loss."
        )

    avg_ms = res.avg_rtt_ms
    loss = res.loss_percent

    if loss > 20:
        verdict = "WARNING"
        summary = f"Packet Loss Detected ({loss:.1f}%)"
        diag = "Network is dropping packets. Check Wi-Fi interference or ISP line quality."
    elif avg_ms < 50:
        verdict = "PASS"
        summary = f"Excellent Latency ({avg_ms:.1f}ms)"
        diag = None
    elif avg_ms < 120:
        verdict = "PASS"
        summary = f"Good Latency ({avg_ms:.1f}ms)"
        diag = None
    elif avg_ms < 250:
        verdict = "WARNING"
        summary = f"Elevated Latency ({avg_ms:.1f}ms)"
        diag = "Higher than normal latency. May cause noticeable delays in VoIP or video streaming."
    else:
        verdict = "WARNING"
        summary = f"High Latency ({avg_ms:.1f}ms)"
        diag = "Severe latency detected. Check network bandwidth congestion."

    return ConnectivityStageResult(
        stage_number=6,
        name="Latency & Connection Quality",
        verdict=verdict,
        summary=summary,
        details=f"Ping RTT Min={res.min_rtt_ms}ms, Max={res.max_rtt_ms}ms, Avg={res.avg_rtt_ms}ms | Loss={loss:.1f}%",
        latency_ms=avg_ms,
        failure_diagnosis=diag
    )


# =========================================================================
# SEQUENTIAL LADDER PIPELINE RUNNER
# =========================================================================

def run_internet_health_check(
    progress_callback: Optional[Callable[[int, ConnectivityStageResult], None]] = None
) -> InternetHealthReport:
    """
    Executes the complete 6-stage connectivity health ladder in sequential order.
    Calls progress_callback(stage_index, stage_result) as each stage completes.
    """
    logger.info("Starting automated Internet & DNS connectivity health ladder...")
    stages: List[ConnectivityStageResult] = []

    # Stage 1: Adapter
    s1 = check_adapter_stage()
    stages.append(s1)
    if progress_callback:
        progress_callback(1, s1)

    # If Stage 1 is a hard FAIL, short-circuit remaining stages
    if s1.verdict == "FAIL":
        for i in range(2, 7):
            names = ["Gateway", "Public IP", "DNS", "HTTPS", "Latency"]
            skipped = ConnectivityStageResult(
                stage_number=i,
                name=f"Stage {i}: {names[i-2]}",
                verdict="SKIPPED",
                summary="Skipped due to adapter failure",
                details="Cannot test downstream stages when local network adapter is disconnected.",
                failure_diagnosis=s1.failure_diagnosis
            )
            stages.append(skipped)
            if progress_callback:
                progress_callback(i, skipped)

        return _build_report(stages)

    # Stage 2: Gateway
    s2 = check_gateway_stage()
    stages.append(s2)
    if progress_callback:
        progress_callback(2, s2)

    # Stage 3: Public IP
    s3 = check_internet_ip_stage()
    stages.append(s3)
    if progress_callback:
        progress_callback(3, s3)

    # Stage 4: DNS Resolution
    s4 = check_dns_stage()
    stages.append(s4)
    if progress_callback:
        progress_callback(4, s4)

    # Stage 5: HTTPS Handshake
    s5 = check_https_stage()
    stages.append(s5)
    if progress_callback:
        progress_callback(5, s5)

    # Stage 6: Latency
    s6 = check_latency_stage()
    stages.append(s6)
    if progress_callback:
        progress_callback(6, s6)

    return _build_report(stages)


def _build_report(stages: List[ConnectivityStageResult]) -> InternetHealthReport:
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    passed = sum(1 for s in stages if s.verdict == "PASS")
    failed = sum(1 for s in stages if s.verdict == "FAIL")
    warns = sum(1 for s in stages if s.verdict == "WARNING")

    if failed == 0 and warns == 0:
        overall = "HEALTHY"
        verdict_str = "All diagnostic checks passed. Full internet and DNS connectivity active."
        action_str = "No action required. Network is operating at peak performance."
    elif failed == 0 and warns > 0:
        overall = "DEGRADED"
        verdict_str = "Internet is functional, but performance warnings were detected."
        # Find first warning diagnosis
        first_warn = next((s for s in stages if s.failure_diagnosis), None)
        action_str = first_warn.failure_diagnosis if first_warn else "Monitor connection stability."
    else:
        overall = "OFFLINE"
        # Find first failed stage
        first_fail = next((s for s in stages if s.verdict == "FAIL"), None)
        if first_fail:
            verdict_str = f"Connection failure detected at Stage {first_fail.stage_number} ({first_fail.name})."
            action_str = first_fail.failure_diagnosis or "Investigate network adapter or router configuration."
        else:
            verdict_str = "Internet connectivity is offline."
            action_str = "Check network hardware."

    logger.info(f"Health ladder completed: Overall={overall}, Passed={passed}, Failed={failed}, Warnings={warns}")
    return InternetHealthReport(
        timestamp=now_str,
        overall_status=overall,
        stages=stages,
        passed_count=passed,
        failed_count=failed,
        warning_count=warns,
        summary_verdict=verdict_str,
        recommended_action=action_str
    )
