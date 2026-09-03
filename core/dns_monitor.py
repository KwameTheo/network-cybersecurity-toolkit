"""
Live DNS Query Monitor & Anomaly Inspector Engine
Inspects host DNS client resolver cache, tracks domain lookups across applications,
and detects cybersecurity anomalies (DGA entropy, DNS tunneling, suspicious TLDs).
"""

import math
import platform
import json
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.subprocess_runner import run_powershell

logger = get_logger()

# Mapping of Windows DNS Type integers to friendly labels
DNS_TYPE_MAP = {
    1: "A (IPv4)",
    28: "AAAA (IPv6)",
    5: "CNAME (Alias)",
    12: "PTR (Reverse)",
    15: "MX (Mail)",
    16: "TXT (Text)",
    6: "SOA (Authority)",
    33: "SRV (Service)",
    65: "HTTPS",
}

# High-risk TLDs commonly abused for spam, phishing, and malware C2
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".zip", ".mov", ".cc", ".ru", ".click",
    ".buzz", ".work", ".cn", ".rest", ".gq", ".cf", ".ml", ".ga"
}


@dataclass
class DnsQueryRecord:
    domain: str
    record_type: str
    record_type_id: int
    resolved_data: str
    ttl_seconds: int
    status: str  # "SUCCESS", "FAILED / NXDOMAIN"
    anomaly_flag: str  # "CLEAN", "SUSPICIOUS_TLD", "DGA_ENTROPY", "DNS_TUNNELING", "NXDOMAIN"
    anomaly_reason: Optional[str] = None
    entropy_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DnsMonitorReport:
    total_queries: int
    clean_count: int
    anomaly_count: int
    records: List[DnsQueryRecord]
    suspicious_tld_count: int
    dga_count: int
    tunneling_count: int
    nxdomain_count: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =========================================================================
# ANOMALY DETECTION ALGORITHMS
# =========================================================================

def calculate_shannon_entropy(text: str) -> float:
    """
    Calculates the Shannon Entropy of a string to measure character randomness.
    Higher entropy (> 3.5 on short strings) is a strong indicator of DGA / malware generation.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def evaluate_domain_anomaly(domain: str, status_code: int) -> tuple[str, Optional[str], float]:
    """
    Applies heuristic and algorithmic rules to classify domain threat profile.
    Returns: (anomaly_flag, reason, entropy_score)
    """
    domain_clean = domain.strip().lower().rstrip(".")
    if not domain_clean:
        return "CLEAN", None, 0.0

    # 1. Check Status Code for NXDOMAIN
    if status_code != 0:
        return "NXDOMAIN", "DNS query failed or domain does not exist (NXDOMAIN / Timeout).", 0.0

    # 2. Check for DNS Tunneling (Unusually long subdomain strings)
    labels = domain_clean.split(".")
    max_label_len = max(len(l) for l in labels) if labels else 0
    if len(domain_clean) > 55 or max_label_len > 35:
        return "DNS_TUNNELING", f"Abnormally long domain ({len(domain_clean)} chars) or subdomain label ({max_label_len} chars). Possible data exfiltration.", 0.0

    # 3. Check for Suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain_clean.endswith(tld):
            return "SUSPICIOUS_TLD", f"Domain uses high-risk Top-Level Domain '{tld}'.", 0.0

    # 4. Check for Domain Generation Algorithms (DGA / High Entropy)
    # Extract base domain name without TLD (e.g. 'x7q84m9klz02p' from 'x7q84m9klz02p.com')
    base_name = labels[0] if labels else domain_clean
    entropy = calculate_shannon_entropy(base_name)

    # Check for excessive entropy or high consonant/digit mixture (typical in DGAs)
    alphanumeric = re.findall(r"[a-z0-9]", base_name)
    if len(alphanumeric) >= 10:
        vowels = len(re.findall(r"[aeiou]", base_name))
        digits = len(re.findall(r"[0-9]", base_name))
        vowel_ratio = vowels / len(alphanumeric)
        digit_ratio = digits / len(alphanumeric)
        # High entropy (> 3.4) and (low vowel ratio < 20% or high mixed digit ratio >= 25%)
        if entropy >= 3.4 and (vowel_ratio < 0.20 or digit_ratio >= 0.25):
            return "DGA_ENTROPY", f"High Shannon Entropy ({entropy}), low vowel ratio ({vowel_ratio:.1%}), or random digits ({digit_ratio:.1%}). Likely Domain Generation Algorithm (DGA).", entropy

    return "CLEAN", None, entropy


# =========================================================================
# DNS CLIENT CACHE INSPECTOR
# =========================================================================

def get_live_dns_cache() -> List[DnsQueryRecord]:
    """
    Queries Windows DNS Resolver Cache via 'Get-DnsClientCache'.
    """
    if platform.system() != "Windows":
        return []

    cmd = "Get-DnsClientCache | Select-Object Entry, Type, Status, TimeToLive, Data | ConvertTo-Json"
    res = run_powershell(cmd)
    if not res.success or not res.stdout:
        return []

    try:
        raw_entries = json.loads(res.stdout)
        if isinstance(raw_entries, dict):
            raw_entries = [raw_entries]

        records: List[DnsQueryRecord] = []
        seen_keys = set()

        for item in raw_entries:
            entry_name = item.get("Entry", "")
            if not entry_name:
                continue

            type_id = item.get("Type", 1)
            status_code = item.get("Status", 0)
            ttl = item.get("TimeToLive", 0)
            data_val = str(item.get("Data", "") or "--")

            # Avoid duplicate rows in UI
            unique_key = f"{entry_name}_{type_id}_{data_val}"
            if unique_key in seen_keys:
                continue
            seen_keys.add(unique_key)

            type_label = DNS_TYPE_MAP.get(type_id, f"Type {type_id}")
            status_label = "SUCCESS" if status_code == 0 else f"FAILED ({status_code})"

            flag, reason, entropy = evaluate_domain_anomaly(entry_name, status_code)

            records.append(DnsQueryRecord(
                domain=entry_name,
                record_type=type_label,
                record_type_id=type_id,
                resolved_data=data_val,
                ttl_seconds=ttl,
                status=status_label,
                anomaly_flag=flag,
                anomaly_reason=reason,
                entropy_score=entropy
            ))

        logger.info(f"Retrieved {len(records)} DNS client cache query records.")
        return records
    except Exception as e:
        logger.error(f"Failed to parse DNS client cache: {e}", exc_info=True)
        return []


def run_dns_monitor_audit() -> DnsMonitorReport:
    """
    Gathers live DNS records and compiles an overall anomaly telemetry report.
    """
    records = get_live_dns_cache()
    total = len(records)

    clean_cnt = sum(1 for r in records if r.anomaly_flag == "CLEAN")
    anom_cnt = total - clean_cnt
    tld_cnt = sum(1 for r in records if r.anomaly_flag == "SUSPICIOUS_TLD")
    dga_cnt = sum(1 for r in records if r.anomaly_flag == "DGA_ENTROPY")
    tunnel_cnt = sum(1 for r in records if r.anomaly_flag == "DNS_TUNNELING")
    nx_cnt = sum(1 for r in records if r.anomaly_flag == "NXDOMAIN")

    return DnsMonitorReport(
        total_queries=total,
        clean_count=clean_cnt,
        anomaly_count=anom_cnt,
        records=records,
        suspicious_tld_count=tld_cnt,
        dga_count=dga_cnt,
        tunneling_count=tunnel_cnt,
        nxdomain_count=nx_cnt
    )
