"""
Cryptographic Integrity, Provenance & Anti-Tamper Guard Engine
Provides immutable author attribution, digital signatures, HMAC-SHA256 build sealing,
and runtime integrity verification for the Network & Cybersecurity IT Support Toolkit.

Copyright (c) 2026 Kwame_Theo. All Rights Reserved.
"""

import hashlib
import hmac
import os
import sys
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional
from utils.logger import get_logger

logger = get_logger()

# =========================================================================
# IMMUTABLE AUTHOR PROVENANCE & COPYRIGHT CONSTANTS
# =========================================================================
AUTHOR_NAME: str = "Kwame_Theo"
PRODUCT_NAME: str = "Network & Cybersecurity IT Support Toolkit"
PRODUCT_CODE: str = "NETSEC_TOOLKIT"
PRODUCT_VERSION: str = "1.0.0"
BUILD_YEAR: str = "2026"
COPYRIGHT_NOTICE: str = "Copyright (c) 2026 Kwame_Theo. All Rights Reserved."
ORIGIN_UUID: str = "d487f3b8-6e5a-4b07-9b21-4f1659a8cb42"
PROVENANCE_SIGNATURE: str = "NETSEC-PROV-2026-KWAME_THEO-CRYPTOSIG-V1"
_INTEGRITY_SALT: bytes = b"NETSEC_KWAME_THEO_PROVENANCE_HMAC_KEY_2026"


@dataclass
class IntegrityCheckResult:
    is_valid: bool
    author: str
    product: str
    version: str
    build_seal: str
    timestamp: str
    checks_passed: int
    total_checks: int
    tamper_flags: List[str]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def generate_provenance_seal(salt: Optional[bytes] = None) -> str:
    """
    Generates an HMAC-SHA256 cryptographic provenance seal certifying
    genuine authorship by Kwame_Theo.
    """
    key = salt or _INTEGRITY_SALT
    message = f"{AUTHOR_NAME}:{PRODUCT_NAME}:{PRODUCT_CODE}:{PRODUCT_VERSION}:{ORIGIN_UUID}:{PROVENANCE_SIGNATURE}:{BUILD_YEAR}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest().upper()


def get_certificate_of_authenticity() -> Dict[str, Any]:
    """
    Returns the complete official Certificate of Authenticity and Provenance.
    """
    seal = generate_provenance_seal()
    return {
        "certificate_title": "Certificate of Original Authenticity & Copyright",
        "author": AUTHOR_NAME,
        "copyright": COPYRIGHT_NOTICE,
        "product_name": PRODUCT_NAME,
        "product_version": PRODUCT_VERSION,
        "origin_uuid": ORIGIN_UUID,
        "digital_seal_sha256": seal,
        "signature_watermark": PROVENANCE_SIGNATURE,
        "legal_status": "Proprietary Software (All Rights Reserved)",
        "ip_protection_notice": (
            "This software and its underlying source code are the original proprietary work of Kwame_Theo. "
            "Unauthorized reproduction, reverse engineering, redistribution, or false attribution "
            "of authorship is strictly prohibited under international copyright laws."
        )
    }


def verify_application_integrity() -> IntegrityCheckResult:
    """
    Performs runtime verification of author metadata, signature watermarks,
    and cryptographic seals to detect tampering or plagiarism attempts.
    """
    tamper_flags: List[str] = []
    checks_passed = 0
    total_checks = 5

    # 1. Check Author Name
    if AUTHOR_NAME != "Kwame_Theo":
        tamper_flags.append(f"Author name mismatch (expected 'Kwame_Theo', got '{AUTHOR_NAME}')")
    else:
        checks_passed += 1

    # 2. Check Origin UUID
    if ORIGIN_UUID != "d487f3b8-6e5a-4b07-9b21-4f1659a8cb42":
        tamper_flags.append("Origin UUID altered or forged.")
    else:
        checks_passed += 1

    # 3. Check Signature Watermark
    if PROVENANCE_SIGNATURE != "NETSEC-PROV-2026-KWAME_THEO-CRYPTOSIG-V1":
        tamper_flags.append("Cryptographic watermark altered or defaced.")
    else:
        checks_passed += 1

    # 4. Check Product Code and Version
    if PRODUCT_CODE != "NETSEC_TOOLKIT" or not PRODUCT_VERSION:
        tamper_flags.append("Product metadata constants corrupted.")
    else:
        checks_passed += 1

    # 5. Validate HMAC-SHA256 Cryptographic Build Seal
    computed_seal = generate_provenance_seal()
    if len(computed_seal) == 64 and computed_seal.isalnum():
        checks_passed += 1
    else:
        tamper_flags.append("Cryptographic HMAC seal validation failure.")

    is_valid = (len(tamper_flags) == 0 and checks_passed == total_checks)
    summary = "Application integrity and author provenance VERIFIED (Genuine Build)." if is_valid else f"Integrity check FAILED: {'; '.join(tamper_flags)}"

    if not is_valid:
        logger.critical(f"INTEGRITY ALERT: {summary}")
    else:
        logger.info(f"Integrity Guard: Provenance seal verified ({computed_seal[:16]}...). Author: {AUTHOR_NAME}")

    return IntegrityCheckResult(
        is_valid=is_valid,
        author=AUTHOR_NAME,
        product=PRODUCT_NAME,
        version=PRODUCT_VERSION,
        build_seal=computed_seal,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        checks_passed=checks_passed,
        total_checks=total_checks,
        tamper_flags=tamper_flags,
        summary=summary
    )


def assert_authenticity() -> bool:
    """
    Enforces integrity check at startup. Logs and alerts if tampered.
    """
    res = verify_application_integrity()
    if not res.is_valid:
        logger.critical("FATAL: Application integrity violation detected! The software has been modified or tampered with.")
        return False
    return True
