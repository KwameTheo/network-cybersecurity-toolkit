"""
Tests for core/integrity_guard.py
Verifies cryptographic provenance, HMAC build seals, author attribution, and anti-tamper detection.

Copyright (c) 2026 Kwame_Theo. All Rights Reserved.
"""

import unittest
from unittest.mock import patch
from core.integrity_guard import (
    AUTHOR_NAME,
    BUILD_YEAR,
    COPYRIGHT_NOTICE,
    ORIGIN_UUID,
    PRODUCT_NAME,
    PRODUCT_VERSION,
    PROVENANCE_SIGNATURE,
    assert_authenticity,
    generate_provenance_seal,
    get_certificate_of_authenticity,
    verify_application_integrity,
)


class TestIntegrityGuard(unittest.TestCase):
    def test_author_provenance_constants(self):
        self.assertEqual(AUTHOR_NAME, "Kwame_Theo")
        self.assertEqual(BUILD_YEAR, "2026")
        self.assertIn("Kwame_Theo", COPYRIGHT_NOTICE)
        self.assertEqual(ORIGIN_UUID, "d487f3b8-6e5a-4b07-9b21-4f1659a8cb42")
        self.assertTrue(PROVENANCE_SIGNATURE.startswith("NETSEC-PROV-2026"))

    def test_generate_provenance_seal(self):
        seal1 = generate_provenance_seal()
        self.assertIsInstance(seal1, str)
        self.assertEqual(len(seal1), 64)
        self.assertTrue(seal1.isalnum())

        # Deterministic check
        seal2 = generate_provenance_seal()
        self.assertEqual(seal1, seal2)

        # Salt sensitivity check
        custom_seal = generate_provenance_seal(salt=b"DIFFERENT_SALT_KEY")
        self.assertNotEqual(seal1, custom_seal)

    def test_verify_application_integrity_passing(self):
        res = verify_application_integrity()
        self.assertTrue(res.is_valid)
        self.assertEqual(res.author, "Kwame_Theo")
        self.assertEqual(res.checks_passed, 5)
        self.assertEqual(res.total_checks, 5)
        self.assertEqual(len(res.tamper_flags), 0)
        self.assertIn("VERIFIED", res.summary)

        # Dataclass dict serialization
        d = res.to_dict()
        self.assertEqual(d["author"], "Kwame_Theo")
        self.assertTrue(d["is_valid"])

    def test_tamper_detection_author_spoofing(self):
        with patch("core.integrity_guard.AUTHOR_NAME", "Imposter / Hacker"):
            res = verify_application_integrity()
            self.assertFalse(res.is_valid)
            self.assertGreater(len(res.tamper_flags), 0)
            self.assertTrue(any("Author name mismatch" in f for f in res.tamper_flags))

    def test_tamper_detection_uuid_forgery(self):
        with patch("core.integrity_guard.ORIGIN_UUID", "00000000-0000-0000-0000-000000000000"):
            res = verify_application_integrity()
            self.assertFalse(res.is_valid)
            self.assertTrue(any("Origin UUID altered" in f for f in res.tamper_flags))

    def test_tamper_detection_watermark_defaced(self):
        with patch("core.integrity_guard.PROVENANCE_SIGNATURE", "CORRUPTED_SIGNATURE"):
            res = verify_application_integrity()
            self.assertFalse(res.is_valid)
            self.assertTrue(any("watermark altered" in f for f in res.tamper_flags))

    def test_certificate_of_authenticity(self):
        cert = get_certificate_of_authenticity()
        self.assertIsInstance(cert, dict)
        self.assertEqual(cert["author"], "Kwame_Theo")
        self.assertEqual(cert["origin_uuid"], ORIGIN_UUID)
        self.assertEqual(len(cert["digital_seal_sha256"]), 64)
        self.assertIn("Proprietary Software", cert["legal_status"])

    def test_assert_authenticity_passes(self):
        self.assertTrue(assert_authenticity())


if __name__ == "__main__":
    unittest.main()
