"""
Unit tests for AndroMalHut Online Verifier and Case Selection Workflow
Author: aryxan (https://github.com/aryxan/AndroMalHut)
"""

import unittest
from pathlib import Path
from modules.online_verifier import (
    resolve_friendly_app_name,
    clean_title_from_package,
    verify_package_online,
)
from modules.case_manager import (
    list_cases,
    get_default_base_dir,
)


class TestOnlineVerifierAndWorkflow(unittest.TestCase):
    def test_popular_app_name_resolution(self):
        self.assertIn("Flipkart", resolve_friendly_app_name("com.flipkart.android"))
        self.assertIn("Domino", resolve_friendly_app_name("com.Dominos"))
        self.assertIn("Chess", resolve_friendly_app_name("com.chess"))
        self.assertIn("Wrestling Empire", resolve_friendly_app_name("com.MDickie.WrestlingEmpire"))
        self.assertIn("WhatsApp", resolve_friendly_app_name("com.whatsapp"))
        self.assertIn("Instagram", resolve_friendly_app_name("com.instagram.android"))

    def test_clean_title_fallback(self):
        title = clean_title_from_package("com.example.supersecurityscanner")
        self.assertIn("Supersecurityscanner", title)
        title2 = clean_title_from_package("andes.oplus.documentsreader")
        self.assertIn("Documentsreader", title2)

    def test_verify_package_online_popular(self):
        # 1. Package name alone: MUST produce UNVERIFIED and "Identity claimed, NOT verified"
        res = verify_package_online("com.flipkart.android")
        self.assertEqual(res["package_name"], "com.flipkart.android")
        self.assertIn("Flipkart", res["app_name"])
        self.assertEqual(res["identity_status"], "UNVERIFIED")
        self.assertEqual(res["threat_reputation"], "Identity claimed, NOT verified")

        # 2. Package name with valid cryptographic certificate match: produces VERIFIED
        flipkart_cert = "5dfba3d8d6cb06f39a2e12db6bac64cedface46811ecd093717aa051ac65ce31"
        res_cert = verify_package_online("com.flipkart.android", cert_fingerprint=flipkart_cert)
        self.assertEqual(res_cert["identity_status"], "VERIFIED")
        self.assertIn("VERIFIED VENDOR", res_cert["threat_reputation"])

    def test_cases_listing_for_workflow(self):
        base_dir = get_default_base_dir()
        cases = list_cases(base_dir)
        self.assertIsInstance(cases, list)


if __name__ == "__main__":
    unittest.main()
