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
        res = verify_package_online("com.flipkart.android")
        self.assertEqual(res["package_name"], "com.flipkart.android")
        self.assertIn("Flipkart", res["app_name"])
        self.assertIn("BENIGN", res["threat_reputation"])

    def test_cases_listing_for_workflow(self):
        base_dir = get_default_base_dir()
        cases = list_cases(base_dir)
        self.assertIsInstance(cases, list)


if __name__ == "__main__":
    unittest.main()
