#!/usr/bin/env python3
"""
Unit tests for AndroMalHut scan management, test subfolder creation, and existing scan handling.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

import sys
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from modules.case_manager import (
    init_case,
    get_or_create_scan,
    open_system_folder,
    set_active_case,
    get_active_case,
)
from andromalhut import run_ml_classifier


class TestScanManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp(prefix="andromalhut_test_"))

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_new_scan_with_custom_name_and_subfolders(self):
        scan_name = "TargetInvestigation_Alpha"
        case_dir, already_existed = get_or_create_scan(
            scan_name=scan_name,
            base_dir=self.test_dir,
            open_folder=False,
            description="Test Alpha Scan",
        )
        self.assertFalse(already_existed)
        self.assertEqual(case_dir.name, scan_name)
        self.assertTrue((case_dir / "case.json").exists())

        # Verify dedicated subfolders for each test
        expected_subfolders = [
            "evidence/original_apks",
            "evidence/device_apks",
            "evidence/device_inventory",
            "evidence/device_logs",
            "evidence/sms_exports",
            "evidence/network_captures",
            "evidence/imported_files",
            "analysis/apk_analysis",
            "analysis/ml_classification",
            "analysis/ai_triage",
            "analysis/network_analysis",
            "analysis/log_analysis",
            "analysis/sms_analysis",
            "analysis/timelines",
            "hashes",
            "reports",
            "logs",
        ]
        for sub in expected_subfolders:
            sub_path = case_dir / sub
            self.assertTrue(sub_path.exists(), f"Missing test subfolder: {sub}")
            self.assertTrue(sub_path.is_dir(), f"Expected directory: {sub}")

    def test_existing_scan_detection(self):
        scan_name = "Investigation_Beta"
        # First creation
        case_dir_1, existed_1 = get_or_create_scan(
            scan_name=scan_name,
            base_dir=self.test_dir,
            open_folder=False,
        )
        self.assertFalse(existed_1)

        # Second access with identical name
        case_dir_2, existed_2 = get_or_create_scan(
            scan_name=scan_name,
            base_dir=self.test_dir,
            open_folder=False,
        )
        self.assertTrue(existed_2)
        self.assertEqual(case_dir_1.resolve(), case_dir_2.resolve())
        self.assertEqual(get_active_case().resolve(), case_dir_2.resolve())

    def test_open_system_folder_safe(self):
        # Existing folder
        self.assertTrue(isinstance(open_system_folder(self.test_dir), bool))
        # Non-existing folder
        self.assertFalse(open_system_folder(self.test_dir / "does_not_exist"))

    def test_run_ml_classifier_writes_to_subfolder(self):
        case_dir, _ = get_or_create_scan(
            scan_name="ML_Subfolder_Test",
            base_dir=self.test_dir,
            open_folder=False,
        )
        apk_path = ROOT_DIR / "examples/test_malware.apk"
        if apk_path.exists():
            result = run_ml_classifier(apk_path, case_dir)
            self.assertEqual(result.get("status"), "SUCCESS")
            self.assertEqual(result.get("verdict"), "MALICIOUS")
            self.assertGreater(result.get("malware_probability", 0), 0.5)

            # Check that it wrote to analysis/ml_classification/
            ml_dir = case_dir / "analysis" / "ml_classification"
            self.assertTrue(ml_dir.exists())
            expected_json = ml_dir / f"ml_assessment_{apk_path.stem}.json"
            self.assertTrue(expected_json.exists())


if __name__ == "__main__":
    unittest.main()
