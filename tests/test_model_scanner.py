#!/usr/bin/env python3
import json
import unittest
from pathlib import Path
import subprocess

import sys
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCAL_MODEL_DIR = PROJECT_ROOT / "ml_model"
LEGACY_MODEL_DIR = Path.home() / "Android-Forensics/Datasets/Drebin/model"
MODEL_DIR = LOCAL_MODEL_DIR if (LOCAL_MODEL_DIR / "drebin_rf.joblib").exists() else LEGACY_MODEL_DIR
SCANNER = MODEL_DIR / "scan_apk.py"
PYTHON_VENV = (LEGACY_MODEL_DIR / "venv/bin/python") if (LEGACY_MODEL_DIR / "venv/bin/python").exists() else Path(sys.executable)

class TestModelScanner(unittest.TestCase):
    def test_model_files_exist(self):
        self.assertTrue((MODEL_DIR / "drebin_rf.joblib").exists())
        self.assertTrue((MODEL_DIR / "evaluation.json").exists())
        self.assertTrue(SCANNER.exists())

    def test_model_metrics(self):
        meta = json.loads((MODEL_DIR / "evaluation.json").read_text())
        self.assertGreaterEqual(meta["accuracy"], 0.90)
        self.assertGreaterEqual(meta["balanced_accuracy"], 0.90)
        self.assertGreaterEqual(meta["total_samples"], 20000)

    def test_scan_test_malware(self):
        apk = PROJECT_ROOT / "examples/test_malware.apk"
        res = subprocess.run([str(PYTHON_VENV), str(SCANNER), str(apk)], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Verdict              : MALICIOUS", res.stdout)
        self.assertIn("Classification       : MALWARE", res.stdout)

    def test_scan_androrat_malware(self):
        apk = Path.home() / "AndroRAT/Android_Code/app/release/app-release.apk"
        if apk.exists():
            res = subprocess.run([str(PYTHON_VENV), str(SCANNER), str(apk)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Classification       : MALWARE", res.stdout)

    def test_scan_benign_flipkart(self):
        apk = PROJECT_ROOT / "Android-Forensics/CASE-20261019-001/evidence/original_apks/com.flipkart.android.apk"
        if apk.exists():
            res = subprocess.run([str(PYTHON_VENV), str(SCANNER), str(apk)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verdict              : BENIGN", res.stdout)
            self.assertIn("Classification       : BENIGN", res.stdout)

if __name__ == "__main__":
    unittest.main()
