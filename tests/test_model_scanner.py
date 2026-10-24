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
        self.assertTrue((MODEL_DIR / "andromalhut_xgboost.json").exists())
        self.assertTrue((MODEL_DIR / "andromalhut_model_metadata.json").exists())
        self.assertTrue((MODEL_DIR / "drebin_rf.joblib").exists())
        self.assertTrue((MODEL_DIR / "evaluation.json").exists())
        self.assertTrue(SCANNER.exists())

    def test_model_metrics(self):
        meta = json.loads((MODEL_DIR / "evaluation.json").read_text())
        self.assertGreaterEqual(meta["accuracy"], 0.90)
        self.assertGreaterEqual(meta["balanced_accuracy"], 0.90)
        self.assertGreaterEqual(meta.get("datasets", {}).get("total_samples_raw", 20000), 20000)
        self.assertGreaterEqual(meta["total_samples"], 10000)
        # Verify cross-dataset and ablation metrics are recorded
        self.assertIn("cross_dataset_metrics", meta)
        self.assertIn("source_ablation_metrics", meta)

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
            self.assertIn("Classification       : SUSPICIOUS", res.stdout)
            self.assertIn("Verdict              : SUSPICIOUS", res.stdout)

    def test_scan_benign_flipkart(self):
        apk = PROJECT_ROOT / "Android-Forensics/CASE-20261019-001/evidence/original_apks/com.flipkart.android.apk"
        if apk.exists():
            res = subprocess.run([str(PYTHON_VENV), str(SCANNER), str(apk)], capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)
            self.assertIn("Verdict              : BENIGN", res.stdout)
            self.assertIn("Classification       : BENIGN", res.stdout)

    def test_load_ml_model_secure_and_tamper_detection(self):
        import sys
        sys.path.insert(0, str(PROJECT_ROOT))
        from ml_model.scan_apk import load_ml_model

        # Verify model loads safely
        model, features, canonical_features, total_samples, desc = load_ml_model(LOCAL_MODEL_DIR)
        self.assertIsNotNone(model)
        self.assertGreater(len(features), 100)
        self.assertGreater(total_samples, 10000)
        self.assertIn("XGBoost", desc)

    def test_metric_rate_formulas(self):
        meta = json.loads((LOCAL_MODEL_DIR / "evaluation.json").read_text())
        cm = meta["confusion_matrix"]
        tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
        rates = meta["random_split_test_metrics"]["rates"]

        expected_fpr = fp / (fp + tn)
        expected_fnr = fn / (fn + tp)
        self.assertAlmostEqual(rates["false_positive_rate"], expected_fpr, places=5)
        self.assertAlmostEqual(rates["false_negative_rate"], expected_fnr, places=5)


if __name__ == "__main__":
    unittest.main()

