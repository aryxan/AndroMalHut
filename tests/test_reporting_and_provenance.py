import unittest
import tempfile
import shutil
import json
from pathlib import Path

from modules.apk_analysis import parse_apk_manifest, detect_apk_provenance
from modules.reporting import load_case_data, generate_markdown_report, generate_pdf_report
from modules.device_inventory import parse_dumpsys_package


class TestReportingAndProvenance(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_dir = self.test_dir / "Test_Scan_01"
        self.case_dir.mkdir(parents=True)

        # Create subfolders
        (self.case_dir / "evidence" / "device_inventory").mkdir(parents=True)
        (self.case_dir / "evidence" / "original_apks").mkdir(parents=True)
        (self.case_dir / "analysis" / "apk_analysis").mkdir(parents=True)
        (self.case_dir / "hashes").mkdir(parents=True)
        (self.case_dir / "reports").mkdir(parents=True)

        # Write sample case.json
        (self.case_dir / "case.json").write_text(json.dumps({
            "case_id": "Test_Scan_01",
            "created_at_utc": "2026-10-20T00:00:00Z",
            "investigator": "aryxan",
            "device_identifier": "Unknown Device",
        }), encoding="utf-8")

        # Write sample device_info.json
        (self.case_dir / "evidence" / "device_inventory" / "device_info.json").write_text(json.dumps({
            "status": "SUCCESS",
            "device_serial": "TESTSERIAL12345",
            "manufacturer": "Google",
            "model": "Pixel 8",
            "brand": "google",
            "android_version": "14",
            "api_level": "34",
            "security_patch": "2026-09-01",
            "build_fingerprint": "google/shiba/shiba:14/UQ1A.240105.004/11269002:user/release-keys",
        }), encoding="utf-8")

        # Write sample installed_apps_sample.json
        (self.case_dir / "evidence" / "device_inventory" / "installed_apps_sample.json").write_text(json.dumps({
            "status": "SUCCESS",
            "total_apps": 150,
            "user_apps_count": 25,
            "system_apps_count": 125,
            "applications": [
                {
                    "package_name": "com.suspicious.app",
                    "apk_path": "/data/app/~~sample/com.suspicious.app/base.apk",
                    "type": "User/Third-Party",
                    "is_running": True,
                }
            ],
        }), encoding="utf-8")

        # Write sample package_meta_com.suspicious.app.json
        (self.case_dir / "evidence" / "device_inventory" / "package_meta_com.suspicious.app.json").write_text(json.dumps({
            "package_name": "com.suspicious.app",
            "dumpsys_metadata": {
                "first_install_time": "2026-10-18 14:32:00",
                "last_update_time": "2026-10-18 14:32:00",
                "installer_package": "com.android.vending",
                "download_source": "Google Play Store (com.android.vending)",
            }
        }), encoding="utf-8")

        # Write sample apk_analysis file
        (self.case_dir / "analysis" / "apk_analysis" / "apk_analysis_com.suspicious.app.json").write_text(json.dumps({
            "apk_path": "/dummy.apk",
            "hashes": {"sha256": "abcdef123456", "size_bytes": 12345},
            "manifest": {
                "package_name": "com.suspicious.app",
                "version_name": "1.0.0",
                "version_code": "100",
                "target_sdk": "34",
                "min_sdk": "28",
                "application_label": "Suspicious App",
                "permissions": ["android.permission.INTERNET"],
            },
            "provenance": {
                "first_install_time": "2026-10-18 14:32:00",
                "download_source": "Google Play Store (com.android.vending)",
            },
            "permissions_analysis": {
                "risk_score": 10,
                "overall_severity": "LOW",
                "capabilities": ["INTERNET"],
            },
            "embedded_files": {"dex_files": ["classes.dex"], "native_libraries": []},
        }), encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_load_case_data_auto_resolves_device(self):
        data = load_case_data(self.case_dir)
        self.assertIsNotNone(data["device_info"])
        self.assertEqual(data["device_info"]["model"], "Pixel 8")
        self.assertIsNotNone(data["inventory"])
        self.assertEqual(data["inventory"]["total_apps"], 150)
        self.assertIn("Pixel 8", data["case"]["device_identifier"])

    def test_parse_dumpsys_package_provenance(self):
        sample_dumpsys = (
            "Package [com.example.test]\n"
            "  versionName=1.2.3\n"
            "  versionCode=456\n"
            "  firstInstallTime=2026-10-15 10:00:00\n"
            "  lastUpdateTime=2026-10-15 10:00:00\n"
            "  installerPackageName=com.google.android.packageinstaller\n"
            "  originatingUri=https://example.com/malicious.apk\n"
        )
        parsed = parse_dumpsys_package(sample_dumpsys)
        self.assertEqual(parsed["version_name"], "1.2.3")
        self.assertEqual(parsed["first_install_time"], "2026-10-15 10:00:00")
        self.assertEqual(parsed["installer_package"], "com.google.android.packageinstaller")
        self.assertEqual(parsed["originating_uri"], "https://example.com/malicious.apk")
        self.assertIn("https://example.com/malicious.apk", parsed["download_source"])

    def test_detect_apk_provenance_playstore(self):
        manifest = {
            "package_name": "com.example.chess",
            "version_name": "1.0.0-googleplay",
            "permissions": ["com.android.vending.BILLING"],
        }
        prov = detect_apk_provenance(Path("/dummy.apk"), manifest, {})
        self.assertIn("Google Play Store", prov["download_source"])

    def test_markdown_and_pdf_report_generation(self):
        md_file = generate_markdown_report(self.case_dir, operator="aryxan")
        self.assertTrue(md_file.exists())
        content = md_file.read_text(encoding="utf-8")
        self.assertIn("Pixel 8", content)
        self.assertIn("Google Play Store", content)

        pdf_file, err = generate_pdf_report(self.case_dir, operator="aryxan")
        self.assertIsNone(err)
        self.assertIsNotNone(pdf_file)
    def test_permission_analysis_provenance_playstore_vs_sideload(self):
        from modules.permission_analysis import analyze_permissions

        banking_perms = [
            "android.permission.INTERNET",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.READ_PHONE_STATE",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
        ]

        # Case A: Official Google Play Store distribution
        play_prov = {
            "download_source": "Google Play Store (com.android.vending)",
            "installer_package": "com.android.vending",
        }
        res_play = analyze_permissions(
            banking_perms,
            provenance=play_prov,
            package_name="com.lcode.ucomobilebanking",
            app_label="UCO mBanking Plus",
        )
        self.assertEqual(res_play["overall_severity"], "LOW")
        self.assertLessEqual(res_play["risk_score"], 25)
        pattern_names_play = [p["name"] for p in res_play["matched_threat_patterns"]]
        self.assertIn("Standard Banking / 2FA SMS Verification Capability", pattern_names_play)
        self.assertNotIn("SMS Stealer / OTP Interceptor Pattern", pattern_names_play)

        # Case B: Sideloaded / Untrusted distribution
        sideload_prov = {
            "download_source": "Manual Sideload / Direct File Transfer",
            "installer_package": "Unknown",
        }
        res_side = analyze_permissions(
            banking_perms,
            provenance=sideload_prov,
            package_name="peak.nexus.forge375",
            app_label="UCO BANK LIFE CERTIFICATE",
        )
        self.assertIn(res_side["overall_severity"], ("HIGH", "CRITICAL"))
        self.assertGreaterEqual(res_side["risk_score"], 60)
        pattern_names_side = [p["name"] for p in res_side["matched_threat_patterns"]]
        self.assertIn("SMS Stealer / OTP Interceptor Pattern", pattern_names_side)

    def test_report_harmonization_no_contradictions(self):
        md_file = generate_markdown_report(self.case_dir, operator="aryxan")
        content = md_file.read_text(encoding="utf-8")
        self.assertIn("## 8. Permission and Component Analysis", content)
        self.assertIn("## 14. Conclusions and Behavioral Hypotheses", content)
        self.assertIn("Threat Assessment for `com.suspicious.app`", content)
        self.assertIn("Application: `com.suspicious.app`", content)


if __name__ == "__main__":
    unittest.main()
