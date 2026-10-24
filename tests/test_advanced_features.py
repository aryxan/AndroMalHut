import sys
import unittest
import json
import tempfile
import shutil
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.case_manager import init_case
from modules.permission_analysis import (
    analyze_permissions,
    build_mitre_attack_matrix,
    ANDROID_DANGEROUS_PERMISSIONS,
    SPECIAL_SUSPICIOUS_PERMISSIONS,
)
from modules.apk_analysis import (
    extract_secrets_and_credentials,
    detect_cloud_services,
    detect_packers_and_anti_analysis,
    analyze_native_libraries,
    analyze_accessibility_and_overlay,
    analyze_device_admin,
    analyze_data_exfiltration,
    build_unified_ioc_list,
)
from modules.dynamic_analysis import (
    check_dynamic_environment,
    run_dynamic_sandbox,
)
from modules.reporting import (
    generate_markdown_report,
    generate_pdf_report,
    REPORTLAB_AVAILABLE,
)
from modules.device_inventory import (
    validate_package_name,
    is_valid_package_name,
    validate_apk_path,
    inspect_package,
    pull_application_apk,
)


class TestAdvancedFeatures(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="test_adv_features_")
        self.base_path = Path(self.test_dir)
        self.case_dir = init_case(
            description="Advanced Forensic Feature Verification Scan",
            investigator="Forensic Lead",
            device_identifier="Pixel Test Device",
            base_dir=self.base_path,
        )

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_permission_categorization_and_mitre_matrix(self):
        """Test Normal, Dangerous, Suspicious categorization and MITRE ATT&CK Mobile matrix."""
        test_perms = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.BIND_DEVICE_ADMIN",
            "com.example.CUSTOM_PERMISSION",
        ]
        res = analyze_permissions(
            declared_permissions=test_perms,
            package_name="com.sample.testapp",
            app_label="Sample Test App",
        )
        breakdown = res.get("permission_breakdown", {})
        self.assertIn("android.permission.INTERNET", breakdown.get("normal", []))
        self.assertIn("android.permission.RECEIVE_SMS", breakdown.get("dangerous", []))
        self.assertIn("android.permission.SYSTEM_ALERT_WINDOW", breakdown.get("suspicious", []))
        self.assertIn("android.permission.BIND_ACCESSIBILITY_SERVICE", breakdown.get("suspicious", []))
        self.assertIn("com.example.CUSTOM_PERMISSION", breakdown.get("custom", []))

        # Check MITRE matrix
        manifest = {"permissions": test_perms, "package_name": "com.sample.testapp"}
        matrix = build_mitre_attack_matrix(
            manifest=manifest,
            permission_analysis=res,
            observed_patterns={"sms_apis": 2, "shell_execution": 1},
        )
        technique_ids = [m["technique_id"] for m in matrix]
        self.assertIn("T1412", technique_ids)  # Capture SMS
        self.assertIn("T1411", technique_ids)  # Input Injection / Accessibility Overlay
        self.assertIn("T1429", technique_ids)  # Audio capture
        self.assertIn("T1432", technique_ids)  # Contact list

    def test_hardcoded_secrets_detection(self):
        """Test detection of Google API keys, AWS keys, JWTs, and private keys."""
        sample_strings = [
            "AIzaSyD-7Yabcdef1234567890abcdef12345678",  # Google API key (39 chars)
            "AKIAIOSFODNN7EXAMPLE",  # AWS access key
            "user.name@security-threat.net",  # Email
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # JWT
            "-----BEGIN RSA PRIVATE KEY-----",  # Private key
        ]
        sec = extract_secrets_and_credentials(sample_strings)
        self.assertGreaterEqual(len(sec["api_keys"]), 2)
        self.assertGreaterEqual(len(sec["emails"]), 1)
        self.assertGreaterEqual(len(sec["cloud_tokens"]), 1)
        self.assertGreaterEqual(len(sec["private_keys"]), 1)
        self.assertGreaterEqual(sec["secrets_found_count"], 5)

    def test_cloud_services_detection(self):
        """Test Firebase RTDB, S3 bucket, GCS, and Azure blob detection."""
        sample_urls = [
            "https://sample-test-db-default-rtdb.firebaseio.com",
            "https://my-threat-c2-bucket.s3.amazonaws.com/payload.apk",
            "https://storage.googleapis.com/malicious-dropper/loader.dex",
            "https://c2storage.blob.core.windows.net/data/exfil.json",
        ]
        cloud = detect_cloud_services(sample_urls)
        fb_urls = [e["endpoint"] for e in cloud["firebase_endpoints"]]
        cs_urls = [e["endpoint"] for e in cloud["cloud_storage_buckets"]]
        self.assertIn("https://sample-test-db-default-rtdb.firebaseio.com", fb_urls)
        self.assertTrue(any("my-threat-c2-bucket.s3.amazonaws.com" in u for u in cs_urls))
        self.assertTrue(any("storage.googleapis.com" in u for u in cs_urls))
        self.assertTrue(any("c2storage.blob.core.windows.net" in u for u in cs_urls))

    def test_overlay_accessibility_and_admin_analysis(self):
        """Test overlay attack, accessibility abuse, and device admin persistence detection."""
        manifest = {
            "permissions": [
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.BIND_DEVICE_ADMIN",
            ],
            "accessibility_services": ["com.threat.MyAccessibilityService"],
            "device_admin_receivers": ["com.threat.AdminReceiver"],
        }
        over = analyze_accessibility_and_overlay(manifest, ["android.accessibilityservice.AccessibilityService", "TYPE_APPLICATION_OVERLAY"])
        self.assertTrue(over["overlay_permission_granted"])
        self.assertTrue(over["accessibility_service_declared"])
        self.assertEqual(over["overlay_threat_level"], "CRITICAL")

        dadmin = analyze_device_admin(manifest, ["DevicePolicyManager", "lockNow", "wipeData"])
        self.assertTrue(dadmin["device_admin_declared"])
        self.assertTrue(any("lockNow" in a for a in dadmin["observed_admin_apis"]))
        self.assertTrue(any("wipeData" in a for a in dadmin["observed_admin_apis"]))

    def test_data_exfiltration_correlation(self):
        """Test exfiltration risk rating when sensitive sources and external sinks co-occur."""
        manifest = {"permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"]}
        code_patterns = {
            "sms_apis": ["SmsManager.getDefault()"],
            "network_apis": ["HttpURLConnection", "OkHttpClient"],
        }
        net_indicators = {"urls": [{"indicator": "http://198.51.100.55/upload"}], "ipv4": []}
        exfil = analyze_data_exfiltration(manifest, code_patterns, net_indicators)
        self.assertIn(exfil["exfiltration_risk_level"], ("HIGH", "CRITICAL"))
        self.assertIn("SMS Messages & 2FA Codes", exfil["sensitive_sources_accessed"])

    def test_unified_ioc_extraction(self):
        """Test unified IOC list building."""
        hashes = {"md5": "098f6bcd4621d373cade4e832627b4f6", "sha1": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}
        manifest = {"package_name": "com.threat.sample"}
        net = {
            "urls": [{"indicator": "https://threat-c2.net/gate.php"}],
            "ipv4": [{"indicator": "203.0.113.10"}],
            "domains": [{"indicator": "threat-c2.net"}],
        }
        cloud = {"cloud_storage_buckets": [{"endpoint": "https://c2-bucket.s3.amazonaws.com"}]}
        iocs = build_unified_ioc_list(hashes, manifest, net, cloud, [])
        self.assertEqual(iocs["hashes"]["sha256"], hashes["sha256"])
        self.assertIn("threat-c2.net", iocs["domains"])
        self.assertIn("https://threat-c2.net/gate.php", iocs["urls"])
        self.assertIn("203.0.113.10", iocs["ipv4_addresses"])
        self.assertIn("com.threat.sample", iocs["package_names"])
        self.assertTrue(any("c2-bucket.s3.amazonaws.com" in c for c in iocs["cloud_infrastructure"]))

    def test_dynamic_environment_check(self):
        """Test dynamic environment inspects ADB and emulators without raising errors."""
        env = check_dynamic_environment()
        self.assertIn("adb_installed", env)
        self.assertIn("connected_devices_count", env)
        self.assertIn("ready", env)

    def test_package_name_input_validation(self):
        """Test strict Android package name validation against injection and malformed strings."""
        # Valid package names
        valid_pkgs = [
            "com.example.app",
            "org.telegram.messenger",
            "com.google.android.apps.messaging",
            "in.gov.cybercrime.reporting",
            "com.test_app_123.tool_4",
        ]
        for pkg in valid_pkgs:
            self.assertTrue(is_valid_package_name(pkg), f"Should be valid: {pkg}")
            self.assertEqual(validate_package_name(pkg), pkg)

        # Malicious / command injection / malformed package names
        invalid_pkgs = [
            "com.example.app; rm -rf /",
            "com.example.app && echo pwned",
            "com.example | cat /etc/passwd",
            "`reboot`",
            "com.example.app$(whoami)",
            "com.example app",
            "com.example.app\n",
            "singleword",
            "-com.flag.injection",
            "",
            None,
            12345,
            "a" * 300,
        ]
        for bad in invalid_pkgs:
            self.assertFalse(is_valid_package_name(bad), f"Should be invalid: {bad}")
            with self.assertRaises(ValueError):
                validate_package_name(bad)

        # Inspect package rejects invalid package format gracefully
        err_inspect = inspect_package("com.evil; reboot")
        self.assertEqual(err_inspect.get("status"), "ERROR")
        self.assertIn("Invalid package name", err_inspect.get("error", ""))

        # Pull package rejects invalid package format gracefully
        err_pull = pull_application_apk("com.evil; rm -rf /", self.case_dir)
        self.assertEqual(err_pull.get("status"), "ERROR")
        self.assertIn("Invalid package name", err_pull.get("error", ""))

    def test_apk_path_validation(self):
        """Test APK path validation ensures file existence and .apk suffix."""
        # Non-existent file
        with self.assertRaises(FileNotFoundError):
            validate_apk_path(self.base_path / "non_existent.apk")

        # Non-apk file extension
        text_file = self.base_path / "notes.txt"
        text_file.write_text("not an apk")
        with self.assertRaises(ValueError):
            validate_apk_path(text_file)

        # Valid APK file
        fake_apk = self.base_path / "sample.apk"
        fake_apk.write_bytes(b"PK\x03\x04test_apk_content")
        valid_path = validate_apk_path(fake_apk)
        self.assertEqual(valid_path, fake_apk.resolve())


if __name__ == "__main__":
    unittest.main()
