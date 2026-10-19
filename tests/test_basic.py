"""
DroidSleuth Unit Test Suite
Covers cryptographic hashing, case management, permission threat scoring,
synthetic APK analysis, network IOC extraction, SMS parsing, timeline sorting,
and forensic report generation.
"""

import os
import sys
import json
import zipfile
import tempfile
import unittest
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from modules.case_manager import (
    calculate_hashes,
    init_case,
    record_evidence_file,
    verify_case_hashes,
)
from modules.permission_analysis import (
    analyze_permissions,
    COMBINATION_RULES,
)
from modules.apk_analysis import (
    analyze_apk,
    extract_indicators_from_strings,
    extract_raw_printable_strings,
)
from modules.network_analysis import (
    analyze_network_evidence,
    is_private_ip,
)
from modules.sms_analysis import (
    parse_sms_xml_backup,
    analyze_sms_messages,
)
from modules.timeline import (
    normalize_iso_timestamp,
    build_incident_timeline,
)
from modules.reporting import (
    generate_markdown_report,
    generate_pdf_report,
    REPORTLAB_AVAILABLE,
)


class TestDroidSleuthCore(unittest.TestCase):
    """Test suite for DroidSleuth core forensic components."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.temp_dir.name)
        os.environ["DROIDSLEUTH_ACTIVE_CASE"] = str(self.base_path / ".test_active_case")
        os.environ["DROIDSLEUTH_CASES_DIR"] = str(self.base_path)

    def tearDown(self):
        os.environ.pop("DROIDSLEUTH_ACTIVE_CASE", None)
        os.environ.pop("DROIDSLEUTH_CASES_DIR", None)
        self.temp_dir.cleanup()

    def test_hashing_correctness(self):
        """Test SHA-256, SHA-1, MD5 and byte size calculations against known values."""
        test_file = self.base_path / "sample_evidence.bin"
        content = b"DroidSleuth Forensic Test Payload\n"
        test_file.write_bytes(content)

        res = calculate_hashes(test_file)
        self.assertEqual(res["size_bytes"], len(content))
        self.assertEqual(len(res["sha256"]), 64)
        self.assertEqual(len(res["sha1"]), 40)
        self.assertEqual(len(res["md5"]), 32)

    def test_case_initialization_and_verification(self):
        """Test case creation, evidence preservation, and cryptographic hash verification."""
        case_dir = init_case(
            description="Unit Test Case",
            investigator="Test Investigator",
            device_identifier="Virtual Test Android",
            base_dir=self.base_path,
        )

        self.assertTrue((case_dir / "case.json").exists())
        self.assertTrue((case_dir / "hashes" / "evidence_hashes.json").exists())

        # Create dummy evidence and record it
        dummy_file = self.base_path / "logcat.txt"
        dummy_file.write_text("ActivityManager: Starting intent...\n", encoding="utf-8")

        preserved = record_evidence_file(
            case_dir=case_dir,
            source_file=dummy_file,
            target_subfolder="device_logs",
            description="Test logcat file",
        )
        self.assertTrue(preserved.exists())

        # Verify hashes
        verifications = verify_case_hashes(case_dir)
        self.assertEqual(len(verifications), 1)
        self.assertEqual(verifications[0]["status"], "VERIFIED")

        # Simulate tampering
        with open(preserved, "a", encoding="utf-8") as f:
            f.write("TAMPERED DATA INSERTION\n")

        tampered_verify = verify_case_hashes(case_dir)
        self.assertEqual(tampered_verify[0]["status"], "CORRUPTED_OR_TAMPERED")

    def test_permission_threat_scoring(self):
        """Test detection of dangerous permissions and malicious combination patterns."""
        # Banking Trojan combination
        trojan_perms = [
            "android.permission.INTERNET",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ]
        res = analyze_permissions(trojan_perms)
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertEqual(res["overall_severity"], "CRITICAL")
        self.assertIn("ACCESSIBILITY_HIJACK", res["capabilities"])
        self.assertIn("OVERLAY_ATTACK", res["capabilities"])

        matched_names = [p["name"] for p in res["matched_threat_patterns"]]
        self.assertIn("Banking Trojan / Overlay Phishing Pattern", matched_names)

        # Benign / Minimal permissions
        benign_perms = ["android.permission.INTERNET", "android.permission.VIBRATE"]
        res_benign = analyze_permissions(benign_perms)
        self.assertLess(res_benign["risk_score"], 20)
        self.assertEqual(res_benign["overall_severity"], "LOW")

    def test_private_ip_detection(self):
        """Test accurate filtering of private RFC1918 and loopback IPs."""
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertTrue(is_private_ip("192.168.1.100"))
        self.assertTrue(is_private_ip("10.0.0.5"))
        self.assertTrue(is_private_ip("172.16.0.1"))
        self.assertFalse(is_private_ip("185.220.101.5"))
        self.assertFalse(is_private_ip("8.8.8.8"))

    def test_string_indicator_extraction(self):
        """Test extraction and deduplication of IPs, domains, and URLs from strings."""
        sample_corpus = [
            "Connecting to http://185.220.101.5:8080/c2/endpoint",
            "Resolving malicious domain evil-c2-server.top",
            "Ignored Android schema http://schemas.android.com/apk/res/android",
            "Local loopback 127.0.0.1 should not be flagged",
        ]
        indicators = extract_indicators_from_strings(sample_corpus, source_name="Test")
        self.assertTrue(any("185.220.101.5" in item["indicator"] for item in indicators["urls"]))
        self.assertTrue(any("185.220.101.5" in item["indicator"] for item in indicators["ipv4"]))
        self.assertTrue(any("evil-c2-server.top" in item["indicator"] for item in indicators["domains"]))
        # Verify schema filtering
        self.assertFalse(any("schemas.android.com" in item["indicator"] for item in indicators["urls"]))

    def test_synthetic_apk_static_analysis(self):
        """Test APK analysis engine on a synthetic APK file with embedded assets and bytecode."""
        apk_path = self.base_path / "suspect_app.apk"

        # Build synthetic APK zip
        with zipfile.ZipFile(apk_path, "w") as z:
            # Add synthetic AndroidManifest strings
            z.writestr(
                "AndroidManifest.xml",
                b"\x03\x00\x08\x00" + b"android.permission.SEND_SMS android.permission.RECEIVE_BOOT_COMPLETED"
            )
            # Add synthetic classes.dex with C2 strings
            dex_content = (
                b"dex\n035\0"
                b"Lcom/malware/dropper/Payload;\0"
                b"http://194.26.29.112/stage2.apk\0"
                b"DexClassLoader\0"
                b"Runtime.getRuntime().exec\0"
            )
            z.writestr("classes.dex", dex_content)
            z.writestr("assets/config.json", b'{"c2_host": "https://c2-mobile-sync.xyz/gate"}')

        analysis_dir = self.base_path / "analysis"
        res = analyze_apk(apk_path, output_analysis_dir=analysis_dir)

        self.assertIn("hashes", res)
        self.assertEqual(res["hashes"]["size_bytes"], apk_path.stat().st_size)
        self.assertIn("classes.dex", res["embedded_files"]["dex_files"])

        # Check observed code patterns
        patterns = res["observed_patterns"]
        self.assertTrue(any("DexClassLoader" in p for p in patterns.get("dynamic_code_loading", [])))
        self.assertTrue(any("Runtime.getRuntime" in p for p in patterns.get("command_execution", [])))

        # Check network indicators
        urls = [u["indicator"] for u in res["network_indicators"]["urls"]]
        self.assertTrue(any("194.26.29.112" in u for u in urls))

    def test_network_text_log_analysis(self):
        """Test network analysis on a synthetic network log."""
        net_log = self.base_path / "dns_queries.log"
        net_log.write_text(
            "2026-10-20 02:00:01 192.168.1.50 -> 185.220.101.5 HTTP GET http://185.220.101.5/beacon.php\n"
            "2026-10-20 02:00:05 DNS query for api-verify-security.top resolved to 45.154.255.89\n",
            encoding="utf-8",
        )

        res = analyze_network_evidence(net_log)
        self.assertEqual(res["status"], "SUCCESS")
        indicators = [i["indicator"] for i in res["indicators"]]
        self.assertTrue(any("185.220.101.5" in ind for ind in indicators))
        self.assertTrue(any("api-verify-security.top" in ind for ind in indicators))

    def test_sms_xml_parsing_and_analysis(self):
        """Test parsing of SMS backup XML files and detection of 2FA/phishing links."""
        sms_file = self.base_path / "sms_backup.xml"
        sms_file.write_text(
            "<smses count='2'>"
            "  <sms address='+18005550199' date='1760918400000' type='1' body='ALERT: Chase account locked. Verify: https://bit.ly/chase-fake' />"
            "  <sms address='22000' date='1760918500000' type='1' body='Your Google security code is 918234' />"
            "</smses>",
            encoding="utf-8",
        )

        messages = parse_sms_xml_backup(sms_file)
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[0]["direction"], "INBOX")

        analysis = analyze_sms_messages(messages)
        self.assertEqual(analysis["total_messages"], 2)
        self.assertEqual(analysis["flagged_messages_count"], 2)
        self.assertEqual(analysis["extracted_urls_count"], 1)

    def test_timeline_sorting_and_normalization(self):
        """Test timeline timestamp normalization and chronological sorting."""
        ts_norm, note = normalize_iso_timestamp("2026-10-20 02:30:00")
        self.assertTrue(ts_norm.startswith("2026-10-20T02:30:00"))

        ts_epoch, _ = normalize_iso_timestamp("1760918400000")
        self.assertTrue(ts_epoch.startswith("2025") or ts_epoch.startswith("2026"))

        # Verify handling of missing timestamp
        ts_none, note_none = normalize_iso_timestamp("Unknown")
        self.assertEqual(ts_none, "0000-00-00T00:00:00Z")
        self.assertIn("missing", note_none)

    def test_report_generation_markdown_and_pdf(self):
        """Test generation of both Markdown and PDF forensic reports."""
        case_dir = init_case(
            description="Full Test Investigation Report",
            investigator="Dr. Forensics",
            device_identifier="Samsung Galaxy S22",
            base_dir=self.base_path,
        )

        # Generate Markdown report
        md_path = generate_markdown_report(case_dir)
        self.assertTrue(md_path.exists())
        content = md_path.read_text(encoding="utf-8")

        # Verify key sections exist
        self.assertIn("1. Case Summary", content)
        self.assertIn("2. Scope and Authorization Notes", content)
        self.assertIn("4. Evidence Inventory & Chain of Custody", content)
        self.assertIn("5. Cryptographic Hash Manifest", content)
        self.assertIn("12. Chronological Incident Timeline", content)
        self.assertIn("15. Recommended Defensive Actions", content)

        # Generate PDF report if ReportLab is installed
        if REPORTLAB_AVAILABLE:
            pdf_path, err = generate_pdf_report(case_dir)
            self.assertIsNotNone(pdf_path)
            self.assertIsNone(err)
            self.assertTrue(pdf_path.exists())
            self.assertGreater(pdf_path.stat().st_size, 1000)


if __name__ == "__main__":
    unittest.main()
