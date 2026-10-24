#!/usr/bin/env python3
"""
AScanner Hybrid Android APK Static Inspector & Malware Classifier
Uses a multi-source machine learning model trained on 25,722 applications
(AndroZoo + Drebin datasets) alongside static forensic indicator extraction.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import shutil
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

# Suppress verbose debug logs from third-party libraries
try:
    from loguru import logger
    logger.remove()
except Exception:
    pass

try:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX
    from joblib import load
except ImportError as exc:
    sys.exit(f"Missing dependency: {exc}")

BASE = Path(__file__).resolve().parent
REPORT_DIR = BASE / "reports"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def load_ml_model(base_dir: Path):
    """
    Safely load trained XGBoost model.
    Prefers native JSON format (no arbitrary code execution risk).
    When loading joblib, verifies cryptographic SHA-256 against recorded metadata.
    """
    native_json = base_dir / "andromalhut_xgboost.json"
    meta_path = base_dir / "andromalhut_model_metadata.json"
    eval_path = base_dir / "evaluation.json"

    meta = {}
    if meta_path.exists():
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    elif eval_path.exists():
        try:
            meta = json.loads(eval_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 1. Native XGBoost JSON (Safe deserialization)
    if native_json.exists():
        try:
            import xgboost as xgb
            model = xgb.XGBClassifier()
            model.load_model(str(native_json))
            features = meta.get("features", [])
            canonical_features = meta.get("canonical_features", features)
            total_samples = meta.get("total_samples", meta.get("datasets", {}).get("deduplicated_samples_total", 11696))
            return model, features, canonical_features, total_samples, "XGBoost Native JSON (Safe)"
        except Exception as e:
            print(f"[!] Warning: Failed loading native JSON model, falling back to joblib: {e}", file=sys.stderr)

    # 2. Joblib candidates with cryptographic checksum verification
    joblib_candidates = [
        base_dir / "andromalhut_xgboost.joblib",
        base_dir / "drebin_rf.joblib",
    ]
    for jc in joblib_candidates:
        if jc.exists():
            expected_sha = None
            if meta:
                artifacts = meta.get("model_artifacts", {})
                for art in artifacts.values():
                    if art.get("file") == jc.name:
                        expected_sha = art.get("sha256")
                        break
            actual_sha = sha256_file(jc)
            if expected_sha and actual_sha != expected_sha:
                raise ValueError(
                    f"Security Alert: Model file {jc.name} SHA-256 mismatch! "
                    f"Expected {expected_sha}, got {actual_sha}"
                )
            saved = load(jc)
            model = saved["model"]
            features = saved.get("features", meta.get("features", []))
            canonical_features = saved.get("canonical_features", meta.get("canonical_features", features))
            total_samples = saved.get("total_samples", meta.get("total_samples", 11696))
            return model, features, canonical_features, total_samples, f"Joblib (SHA256: {actual_sha[:10]}...)"

    raise FileNotFoundError(f"No valid model artifacts found in {base_dir}")



def canon_name(name: str) -> str:
    n = name.strip()
    for prefix in ['android.permission.', 'permission.', 'com.android.browser.permission.']:
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n.upper()


def extract_features_from_apk(apk_path: Path):
    """Extract declared permissions, intent actions, and verified sensitive code APIs using authoritative aapt & DEX."""
    apk_path = Path(apk_path).resolve()
    package = ""
    app_name = ""
    version_name = ""
    version_code = ""
    permissions = []
    dex_count = 0
    parsing_status = "SUCCESS"
    parsing_error = None

    perms_set = set()
    intents_set = set()
    sensitive_code_apis = set()
    all_observed_strings = set()

    # Step 1: Authoritative AAPT extraction (rock solid on all modern Android APKs)
    aapt_bin = shutil.which("aapt") or "/usr/bin/aapt"
    if os.path.exists(aapt_bin):
        try:
            badging_proc = subprocess.run(
                [aapt_bin, "dump", "badging", str(apk_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if badging_proc.returncode == 0:
                for line in badging_proc.stdout.splitlines():
                    if line.startswith("package:"):
                        m_pkg = re.search(r"name='([^']+)'", line)
                        if m_pkg:
                            package = m_pkg.group(1)
                        m_vname = re.search(r"versionName='([^']+)'", line)
                        if m_vname:
                            version_name = m_vname.group(1)
                        m_vcode = re.search(r"versionCode='([^']+)'", line)
                        if m_vcode:
                            version_code = m_vcode.group(1)
                    elif "application-label:" in line:
                        m_app = re.search(r"application-label(?:-[a-zA-Z]+)?:'([^']+)'", line)
                        if m_app and not app_name:
                            app_name = m_app.group(1)
                    elif line.startswith("uses-permission:"):
                        m_perm = re.search(r"name='([^']+)'", line)
                        if m_perm:
                            p = m_perm.group(1).strip()
                            permissions.append(p)
                            perms_set.add(canon_name(p))

                # Intent filters and components from xmltree
                xmltree_proc = subprocess.run(
                    [aapt_bin, "dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if xmltree_proc.returncode == 0:
                    for m in re.finditer(r'android:name\(0x[0-9a-f]+\)=\"([^\"]+)\"', xmltree_proc.stdout):
                        val = m.group(1).strip()
                        if "permission" in val.lower():
                            perms_set.add(canon_name(val))
                        elif "action" in val.lower() or "intent" in val.lower():
                            intents_set.add(canon_name(val))
        except Exception as e:
            parsing_error = f"AAPT extraction warning: {e}"

    # Step 2: Fallback to Androguard or raw AndroidManifest.xml if AAPT didn't get permissions
    if not perms_set:
        try:
            a = APK(str(apk_path))
            package = package or str(a.get_package() or "")
            app_name = app_name or str(a.get_app_name() or "")
            version_name = version_name or str(a.get_androidversion_name() or "")
            version_code = version_code or str(a.get_androidversion_code() or "")
            for p in (a.get_permissions() or []):
                permissions.append(p)
                perms_set.add(canon_name(p))
            try:
                for tag in a.get_android_manifest_xml().iter():
                    name = tag.attrib.get('{http://schemas.android.com/apk/res/android}name')
                    if name:
                        if 'permission' in name:
                            perms_set.add(canon_name(name))
                        elif 'intent.action' in name:
                            intents_set.add(canon_name(name))
            except Exception:
                pass
        except Exception as exc:
            parsing_status = "FALLBACK_PARSED"
            parsing_error = str(exc)

    if not perms_set:
        try:
            with zipfile.ZipFile(str(apk_path), "r") as z:
                if "AndroidManifest.xml" in z.namelist():
                    raw_xml = z.read("AndroidManifest.xml").decode("latin1", errors="ignore")
                    for p in re.findall(r"android\.permission\.[A-Za-z0-9_]+", raw_xml):
                        permissions.append(p)
                        perms_set.add(canon_name(p))
                for n in z.namelist():
                    if n.endswith(".dex"):
                        dex_raw = z.read(n).decode("latin1", errors="ignore")
                        if "DexClassLoader" in dex_raw:
                            sensitive_code_apis.add("DEXCLASSLOADER")
                        if "Runtime" in dex_raw and "exec" in dex_raw:
                            sensitive_code_apis.add("EXEC")
                            sensitive_code_apis.add("RUNTIME.EXEC")
                        if "getDeviceId" in dex_raw:
                            sensitive_code_apis.add("GETDEVICEID")
                            sensitive_code_apis.add("TELEPHONYMANAGER.GETDEVICEID")
                        if "SmsManager" in dex_raw or "sendTextMessage" in dex_raw:
                            sensitive_code_apis.add("SENDTEXTMESSAGE")
                            sensitive_code_apis.add("SMSMANAGER.SENDTEXTMESSAGE")
            if perms_set:
                parsing_status = "FALLBACK_PARSED"
        except Exception:
            pass

    # Step 3: Count DEX files and inspect bytecode code APIs safely
    try:
        with zipfile.ZipFile(str(apk_path), "r") as z:
            dex_names = [name for name in z.namelist() if name.endswith(".dex")]
            dex_count = len(dex_names)
    except Exception:
        dex_count = 1

    # Check sensitive APIs using Androguard or raw scan
    try:
        a = APK(str(apk_path))
        dex_list = a.get_all_dex()
        for d in dex_list:
            try:
                dex = DEX(d)
                for m in dex.get_methods():
                    mname = f"{m.get_class_name()}->{m.get_name()}"
                    if 'DexClassLoader' in mname:
                        sensitive_code_apis.add('DEXCLASSLOADER')
                    if 'Runtime' in mname and 'exec' in mname:
                        sensitive_code_apis.add('EXEC')
                        sensitive_code_apis.add('RUNTIME.EXEC')
                    if 'getDeviceId' in mname:
                        sensitive_code_apis.add('GETDEVICEID')
                        sensitive_code_apis.add('TELEPHONYMANAGER.GETDEVICEID')
                    if 'getSubscriberId' in mname:
                        sensitive_code_apis.add('GETSUBSCRIBERID')
                        sensitive_code_apis.add('TELEPHONYMANAGER.GETSUBSCRIBERID')
                    if 'sendTextMessage' in mname:
                        sensitive_code_apis.add('SENDTEXTMESSAGE')
                        sensitive_code_apis.add('SMSMANAGER.SENDTEXTMESSAGE')
            except Exception:
                pass
    except Exception:
        pass

    if not package:
        package = apk_path.stem

    permissions = sorted(set(permissions))
    return {
        "package": package,
        "app_name": app_name or package,
        "version_name": version_name,
        "version_code": version_code,
        "permissions": permissions,
        "perms_set": perms_set,
        "intents_set": intents_set,
        "sensitive_code_apis": sensitive_code_apis,
        "observed_strings_count": len(all_observed_strings),
        "dex_files": dex_count,
        "parsing_status": parsing_status,
        "parsing_error": parsing_error
    }


def main():
    parser = argparse.ArgumentParser(
        description="Static Android APK inspection and calibrated malware classifier"
    )
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("--installer", default=None, help="Installer package name from dumpsys")
    parser.add_argument("--source", default=None, help="Download source description")
    parser.add_argument("--online", action="store_true", default=False, help="Opt-in to online lookups (Google Play, CIRCL, VirusTotal)")
    args = parser.parse_args()

    apk_path = Path(args.apk).expanduser().resolve()
    if not apk_path.is_file():
        sys.exit(f"ERROR: APK not found: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        sys.exit("ERROR: Input must have an .apk extension")

    digest = sha256_file(apk_path)
    data = extract_features_from_apk(apk_path)
    perms_set = data["perms_set"]
    intents_set = data["intents_set"]
    code_apis = data["sensitive_code_apis"]

    # Extract signing certificate for cryptographic identity verification
    cert_verified_clean = False
    cert_fp = None
    try:
        from modules.apk_analysis import extract_apk_signing_info
        from modules.online_verifier import KNOWN_VENDOR_CERTIFICATES, verify_package_online
        cert_info = extract_apk_signing_info(apk_path)
        for cert in cert_info.get("certificates", []):
            fp = cert.get("fingerprint_sha256")
            if fp:
                cert_fp = fp
                pkg_key = data.get("package", "")
                known_fps = [kfp.lower().replace(":", "").strip() for kfp in KNOWN_VENDOR_CERTIFICATES.get(pkg_key, [])]
                if fp.lower().replace(":", "").strip() in known_fps:
                    cert_verified_clean = True
                    break
    except Exception:
        pass

    # Optional online lookups (strictly opt-in via --online)
    online_info = None
    if args.online:
        try:
            from modules.online_verifier import verify_package_online
            online_info = verify_package_online(data.get("package", ""), digest, cert_fingerprint=cert_fp, online=True)
            if online_info.get("identity_status") == "VERIFIED":
                cert_verified_clean = True
        except Exception as e:
            print(f"[!] Warning: Online lookup failed: {e}", file=sys.stderr)

    # Resolve installer and provenance context from args or evidence directory
    pkg_name = data.get("package", "")
    installer = args.installer
    source = args.source

    if not installer and not source:
        for parent_cand in [apk_path.parent.parent.parent, apk_path.parent.parent]:
            meta_cand = parent_cand / "evidence" / "device_inventory" / f"package_meta_{pkg_name}.json"
            if meta_cand.exists():
                try:
                    mdata = json.loads(meta_cand.read_text(encoding="utf-8"))
                    dmeta = mdata.get("dumpsys_metadata", {})
                    installer = dmeta.get("installer_package")
                    source = dmeta.get("download_source")
                    break
                except Exception:
                    pass

    # Authoritative determination of official Google Play Store provenance
    # SECURITY RULE: Package name alone or BILLING permission must NEVER force benign!
    # Only a cryptographic signing certificate match can prove authorized identity.
    is_play_store = bool(cert_verified_clean)

    # Detect hardware acceleration engine
    gpu_device_label = "CPU Execution Engine"
    try:
        smi = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True, text=True)
        if smi.returncode == 0 and smi.stdout.strip():
            gpu_device_label = f"NVIDIA CUDA GPU ({smi.stdout.strip().splitlines()[0]})"
    except Exception:
        pass

    # Load model securely
    try:
        model, feature_names, canonical_features, total_samples, model_source_desc = load_ml_model(BASE)
    except Exception as e:
        sys.exit(f"ERROR: Failed loading ML model: {e}")

    # Construct feature row matching the model's schema
    row = {}
    for feat in canonical_features:
        # Match permissions and intents strictly against actual declared capabilities
        val = 1 if (feat in perms_set or feat in intents_set) else 0
        row[feat] = val

    # Interaction risk indicators matching trained feature set
    row['RISK_SMS_BOOT'] = 1 if ((row.get('SEND_SMS', 0) or row.get('READ_SMS', 0) or row.get('RECEIVE_SMS', 0)) and row.get('RECEIVE_BOOT_COMPLETED', 0)) else 0
    row['RISK_COVERT_SPYWARE'] = 1 if ((row.get('RECORD_AUDIO', 0) or row.get('CAMERA', 0)) and row.get('READ_CALL_LOG', 0) and (row.get('READ_CONTACTS', 0) or row.get('READ_SMS', 0))) else 0
    row['RISK_OVERLAY_ACCESS'] = 1 if (row.get('SYSTEM_ALERT_WINDOW', 0) and (row.get('BIND_ACCESSIBILITY_SERVICE', 0) or row.get('RECEIVE_BOOT_COMPLETED', 0) or row.get('REQUEST_INSTALL_PACKAGES', 0))) else 0
    row['RISK_DEVICE_TAKEOVER'] = 1 if (row.get('BIND_DEVICE_ADMIN', 0) or row.get('BIND_ACCESSIBILITY_SERVICE', 0)) else 0

    df_row = pd.DataFrame([row], columns=feature_names).fillna(0)

    # Inference (suppressing mismatched device warnings for single-row CLI triage)
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        probabilities = model.predict_proba(df_row)[0]
    prob_malware = float(probabilities[1])
    prob_benign = float(probabilities[0])

    # Dynamic verdict determined purely by model probability distribution
    # Dynamic verdict determined purely by model probability distribution
    if prob_malware >= 0.65:
        verdict = "MALICIOUS"
        classification = "MALWARE"
    elif prob_malware >= 0.50:
        verdict = "SUSPICIOUS"
        classification = "SUSPICIOUS"
    else:
        verdict = "BENIGN"
        classification = "BENIGN"

    # Contextual calibration: cryptographically verified applications without high-confidence signals are benign
    if cert_verified_clean and prob_malware < 0.65:
        verdict = "BENIGN"
        classification = "BENIGN"

    # Explainable behavioral interaction risk patterns
    behavioral_risk_flags = []
    if row.get('RISK_OVERLAY_ACCESS'):
        behavioral_risk_flags.append("Banking Overlay / Accessibility Hijacking pattern detected")
    if row.get('RISK_COVERT_SPYWARE'):
        behavioral_risk_flags.append("Covert surveillance pattern detected (microphone/camera + call logs + contacts/SMS)")
    if row.get('RISK_DEVICE_TAKEOVER'):
        behavioral_risk_flags.append("Device Admin / Accessibility takeover privileges requested")
    if row.get('RISK_SMS_BOOT'):
        behavioral_risk_flags.append("SMS Exfiltration / 2FA Interception with Boot persistence")

    # Forensic override: elevate benign verdict to SUSPICIOUS when critical takeover or surveillance patterns are present
    if verdict == "BENIGN" and (row.get('RISK_OVERLAY_ACCESS') or row.get('RISK_DEVICE_TAKEOVER') or row.get('RISK_COVERT_SPYWARE')):
        verdict = "SUSPICIOUS"
        classification = "SUSPICIOUS"

    # Identify active threat indicators (strictly from genuine declared capabilities)
    active_indicators = [k for k, v in row.items() if v == 1]
    highlighted_threats = list(behavioral_risk_flags)
    if 'SYSTEM_ALERT_WINDOW' in perms_set:
        highlighted_threats.append("Draw Overlays (SYSTEM_ALERT_WINDOW) requested")
    if 'BIND_ACCESSIBILITY_SERVICE' in perms_set:
        highlighted_threats.append("Full Accessibility Service (keylogging/UI automation) binding requested")
    if 'BIND_DEVICE_ADMIN' in perms_set:
        highlighted_threats.append("Device Admin Privileges (anti-uninstall / lock / wipe)")
    if row.get('RISK_SMS_BOOT'):
        if verdict in ("MALICIOUS", "SUSPICIOUS") and not is_play_store:
            highlighted_threats.append("SMS Exfiltration / 2FA Interception with Boot persistence")
        else:
            highlighted_threats.append("Standard SMS 2FA / OTP Verification capability with Boot persistence")
    if ('EXEC' in code_apis or 'RUNTIME.EXEC' in code_apis) and verdict in ("MALICIOUS", "SUSPICIOUS"):
        highlighted_threats.append("Arbitrary command execution runtime calls detected")
    if 'DEXCLASSLOADER' in code_apis and verdict in ("MALICIOUS", "SUSPICIOUS"):
        highlighted_threats.append("Dynamic code loading (DexClassLoader / dropped payload execution)")

    evidence_quality = "HIGH" if data["parsing_status"] == "SUCCESS" else "MODERATE"
    reason = (
        f"Multi-source ML model ({gpu_device_label}) predicts {prob_malware:.1%} malware probability "
        f"based on {len(active_indicators)} matched capability features across {total_samples:,} training samples."
    )

    limitations = [
        "Static indicators and model predictions assess behavioral potential, not dynamic execution proof.",
        "OEM pre-installed system applications may request high-privilege permissions legitimately.",
        "Heuristic analysis should be corroborated with sandbox runtime observation when available."
    ]

    report = {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "file": str(apk_path),
        "sha256": digest,
        "analysis_mode": "static; multi-source ML triage (AndroZoo + Drebin)",
        "hardware_engine": gpu_device_label,
        "package": data["package"],
        "app_name": data["app_name"],
        "version_name": data["version_name"],
        "version_code": data["version_code"],
        "permissions": data["permissions"],
        "permission_count": len(data["permissions"]),
        "dex_files": data["dex_files"],
        "parsing_status": data["parsing_status"],
        "classification": classification,
        "feature_presence_preview": {k: v for k, v in row.items() if v == 1},
        "maliciousness_assessment": {
            "verdict": verdict,
            "maliciousness_probability": round(prob_malware, 4),
            "benign_probability": round(prob_benign, 4),
            "probability_status": "AVAILABLE",
            "evidence_quality": evidence_quality,
            "reason": reason,
            "highlighted_threats": highlighted_threats,
            "behavioral_risk_flags": behavioral_risk_flags,
            "active_feature_count": len(active_indicators),
            "limitations": limitations
        }
    }

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", apk_path.stem)
    report_path = REPORT_DIR / f"{stem}_{stamp}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\n" + "=" * 60)
    print("     ANDROMALHUT STATIC APK INSPECTION & MALWARE TRIAGE")
    print("=" * 60)
    print(f"File             : {apk_path.name}")
    print(f"SHA-256          : {digest}")
    print(f"Package          : {data['package'] or 'Unknown'}")
    print(f"App Name         : {data['app_name'] or 'Unknown'}")
    print(f"Permissions      : {len(data['permissions'])}")
    print(f"DEX Files        : {data['dex_files']}")
    print(f"Status           : {data['parsing_status']}")
    print(f"Execution Engine : {gpu_device_label}")

    print("\n" + "-" * 60)
    print("         MACHINE LEARNING MALICIOUSNESS ASSESSMENT")
    print("-" * 60)
    print(f"Verdict              : {verdict}")
    print(f"Malware Probability  : {prob_malware:.1%}")
    print(f"Classification       : {classification}")
    print(f"Evidence Quality     : {evidence_quality}")
    print(f"Active Features      : {len(active_indicators)}")
    if highlighted_threats:
        print("\nHighlighted Threat Patterns:")
        for t in highlighted_threats:
            print(f"  [!] {t}")
    print(f"\nReport JSON: {report_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
