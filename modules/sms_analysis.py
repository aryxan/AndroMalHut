"""
DroidSleuth SMS Analysis & Import Module
Imports and normalizes SMS message evidence from XML backups, JSON, and CSV exports.
Detects 2FA/OTP interception indicators, phishing URLs, bank fraud lures, and toll fraud.
"""

import os
import re
import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import record_evidence_file, log_case_action
from modules.device_inventory import select_device, run_adb_command


def attempt_adb_sms_export(
    case_dir: Path,
    serial: Optional[str] = None,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Attempt direct authorized ADB export of SMS messages via content provider.
    
    Clearly explains Android permissions and non-rooted limitations when blocked.
    """
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    # Attempt content query
    code, stdout, stderr = run_adb_command(
        ["shell", "content", "query", "--uri", "content://sms", "--projection", "address,date,type,body"],
        target_serial,
        timeout=15,
    )

    if code != 0 or "SecurityException" in stderr or "Permission Denial" in stderr or not stdout.strip():
        reason = (
            "Direct SMS content provider query ('content://sms') was denied by Android security policy. "
            "Modern Android versions (KitKat 4.4+) enforce strict runtime isolation, allowing only the designated "
            "Default SMS Application or root privileges to read the Telephony provider directly over ADB. "
            "Forensic recommendation: Use the 'Import SMS Backup' feature to ingest an authorized SMS Backup & Restore "
            "XML/JSON export, an ADB backup (.ab), or an extraction from a mobile forensic suite (Cellebrite/Oxygen)."
        )
        log_case_action(case_dir, "SMS_EXPORT_RESTRICTED", "Direct ADB SMS export restricted by Android OS", operator)
        return {
            "status": "RESTRICTED",
            "reason": reason,
            "raw_stderr": stderr.strip(),
            "exported_count": 0,
        }

    # If accessible (e.g. older Android or test environment)
    temp_dir = case_dir / "evidence" / "sms_exports" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_file = temp_dir / "adb_sms_export_raw.txt"
    temp_file.write_text(stdout, encoding="utf-8")

    preserved = record_evidence_file(
        case_dir=case_dir,
        source_file=temp_file,
        target_subfolder="sms_exports",
        description=f"Direct ADB content query SMS export from device {target_serial}",
        operator=operator,
    )

    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "status": "SUCCESS",
        "preserved_path": str(preserved),
        "exported_count": len(stdout.strip().splitlines()),
    }


def parse_sms_xml_backup(xml_path: Path) -> List[Dict[str, Any]]:
    """Parse SMS Backup & Restore XML schema."""
    messages = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for elem in root.findall(".//sms"):
            address = elem.get("address", "Unknown")
            date_epoch_str = elem.get("date", "0")
            msg_type = elem.get("type", "1")  # 1: Inbox, 2: Sent
            body = elem.get("body", "")

            # Convert millisecond epoch to ISO UTC
            try:
                date_epoch = int(date_epoch_str) / 1000.0
                dt = datetime.fromtimestamp(date_epoch, tz=timezone.utc)
                ts_utc = dt.isoformat()
            except Exception:
                ts_utc = "Unknown"

            direction = "INBOX" if msg_type == "1" else ("SENT" if msg_type == "2" else f"TYPE_{msg_type}")

            messages.append({
                "timestamp_utc": ts_utc,
                "original_epoch_ms": date_epoch_str,
                "sender_recipient": address,
                "direction": direction,
                "body": body,
                "source_file": xml_path.name,
            })
    except Exception as e:
        print(f"[!] Warning parsing SMS XML: {e}")

    return messages


def parse_sms_json_file(json_path: Path) -> List[Dict[str, Any]]:
    """Parse JSON exported SMS records."""
    messages = []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            data = data.get("messages", [])

        for item in data:
            if isinstance(item, dict):
                body = item.get("body", item.get("message", item.get("text", "")))
                addr = item.get("address", item.get("sender", item.get("number", "Unknown")))
                ts = item.get("timestamp_utc", item.get("date", item.get("time", "Unknown")))
                direction = item.get("direction", item.get("type", "UNKNOWN"))

                messages.append({
                    "timestamp_utc": str(ts),
                    "original_epoch_ms": str(item.get("date", "")),
                    "sender_recipient": str(addr),
                    "direction": str(direction).upper(),
                    "body": str(body),
                    "source_file": json_path.name,
                })
    except Exception as e:
        print(f"[!] Warning parsing SMS JSON: {e}")
    return messages


def parse_sms_csv_file(csv_path: Path) -> List[Dict[str, Any]]:
    """Parse CSV exported SMS records."""
    messages = []
    try:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                body = row.get("body") or row.get("message") or row.get("text") or ""
                addr = row.get("address") or row.get("sender") or row.get("number") or "Unknown"
                ts = row.get("date") or row.get("timestamp") or row.get("time") or "Unknown"
                direction = row.get("direction") or row.get("type") or "UNKNOWN"

                messages.append({
                    "timestamp_utc": str(ts),
                    "original_epoch_ms": "",
                    "sender_recipient": str(addr),
                    "direction": str(direction).upper(),
                    "body": str(body),
                    "source_file": csv_path.name,
                })
    except Exception as e:
        print(f"[!] Warning parsing SMS CSV: {e}")
    return messages


def analyze_sms_messages(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze messages for 2FA/OTP codes, banking keywords, and suspicious links."""
    otp_pattern = re.compile(r"\b(?:\d{4,8}|[A-Z0-9]{6})\b")
    url_pattern = re.compile(r"https?://[a-zA-Z0-9_\-\.\:]+(?:/[^\s]*)?")
    suspicious_url_pattern = re.compile(r"(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|\.xyz|\.top|\.apk)", re.IGNORECASE)

    banking_keywords = re.compile(
        r"\b(?:bank|otp|verification|security code|passcode|transfer|wire|authorized|card|account|login|blocked|suspended|zelle|venmo|paypal)\b",
        re.IGNORECASE,
    )

    flagged_messages = []
    extracted_urls = []

    for msg in messages:
        body = msg.get("body", "")
        suspicious_reasons = []

        # Check for banking keywords
        bank_matches = banking_keywords.findall(body)
        if bank_matches:
            suspicious_reasons.append(f"Financial / 2FA keyword(s): {', '.join(set(bank_matches[:4]))}")

        # Check for URLs
        urls = url_pattern.findall(body)
        if urls:
            for u in urls:
                extracted_urls.append({"url": u, "source_msg": msg["sender_recipient"], "ts": msg["timestamp_utc"]})
                if suspicious_url_pattern.search(u):
                    suspicious_reasons.append(f"High-risk shortener or TLD URL detected: {u}")
                else:
                    suspicious_reasons.append(f"Embedded URL: {u}")

        if suspicious_reasons:
            flagged_messages.append({
                "timestamp_utc": msg.get("timestamp_utc"),
                "sender_recipient": msg.get("sender_recipient"),
                "direction": msg.get("direction"),
                "body": body,
                "reasons": suspicious_reasons,
                "source_file": msg.get("source_file"),
            })

    return {
        "total_messages": len(messages),
        "flagged_messages_count": len(flagged_messages),
        "extracted_urls_count": len(extracted_urls),
        "flagged_messages": flagged_messages,
        "extracted_urls": extracted_urls,
    }


def import_and_analyze_sms_file(
    file_path: Path,
    case_dir: Path,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Import an SMS evidence file, preserve it with cryptographic hashes, and analyze contents."""
    if not file_path.exists():
        raise FileNotFoundError(f"SMS file not found: {file_path}")

    # Preserve file in evidence/sms_exports/
    preserved = record_evidence_file(
        case_dir=case_dir,
        source_file=file_path,
        target_subfolder="sms_exports",
        description=f"Imported SMS backup file ({file_path.suffix.upper()})",
        operator=operator,
    )

    ext = file_path.suffix.lower()
    if ext == ".xml":
        raw_msgs = parse_sms_xml_backup(preserved)
    elif ext == ".json":
        raw_msgs = parse_sms_json_file(preserved)
    elif ext == ".csv":
        raw_msgs = parse_sms_csv_file(preserved)
    else:
        # Default try XML, then JSON
        raw_msgs = parse_sms_xml_backup(preserved) or parse_sms_json_file(preserved)

    analysis_res = analyze_sms_messages(raw_msgs)

    # Save analysis output
    out_dir = case_dir / "analysis" / "sms_analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_out = out_dir / f"sms_analysis_{ts}.json"
    json_out.write_text(json.dumps(analysis_res, indent=2), encoding="utf-8")

    log_case_action(
        case_dir,
        "SMS_FILE_ANALYZED",
        f"Analyzed {len(raw_msgs)} messages from {preserved.name}. Flagged: {analysis_res['flagged_messages_count']}",
        operator,
    )

    return {
        "status": "SUCCESS",
        "preserved_path": str(preserved),
        "analysis": analysis_res,
        "normalized_messages": raw_msgs,
    }
