"""
DroidSleuth Android Log Analysis Module
Collects and analyzes device logs (logcat, dmesg, dumpsys netstats).
Identifies suspicious runtime events, permission changes, crashes, and broadcast triggers.
"""

import os
import re
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import record_evidence_file, log_case_action
from modules.device_inventory import select_device, run_adb_command


def collect_device_logs(
    case_dir: Path,
    serial: Optional[str] = None,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Collect available Android logs via ADB and preserve them as evidence."""
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    collected_files = []
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    temp_dir = case_dir / "evidence" / "device_logs" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)

    # 1. Collect Logcat
    temp_logcat = temp_dir / f"logcat_{timestamp}.txt"
    code, stdout, stderr = run_adb_command(["logcat", "-d", "-v", "threadtime"], target_serial, timeout=60)
    if code == 0 and stdout:
        temp_logcat.write_text(stdout, encoding="utf-8")
        preserved = record_evidence_file(
            case_dir=case_dir,
            source_file=temp_logcat,
            target_subfolder="device_logs",
            description=f"Logcat dump (-v threadtime) from device {target_serial}",
            dest_filename=f"logcat_{timestamp}.txt",
            operator=operator,
        )
        collected_files.append({"name": "logcat", "path": str(preserved), "lines": len(stdout.splitlines())})
    else:
        log_case_action(case_dir, "LOG_COLLECTION_WARNING", f"Logcat dump failed or empty: {stderr}", operator)

    # 2. Collect Dumpsys Netstats
    temp_netstats = temp_dir / f"dumpsys_netstats_{timestamp}.txt"
    code, stdout, _ = run_adb_command(["shell", "dumpsys", "netstats", "detail"], target_serial, timeout=45)
    if code == 0 and stdout:
        temp_netstats.write_text(stdout, encoding="utf-8")
        preserved = record_evidence_file(
            case_dir=case_dir,
            source_file=temp_netstats,
            target_subfolder="device_logs",
            description=f"Dumpsys netstats detail dump from device {target_serial}",
            dest_filename=f"dumpsys_netstats_{timestamp}.txt",
            operator=operator,
        )
        collected_files.append({"name": "dumpsys_netstats", "path": str(preserved)})

    # Clean up temp
    import shutil
    shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "status": "SUCCESS",
        "device_serial": target_serial,
        "collected_logs_count": len(collected_files),
        "files": collected_files,
        "collection_time_utc": datetime.now(timezone.utc).isoformat(),
        "limitations": "Non-rooted devices provide circular logcat buffer with limited history; kernel dmesg is typically restricted by SELinux on Android 8+.",
    }


def parse_logcat_file(logcat_path: Path, target_package: Optional[str] = None) -> Dict[str, Any]:
    """Parse logcat output for suspicious activities and specific package events."""
    if not logcat_path.exists():
        raise FileNotFoundError(f"Logcat file not found: {logcat_path}")

    # Logcat threadtime format: MM-DD HH:MM:SS.mmm PID TID Priority Tag: Message
    line_pattern = re.compile(
        r"^(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$"
    )

    suspicious_tags = {
        "ActivityManager": "App lifecycle & intent dispatch",
        "PackageManager": "Package installation & permission checks",
        "AccessibilityManager": "Accessibility service state changes",
        "DexClassLoader": "Dynamic code loading invocation",
        "dalvikvm": "VM bytecode & dynamic loading",
        "AndroidRuntime": "Fatal exceptions & process crashes",
    }

    suspicious_patterns = [
        (re.compile(r"fatal|FATAL EXCEPTION|AndroidRuntime:\s*FATAL", re.IGNORECASE), "CRASH_OR_FATAL", "Fatal process crash or runtime abort"),
        (re.compile(r"BOOT_COMPLETED|android\.intent\.action\.BOOT_COMPLETED"), "BOOT_EVENT", "Boot broadcast received or dispatched"),
        (re.compile(r"SMS_RECEIVED|android\.provider\.Telephony\.SMS_RECEIVED"), "SMS_EVENT", "SMS received broadcast dispatched"),
        (re.compile(r"AccessibilityService|enabled_accessibility_services"), "ACCESSIBILITY_EVENT", "Accessibility service modification or event"),
        (re.compile(r"DexClassLoader|dalvik\.system\.DexFile"), "DYNAMIC_LOAD_EVENT", "Dynamic DEX loading detected at runtime"),
        (re.compile(r"installPackage|INSTALL_FAILED|PackageInstaller"), "INSTALL_EVENT", "Package install attempt or failure"),
    ]

    total_lines = 0
    package_events = []
    flagged_events = []

    with open(logcat_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            total_lines += 1
            line_str = line.strip()
            match = line_pattern.match(line_str)

            if match:
                dt_str, pid, tid, prio, tag, msg = match.groups()
                tag = tag.strip()
                msg = msg.strip()

                # Package filter
                if target_package and target_package.lower() in (tag.lower() + " " + msg.lower()):
                    package_events.append({
                        "timestamp": dt_str,
                        "priority": prio,
                        "tag": tag,
                        "pid": pid,
                        "message": msg,
                    })

                # Suspicious pattern matching
                for regex, category, desc in suspicious_patterns:
                    if regex.search(tag) or regex.search(msg):
                        flagged_events.append({
                            "timestamp": dt_str,
                            "category": category,
                            "tag": tag,
                            "priority": prio,
                            "description": desc,
                            "message": msg[:200],  # truncated for summary
                        })
                        break

    return {
        "source_file": logcat_path.name,
        "total_lines_inspected": total_lines,
        "package_events_count": len(package_events),
        "flagged_suspicious_events_count": len(flagged_events),
        "package_events": package_events[:50],  # sample
        "flagged_events": flagged_events[:50],  # sample
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
    }
