"""
AndroMalHut Dynamic Behavior Analysis & Sandbox Instrumentation Module
Runs target APK packages on connected Android emulators or physical test devices.
Captures runtime behavior, logcat crashes, process state, and live screen captures.
"""

import os
import sys
import time
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import record_evidence_file, log_case_action
from modules.device_inventory import is_adb_installed, list_connected_devices, select_device, run_adb_command


def check_dynamic_environment() -> Dict[str, Any]:
    """Inspect availability of ADB, connected devices, and local emulators."""
    adb_ok = is_adb_installed()
    devices = list_connected_devices() if adb_ok else []
    emulators = [d for d in devices if "emulator" in d.get("serial", "").lower()]
    physical = [d for d in devices if "emulator" not in d.get("serial", "").lower()]

    emulator_bin = shutil.which("emulator") is not None
    available_avds: List[str] = []
    if emulator_bin:
        try:
            res = subprocess.run(["emulator", "-list-avds"], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                available_avds = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            pass

    return {
        "adb_installed": adb_ok,
        "connected_devices_count": len(devices),
        "emulators_connected": emulators,
        "physical_devices_connected": physical,
        "emulator_binary_available": emulator_bin,
        "available_avds": available_avds,
        "ready": len(devices) > 0,
    }


def capture_device_screenshot(
    case_dir: Path,
    serial: Optional[str] = None,
    name_prefix: str = "runtime_screen",
    description: str = "Live application sandbox screenshot",
    operator: Optional[str] = None,
) -> Optional[Path]:
    """Capture a live device screen directly via ADB and preserve it in evidence/screenshots/."""
    if not is_adb_installed():
        return None

    target_serial, err = select_device(serial)
    if err or not target_serial:
        return None

    screenshots_dir = case_dir / "evidence" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    target_filename = f"{name_prefix}_{timestamp}.png"
    target_path = screenshots_dir / target_filename

    # Method 1: Direct binary pipe via 'adb exec-out screencap -p'
    try:
        cmd = ["adb"]
        if target_serial:
            cmd.extend(["-s", target_serial])
        cmd.extend(["exec-out", "screencap", "-p"])

        res = subprocess.run(cmd, capture_output=True, timeout=15)
        if res.returncode == 0 and len(res.stdout) > 1024:
            target_path.write_bytes(res.stdout)
            record_evidence_file(
                case_dir=case_dir,
                source_file=target_path,
                target_subfolder="screenshots",
                description=f"{description} ({target_serial})",
                operator=operator,
            )
            return target_path
    except Exception:
        pass

    # Method 2: On-device temporary write fallback
    try:
        on_device_tmp = f"/data/local/tmp/{target_filename}"
        run_adb_command(["shell", "screencap", "-p", on_device_tmp], target_serial, timeout=15)
        run_adb_command(["pull", on_device_tmp, str(target_path)], target_serial, timeout=20)
        run_adb_command(["shell", "rm", "-f", on_device_tmp], target_serial, timeout=10)

        if target_path.exists() and target_path.stat().st_size > 1024:
            record_evidence_file(
                case_dir=case_dir,
                source_file=target_path,
                target_subfolder="screenshots",
                description=f"{description} ({target_serial})",
                operator=operator,
            )
            return target_path
    except Exception:
        pass

    return None


def run_dynamic_sandbox(
    apk_path: Path,
    case_dir: Path,
    package_name: Optional[str] = None,
    serial: Optional[str] = None,
    duration_seconds: int = 12,
    auto_interact: bool = True,
    uninstall_after: bool = True,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute target APK in an isolated sandbox/device, capture telemetry and screenshots."""
    if not apk_path.exists():
        return {"status": "ERROR", "reason": f"APK file not found: {apk_path}"}

    if not is_adb_installed():
        return {"status": "ERROR", "reason": "ADB is not installed on system."}

    target_serial, err = select_device(serial)
    if err or not target_serial:
        return {
            "status": "NO_DEVICE",
            "reason": "No Android device or emulator currently connected. Connect a device or start an emulator to perform dynamic behavioral analysis.",
            "diagnostics": check_dynamic_environment(),
        }

    # Derive package name if omitted
    pkg = package_name
    if not pkg:
        try:
            from modules.apk_analysis import parse_apk_manifest
            m = parse_apk_manifest(apk_path)
            pkg = m.get("package_name")
        except Exception:
            pkg = apk_path.stem

    if not pkg or pkg == "Unknown":
        pkg = apk_path.stem

    screenshots: List[str] = []
    dynamic_dir = case_dir / "analysis" / "dynamic_analysis"
    dynamic_dir.mkdir(parents=True, exist_ok=True)

    log_case_action(case_dir, "DYNAMIC_ANALYSIS_START", f"Starting sandbox dynamic run for {pkg} on {target_serial}", operator)

    # 1. Clear logcat buffer
    run_adb_command(["logcat", "-c"], target_serial, timeout=10)

    # 2. Install APK with all runtime permissions pre-granted (-g)
    install_code, install_out, install_err = run_adb_command(
        ["install", "-r", "-g", str(apk_path)],
        target_serial,
        timeout=90,
    )

    install_success = (install_code == 0) and ("Success" in install_out or "Success" in install_err)
    if not install_success:
        return {
            "status": "INSTALL_FAILED",
            "reason": f"Failed to install APK onto device: {install_err or install_out}",
            "package": pkg,
            "device": target_serial,
        }

    # 3. Launch application launcher activity
    # Use monkey to start default launcher activity for package
    run_adb_command(
        ["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"],
        target_serial,
        timeout=15,
    )
    time.sleep(3)

    # Capture Screen 1: App Initial Launch
    s1 = capture_device_screenshot(
        case_dir=case_dir,
        serial=target_serial,
        name_prefix=f"{pkg}_launch",
        description=f"Dynamic Launch Screen: {pkg}",
        operator=operator,
    )
    if s1:
        screenshots.append(str(s1))

    # 4. Optional UI interaction using touch events
    if auto_interact:
        # Send a few non-destructive UI touch events to trigger background threads/services
        run_adb_command(
            ["shell", "monkey", "-p", pkg, "--pct-touch", "100", "--pct-motion", "0", "15"],
            target_serial,
            timeout=15,
        )
        time.sleep(2)

    # Capture Screen 2: Interactive State / Potential Overlay / Permissions prompt
    s2 = capture_device_screenshot(
        case_dir=case_dir,
        serial=target_serial,
        name_prefix=f"{pkg}_interactive",
        description=f"Dynamic Interactive / Overlay Screen: {pkg}",
        operator=operator,
    )
    if s2:
        screenshots.append(str(s2))

    # 5. Check running processes for package
    ps_code, ps_out, _ = run_adb_command(["shell", "ps", "-A"], target_serial, timeout=15)
    running_pids = []
    if ps_code == 0:
        for line in ps_out.splitlines():
            if pkg in line:
                running_pids.append(line.strip())

    # 6. Capture dump of logcat
    logcat_file = case_dir / "evidence" / "device_logs" / f"logcat_dynamic_{pkg}.txt"
    logcat_file.parent.mkdir(parents=True, exist_ok=True)
    l_code, l_out, _ = run_adb_command(["logcat", "-d", "-v", "time"], target_serial, timeout=30)
    if l_code == 0:
        logcat_file.write_text(l_out, encoding="utf-8", errors="replace")

    # Analyze logcat for crashes, exceptions, or security alerts
    crashes = []
    suspicious_logs = []
    for line in l_out.splitlines():
        if pkg in line:
            if any(term in line.lower() for term in ["fatal", "exception", "crash", "anr"]):
                crashes.append(line.strip())
            elif any(term in line.lower() for term in ["http", "socket", "permission", "crypto", "su", "root"]):
                suspicious_logs.append(line.strip())

    # 7. Check open network sockets for package UID
    open_sockets = []
    net_code, net_out, _ = run_adb_command(["shell", "netstat", "-tlpn"], target_serial, timeout=15)
    if net_code == 0:
        for line in net_out.splitlines():
            if any(p in line for p in ["ESTABLISHED", "LISTEN", "SYN_SENT"]):
                open_sockets.append(line.strip())

    # 8. Clean up (uninstall) if requested
    if uninstall_after:
        run_adb_command(["uninstall", pkg], target_serial, timeout=30)

    result = {
        "status": "SUCCESS",
        "package_name": pkg,
        "device_serial": target_serial,
        "duration_seconds": duration_seconds,
        "running_processes": running_pids,
        "screenshots": screenshots,
        "crashes_detected": crashes[:20],
        "suspicious_log_events": suspicious_logs[:30],
        "active_sockets_sample": open_sockets[:15],
        "logcat_evidence": str(logcat_file),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    report_path = dynamic_dir / f"dynamic_behavior_{pkg}.json"
    report_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    log_case_action(case_dir, "DYNAMIC_ANALYSIS_COMPLETE", f"Dynamic analysis complete for {pkg}. Recorded {len(screenshots)} screenshots.", operator)

    return result
