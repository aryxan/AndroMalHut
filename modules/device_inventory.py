"""
DroidSleuth Android Device Collection & Application Inventory Module
Performs authorized, read-only collection from Android devices via ADB.
Inventories installed applications, collects system properties, and pulls APKs.
"""

import os
import re
import sys
import csv
import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import record_evidence_file, log_case_action


def is_adb_installed() -> bool:
    """Check if adb binary exists in PATH."""
    return shutil.which("adb") is not None


def run_adb_command(args: List[str], serial: Optional[str] = None, timeout: int = 30) -> Tuple[int, str, str]:
    """Execute an ADB command safely with arguments array."""
    if not is_adb_installed():
        return (
            1,
            "",
            "Error: 'adb' executable not found in PATH. Install android-tools-adb: sudo apt install adb",
        )

    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return (proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return (124, "", f"ADB command timed out after {timeout} seconds: {' '.join(cmd)}")
    except Exception as e:
        return (1, "", f"Subprocess error executing ADB: {e}")


def list_connected_devices() -> List[Dict[str, str]]:
    """List connected Android devices with status, model, and serial."""
    code, stdout, stderr = run_adb_command(["devices", "-l"])
    if code != 0:
        return []

    devices = []
    lines = stdout.strip().splitlines()
    for line in lines[1:]:  # skip 'List of devices attached'
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"

        meta = {}
        for part in parts[2:]:
            if ":" in part:
                k, v = part.split(":", 1)
                meta[k] = v

        devices.append({
            "serial": serial,
            "state": state,
            "product": meta.get("product", "unknown"),
            "model": meta.get("model", "unknown"),
            "device": meta.get("device", "unknown"),
            "transport_id": meta.get("transport_id", "unknown"),
        })
    return devices


def select_device(preferred_serial: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
    """Resolve which connected device to communicate with.
    
    Returns (serial, error_message).
    Never silently selects an arbitrary device if multiple are attached.
    """
    devices = list_connected_devices()
    if not devices:
        return (
            None,
            "No Android devices detected via ADB. Ensure USB debugging is enabled on the device and 'adb devices' shows it.",
        )

    authorized_devices = [d for d in devices if d["state"] == "device"]
    unauthorized = [d for d in devices if d["state"] == "unauthorized"]

    if unauthorized and not authorized_devices:
        return (
            None,
            f"Device {unauthorized[0]['serial']} is UNAUTHORIZED. Check the phone screen and tap 'Allow USB debugging'.",
        )

    if preferred_serial:
        match = next((d for d in authorized_devices if d["serial"] == preferred_serial), None)
        if match:
            return (match["serial"], None)
        return (None, f"Specified device serial '{preferred_serial}' not found among connected authorized devices.")

    if len(authorized_devices) == 1:
        return (authorized_devices[0]["serial"], None)

    # Multiple devices attached
    dev_list_str = ", ".join(f"{d['serial']} ({d['model']})" for d in authorized_devices)
    return (
        None,
        f"Multiple Android devices attached: {dev_list_str}. You must explicitly select or pass a device serial using -s <serial>.",
    )


def collect_device_info(serial: Optional[str] = None) -> Dict[str, Any]:
    """Collect read-only hardware, build, OS, and timestamp metadata from device."""
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    props = {}
    code, stdout, _ = run_adb_command(["shell", "getprop"], target_serial)
    if code == 0:
        for match in re.finditer(r"\[(.*?)\]:\s*\[(.*?)\]", stdout):
            props[match.group(1)] = match.group(2)

    # Device time
    _, dev_time_out, _ = run_adb_command(["shell", "date", '+"%Y-%m-%dT%H:%M:%S%z"'], target_serial)
    device_time = dev_time_out.strip() if dev_time_out else "Unavailable"

    # Kernel version
    _, uname_out, _ = run_adb_command(["shell", "uname", "-a"], target_serial)
    kernel_info = uname_out.strip() if uname_out else "Unavailable"

    # Uptime
    _, uptime_out, _ = run_adb_command(["shell", "uptime"], target_serial)

    collection_time_utc = datetime.now(timezone.utc).isoformat()

    return {
        "status": "SUCCESS",
        "device_serial": target_serial,
        "collection_time_utc": collection_time_utc,
        "device_reported_time": device_time,
        "manufacturer": props.get("ro.product.manufacturer", "Unknown"),
        "model": props.get("ro.product.model", "Unknown"),
        "brand": props.get("ro.product.brand", "Unknown"),
        "android_version": props.get("ro.build.version.release", "Unknown"),
        "api_level": props.get("ro.build.version.sdk", "Unknown"),
        "security_patch": props.get("ro.build.version.security_patch", "Unknown"),
        "build_fingerprint": props.get("ro.build.fingerprint", "Unknown"),
        "build_id": props.get("ro.build.id", "Unknown"),
        "kernel_version": kernel_info,
        "uptime": uptime_out.strip() if uptime_out else "Unavailable",
        "usb_debugging_state": "Enabled (Active ADB session)",
    }


def parse_dumpsys_package(dumpsys_output: str) -> Dict[str, Any]:
    """Parse output of 'adb shell dumpsys package <pkg>' for detailed app forensics."""
    data = {
        "version_name": "Unknown",
        "version_code": "Unknown",
        "first_install_time": "Unknown",
        "last_update_time": "Unknown",
        "target_sdk": "Unknown",
        "min_sdk": "Unknown",
        "user_id": "Unknown",
        "installer_package": "Unknown",
        "code_path": "Unknown",
        "resource_path": "Unknown",
        "requested_permissions": [],
        "install_permissions": [],
        "runtime_permissions": [],
        "signatures": [],
    }

    # Version
    vname = re.search(r"versionName=([^\s]+)", dumpsys_output)
    if vname:
        data["version_name"] = vname.group(1)

    vcode = re.search(r"versionCode=([0-9]+)", dumpsys_output)
    if vcode:
        data["version_code"] = vcode.group(1)

    # Timestamps
    fit = re.search(r"firstInstallTime=([0-9\-:\s]+)", dumpsys_output)
    if fit:
        data["first_install_time"] = fit.group(1).strip()

    lut = re.search(r"lastUpdateTime=([0-9\-:\s]+)", dumpsys_output)
    if lut:
        data["last_update_time"] = lut.group(1).strip()

    # SDKs
    tsdk = re.search(r"targetSdk=([0-9]+)", dumpsys_output)
    if tsdk:
        data["target_sdk"] = tsdk.group(1)

    msdk = re.search(r"minSdk=([0-9]+)", dumpsys_output)
    if msdk:
        data["min_sdk"] = msdk.group(1)

    # UID & Paths
    uid = re.search(r"userId=([0-9]+)", dumpsys_output)
    if uid:
        data["user_id"] = uid.group(1)

    installer = re.search(r"installerPackageName=([^\s]+)", dumpsys_output)
    if installer:
        data["installer_package"] = installer.group(1)

    cpath = re.search(r"codePath=([^\s]+)", dumpsys_output)
    if cpath:
        data["code_path"] = cpath.group(1)

    # Permissions
    # Section: requested permissions:
    req_match = re.search(r"requested permissions:\s*(.*?)(?:install permissions:|runtime permissions:|queriesPackages:|$)", dumpsys_output, re.DOTALL)
    if req_match:
        for line in req_match.group(1).splitlines():
            line = line.strip()
            if line and not line.startswith("android.permission.") and "." in line:
                data["requested_permissions"].append(line)
            elif line.startswith("android.permission."):
                data["requested_permissions"].append(line)

    # Section: install permissions:
    inst_match = re.search(r"install permissions:\s*(.*?)(?:runtime permissions:|$)", dumpsys_output, re.DOTALL)
    if inst_match:
        for line in inst_match.group(1).splitlines():
            line = line.strip()
            if ":" in line:
                perm_name = line.split(":")[0].strip()
                data["install_permissions"].append(perm_name)

    # Section: runtime permissions:
    rt_match = re.search(r"runtime permissions:\s*(.*?)(?:queriesPackages:|Package Changes:|$)", dumpsys_output, re.DOTALL)
    if rt_match:
        for line in rt_match.group(1).splitlines():
            line = line.strip()
            if "granted=true" in line:
                perm_name = line.split(":")[0].strip()
                data["runtime_permissions"].append(perm_name)

    # Signatures
    sig_match = re.findall(r"signatures:PackageSignatures\{.*?\[(.*?)\]", dumpsys_output)
    if sig_match:
        data["signatures"] = [s.strip() for s in sig_match[0].split(",")]

    return data


def inspect_package(package_name: str, serial: Optional[str] = None) -> Dict[str, Any]:
    """Inspect a single installed package in depth using dumpsys and pm."""
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    # Verify package exists
    code, stdout, _ = run_adb_command(["shell", "pm", "path", package_name], target_serial)
    if code != 0 or not stdout.strip():
        return {
            "status": "ERROR",
            "error": f"Package '{package_name}' not found on connected device {target_serial}.",
        }

    apk_paths = [line.replace("package:", "").strip() for line in stdout.strip().splitlines() if line.startswith("package:")]

    # Check if system app
    _, sys_out, _ = run_adb_command(["shell", "pm", "list", "packages", "-s", package_name], target_serial)
    is_system = package_name in sys_out

    # Dumpsys package
    code, dumpsys_out, _ = run_adb_command(["shell", "dumpsys", "package", package_name], target_serial)
    parsed_dumpsys = parse_dumpsys_package(dumpsys_out) if code == 0 else {}

    # Check running process
    _, ps_out, _ = run_adb_command(["shell", "ps", "-A"], target_serial)
    is_running = any(package_name in line for line in ps_out.splitlines())

    return {
        "status": "SUCCESS",
        "package_name": package_name,
        "is_system_app": is_system,
        "apk_paths": apk_paths,
        "is_running": is_running,
        "data_path_default": f"/data/data/{package_name}",
        "external_data_path": f"/sdcard/Android/data/{package_name}",
        "dumpsys_metadata": parsed_dumpsys,
        "collection_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "limitations_note": (
            "Access to private directory /data/data/<package> is restricted by Android sandbox "
            "permissions on non-rooted devices without app debug flags."
        ),
    }


def inventory_installed_applications(serial: Optional[str] = None) -> Dict[str, Any]:
    """Inventory all user and system applications installed on the connected device."""
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    # Get all packages with paths
    code, stdout, stderr = run_adb_command(["shell", "pm", "list", "packages", "-f", "-u"], target_serial)
    if code != 0:
        return {"status": "ERROR", "error": f"Failed to list packages: {stderr}"}

    # Get list of 3rd party (user) packages
    _, user_out, _ = run_adb_command(["shell", "pm", "list", "packages", "-3"], target_serial)
    user_packages = {line.replace("package:", "").strip() for line in user_out.splitlines() if line.startswith("package:")}

    # Get running processes
    _, ps_out, _ = run_adb_command(["shell", "ps", "-A"], target_serial)
    running_corpus = ps_out

    apps = []
    lines = stdout.strip().splitlines()

    for line in lines:
        line = line.strip()
        if not line.startswith("package:"):
            continue
        # Format: package:/data/app/.../base.apk=com.example.app
        content = line[len("package:"):]
        if "=" in content:
            apk_path, pkg_name = content.rsplit("=", 1)
        else:
            apk_path, pkg_name = "Unknown", content

        is_system = pkg_name not in user_packages
        is_running = pkg_name in running_corpus

        apps.append({
            "package_name": pkg_name,
            "apk_path": apk_path,
            "type": "System" if is_system else "User/Third-Party",
            "is_running": is_running,
        })

    return {
        "status": "SUCCESS",
        "device_serial": target_serial,
        "total_apps": len(apps),
        "user_apps_count": len([a for a in apps if a["type"] == "User/Third-Party"]),
        "system_apps_count": len([a for a in apps if a["type"] == "System"]),
        "applications": sorted(apps, key=lambda x: (x["type"] == "System", x["package_name"])),
        "inventory_time_utc": datetime.now(timezone.utc).isoformat(),
    }


def export_inventory_files(
    inventory_data: Dict[str, Any],
    case_dir: Path,
    operator: Optional[str] = None,
) -> Tuple[Path, Path]:
    """Export application inventory to JSON and CSV in evidence/device_inventory."""
    target_dir = case_dir / "evidence" / "device_inventory"
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    json_path = target_dir / f"installed_apps_{timestamp}.json"
    csv_path = target_dir / f"installed_apps_{timestamp}.csv"

    # Export JSON
    json_path.write_text(json.dumps(inventory_data, indent=2), encoding="utf-8")

    # Export CSV
    apps = inventory_data.get("applications", [])
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Package Name", "Classification", "APK Installation Path", "Currently Running"])
        for app in apps:
            writer.writerow([
                app.get("package_name"),
                app.get("type"),
                app.get("apk_path"),
                "Yes" if app.get("is_running") else "No",
            ])

    log_case_action(
        case_dir,
        "DEVICE_INVENTORY_EXPORTED",
        f"Exported inventory of {len(apps)} applications to {json_path.name} and {csv_path.name}",
        operator,
    )

    return (json_path, csv_path)


def pull_application_apk(
    package_name: str,
    case_dir: Path,
    serial: Optional[str] = None,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Pull an APK from the connected device into evidence/original_apks/ and compute hashes."""
    target_serial, err = select_device(serial)
    if err:
        return {"status": "ERROR", "error": err}

    # Locate APK path on device
    code, stdout, _ = run_adb_command(["shell", "pm", "path", package_name], target_serial)
    if code != 0 or not stdout.strip():
        return {"status": "ERROR", "error": f"Package '{package_name}' not found on device."}

    lines = [l.replace("package:", "").strip() for l in stdout.strip().splitlines() if l.startswith("package:")]
    if not lines:
        return {"status": "ERROR", "error": f"No APK path returned for package '{package_name}'."}

    device_apk_path = lines[0]  # Base APK

    # Create temporary destination
    temp_dir = case_dir / "evidence" / "original_apks" / "temp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_dest = temp_dir / f"{package_name}.apk"

    code, _, stderr = run_adb_command(["pull", device_apk_path, str(temp_dest)], target_serial, timeout=120)
    if code != 0 or not temp_dest.exists():
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        return {"status": "ERROR", "error": f"Failed to pull APK from device: {stderr}"}

    # Record evidence properly with hash computation and audit logging
    preserved_path = record_evidence_file(
        case_dir=case_dir,
        source_file=temp_dest,
        target_subfolder="original_apks",
        description=f"Pulled APK for package '{package_name}' from device path {device_apk_path}",
        dest_filename=f"{package_name}.apk",
        operator=operator,
    )

    # Clean up temp
    shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "status": "SUCCESS",
        "package_name": package_name,
        "device_source_path": device_apk_path,
        "preserved_evidence_path": str(preserved_path),
        "filename": preserved_path.name,
    }
