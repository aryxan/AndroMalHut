"""
AndroMalHut Case Management Module
Handles case lifecycle, evidence preservation, hashing, and audit trails.
Author: aryxan (https://github.com/aryxan/AndroMalHut)
"""

import os
import re
import sys
import json
import hashlib
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def get_default_base_dir() -> Path:
    """Return default base directory for cases, preferring Desktop with home or cwd fallback."""
    if "ANDROMALHUT_CASES_DIR" in os.environ:
        return Path(os.environ["ANDROMALHUT_CASES_DIR"])
    if "DROIDSLEUTH_CASES_DIR" in os.environ:
        return Path(os.environ["DROIDSLEUTH_CASES_DIR"])

    desktop_dir = Path.home() / "Desktop" / "Android-Forensics"
    try:
        if (Path.home() / "Desktop").exists() and os.access(str(Path.home() / "Desktop"), os.W_OK):
            return desktop_dir
    except Exception:
        pass

    home_dir = Path.home() / "Android-Forensics"
    try:
        if Path.home().exists() and os.access(str(Path.home()), os.W_OK):
            return home_dir
    except Exception:
        pass

    return Path.cwd() / "Android-Forensics"


def get_active_case_file() -> Path:
    """Return the path to the file tracking the active case."""
    if "ANDROMALHUT_ACTIVE_CASE" in os.environ:
        return Path(os.environ["ANDROMALHUT_ACTIVE_CASE"])
    if "DROIDSLEUTH_ACTIVE_CASE" in os.environ:
        return Path(os.environ["DROIDSLEUTH_ACTIVE_CASE"])

    local_file = Path.cwd() / ".andromalhut_active_case"
    if local_file.exists():
        return local_file
    legacy_local = Path.cwd() / ".droidsleuth_active_case"
    if legacy_local.exists():
        return legacy_local

    home_file = Path.home() / ".andromalhut_active_case"
    try:
        if Path.home().exists() and os.access(str(Path.home()), os.W_OK):
            return home_file
    except Exception:
        pass

    return local_file


def get_active_case() -> Optional[Path]:
    """Retrieve the currently active case path if it exists."""
    active_file = get_active_case_file()
    if active_file.exists():
        try:
            content = active_file.read_text(encoding="utf-8").strip()
            case_path = Path(content)
            if case_path.exists() and (case_path / "case.json").exists():
                return case_path
        except Exception:
            pass
    return None


def set_active_case(case_dir: Path) -> None:
    """Set the currently active case path, handling read-only filesystems safely."""
    active_file = get_active_case_file()
    try:
        active_file.write_text(str(case_dir.resolve()), encoding="utf-8")
    except OSError:
        fallback_file = Path.cwd() / ".andromalhut_active_case"
        try:
            fallback_file.write_text(str(case_dir.resolve()), encoding="utf-8")
        except OSError:
            pass


def list_cases(base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """List all valid investigation cases found in the base directory."""
    if base_dir is None:
        base_dir = get_default_base_dir()

    cases = []
    if not base_dir.exists():
        return cases

    for item in sorted(base_dir.iterdir()):
        if item.is_dir() and (item / "case.json").exists():
            try:
                metadata = json.loads((item / "case.json").read_text(encoding="utf-8"))
                cases.append({
                    "case_id": metadata.get("case_id", item.name),
                    "path": str(item),
                    "created_at_utc": metadata.get("created_at_utc", "Unknown"),
                    "description": metadata.get("case_description", ""),
                    "device": metadata.get("device_identifier", "Unknown"),
                    "status": metadata.get("status", "Active"),
                })
            except Exception:
                cases.append({
                    "case_id": item.name,
                    "path": str(item),
                    "created_at_utc": "Corrupt case.json",
                    "description": "",
                    "device": "Unknown",
                    "status": "Corrupt",
                })
    return cases


def generate_case_id(base_dir: Path) -> str:
    """Generate a unique sequential case ID: CASE-YYYYMMDD-XXX."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    prefix = f"CASE-{date_str}-"
    existing_nums = []

    if base_dir.exists():
        for item in base_dir.iterdir():
            if item.name.startswith(prefix):
                suffix = item.name[len(prefix):]
                if suffix.isdigit():
                    existing_nums.append(int(suffix))

    next_num = max(existing_nums, default=0) + 1
    return f"{prefix}{next_num:03d}"


def calculate_hashes(file_path: Path) -> Dict[str, Any]:
    """Calculate SHA-256, SHA-1, and MD5 hashes and file size."""
    if not file_path.exists() or not file_path.is_file():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    size = 0

    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            size += len(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
        "size_bytes": size,
    }


def open_system_folder(path: Path) -> bool:
    """Open folder in native desktop file manager if available."""
    try:
        resolved = Path(path).resolve()
        if not resolved.exists():
            return False
        if sys.platform.startswith("linux"):
            if os.getenv("DISPLAY") or os.getenv("WAYLAND_DISPLAY"):
                subprocess.Popen(["xdg-open", str(resolved)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(resolved)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        elif sys.platform == "win32":
            os.startfile(str(resolved))
            return True
    except Exception:
        pass
    return False


def init_case(
    description: str = "",
    investigator: str = "",
    device_identifier: str = "",
    incident_date: str = "",
    notes: str = "",
    base_dir: Optional[Path] = None,
    case_name: Optional[str] = None,
    open_folder: bool = True,
) -> Path:
    """Initialize a new investigation case directory structure or open existing scan folder."""
    if base_dir is None:
        base_dir = get_default_base_dir()

    base_dir.mkdir(parents=True, exist_ok=True)

    if case_name and case_name.strip():
        sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", case_name.strip()).strip("_")
        case_id = sanitized or generate_case_id(base_dir)
    else:
        case_id = generate_case_id(base_dir)

    case_dir = base_dir / case_id

    # Comprehensive subfolders for each distinct test and artifact
    subdirs = [
        "evidence/original_apks",
        "evidence/device_apks",
        "evidence/device_inventory",
        "evidence/device_logs",
        "evidence/sms_exports",
        "evidence/network_captures",
        "evidence/imported_files",
        "analysis/apk_analysis",
        "analysis/ml_classification",
        "analysis/ai_triage",
        "analysis/network_analysis",
        "analysis/log_analysis",
        "analysis/sms_analysis",
        "analysis/timelines",
        "hashes",
        "reports",
        "logs",
    ]

    already_existed = case_dir.exists() and (case_dir / "case.json").exists()

    for sd in subdirs:
        (case_dir / sd).mkdir(parents=True, exist_ok=True)

    now_utc = datetime.now(timezone.utc).isoformat()
    local_tz = datetime.now().astimezone().tzname() or "UTC"

    if already_existed:
        # Update active case pointer and open existing folder
        set_active_case(case_dir)
        audit_log = case_dir / "logs" / "case_audit.log"
        try:
            with open(audit_log, "a", encoding="utf-8") as f:
                f.write(f"[{now_utc}] [INFO] Existing scan accessed and opened: {case_id}\n")
        except OSError:
            pass
        if open_folder:
            open_system_folder(case_dir)
        return case_dir

    metadata = {
        "case_id": case_id,
        "created_at_utc": now_utc,
        "investigator": investigator or os.getenv("USER", "Forensic Investigator"),
        "case_description": description or "Forensic investigation of Android device/APK",
        "device_identifier": device_identifier or "Unknown Device",
        "incident_date": incident_date or now_utc[:10],
        "time_zone": local_tz,
        "notes": notes,
        "status": "Active",
        "history": [
            {
                "timestamp_utc": now_utc,
                "action": "CASE_INITIALIZED",
                "details": f"Scan directory created at {case_dir}",
                "operator": investigator or os.getenv("USER", "Forensic Investigator"),
            }
        ],
    }

    (case_dir / "case.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (case_dir / "hashes" / "evidence_hashes.json").write_text(json.dumps([], indent=2), encoding="utf-8")
    (case_dir / "hashes" / "manifest.sha256").write_text("", encoding="utf-8")

    # Audit log
    audit_log = case_dir / "logs" / "case_audit.log"
    with open(audit_log, "a", encoding="utf-8") as f:
        f.write(f"[{now_utc}] [INFO] Case initialized: {case_id} by {metadata['investigator']}\n")

    set_active_case(case_dir)
    if open_folder:
        open_system_folder(case_dir)
    return case_dir


def get_or_create_scan(
    scan_name: str,
    base_dir: Optional[Path] = None,
    open_folder: bool = True,
    description: str = "",
) -> Tuple[Path, bool]:
    """
    Look up a scan by name. If it already exists, activate it and open its folder.
    If it does not exist, initialize a new scan with dedicated test subfolders and open it.
    Returns (case_dir, already_existed).
    """
    if base_dir is None:
        base_dir = get_default_base_dir()

    base_dir.mkdir(parents=True, exist_ok=True)
    clean_name = scan_name.strip() if scan_name else ""
    if clean_name:
        sanitized = re.sub(r"[^A-Za-z0-9_.-]+", "_", clean_name).strip("_")
        case_id = sanitized or generate_case_id(base_dir)
    else:
        case_id = generate_case_id(base_dir)

    target_dir = base_dir / case_id
    already_existed = target_dir.exists() and (target_dir / "case.json").exists()

    case_dir = init_case(
        case_name=case_id,
        base_dir=base_dir,
        description=description,
        open_folder=open_folder,
    )
    return case_dir, already_existed



def log_case_action(case_dir: Path, action: str, details: str, operator: Optional[str] = None) -> None:
    """Record a forensic action in the case audit log and case.json history."""
    now_utc = datetime.now(timezone.utc).isoformat()
    op = operator or os.getenv("USER", "Forensic Investigator")

    # Update log file
    audit_log = case_dir / "logs" / "case_audit.log"
    audit_log.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_log, "a", encoding="utf-8") as f:
        f.write(f"[{now_utc}] [{action}] {details} (Operator: {op})\n")

    # Update case.json
    case_json_file = case_dir / "case.json"
    if case_json_file.exists():
        try:
            metadata = json.loads(case_json_file.read_text(encoding="utf-8"))
            if "history" not in metadata:
                metadata["history"] = []
            metadata["history"].append({
                "timestamp_utc": now_utc,
                "action": action,
                "details": details,
                "operator": op,
            })
            case_json_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        except Exception as e:
            print(f"[!] Warning: Failed to update case.json history: {e}", file=sys.stderr)


def record_evidence_file(
    case_dir: Path,
    source_file: Path,
    target_subfolder: str,
    description: str,
    dest_filename: Optional[str] = None,
    operator: Optional[str] = None,
) -> Path:
    """Safely preserve an evidence file in the case directory and record its hashes.
    
    Prevents overwriting existing evidence by adding timestamp suffixes if necessary.
    """
    if not source_file.exists():
        raise FileNotFoundError(f"Source evidence file does not exist: {source_file}")

    target_dir = case_dir / "evidence" / target_subfolder
    target_dir.mkdir(parents=True, exist_ok=True)

    filename = dest_filename or source_file.name
    dest_path = target_dir / filename

    # Prevent accidental overwrites
    if dest_path.exists():
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = Path(filename).stem
        ext = Path(filename).suffix
        dest_path = target_dir / f"{stem}_{timestamp}{ext}"

    # Copy read-only
    shutil.copy2(source_file, dest_path)

    # Compute hashes on the preserved evidence file
    hashes = calculate_hashes(dest_path)
    now_utc = datetime.now(timezone.utc).isoformat()

    record = {
        "filename": dest_path.name,
        "relative_path": str(dest_path.relative_to(case_dir)),
        "original_source": str(source_file.resolve()),
        "description": description,
        "collected_at_utc": now_utc,
        "size_bytes": hashes["size_bytes"],
        "sha256": hashes["sha256"],
        "sha1": hashes["sha1"],
        "md5": hashes["md5"],
    }

    # Update evidence_hashes.json
    hashes_file = case_dir / "hashes" / "evidence_hashes.json"
    records = []
    if hashes_file.exists():
        try:
            records = json.loads(hashes_file.read_text(encoding="utf-8"))
        except Exception:
            records = []
    records.append(record)
    hashes_file.write_text(json.dumps(records, indent=2), encoding="utf-8")

    # Update manifest.sha256
    manifest_file = case_dir / "hashes" / "manifest.sha256"
    with open(manifest_file, "a", encoding="utf-8") as f:
        f.write(f"{hashes['sha256']}  {record['relative_path']}\n")

    log_case_action(
        case_dir,
        "EVIDENCE_ACQUIRED",
        f"Acquired {record['filename']} ({hashes['size_bytes']} bytes, SHA256: {hashes['sha256']}) - {description}",
        operator,
    )

    return dest_path


def verify_case_hashes(case_dir: Path) -> List[Dict[str, Any]]:
    """Verify cryptographic hashes of all preserved evidence against stored manifest."""
    hashes_file = case_dir / "hashes" / "evidence_hashes.json"
    results = []

    if not hashes_file.exists():
        return results

    try:
        records = json.loads(hashes_file.read_text(encoding="utf-8"))
    except Exception as e:
        return [{"status": "ERROR", "message": f"Corrupt hash records: {e}"}]

    for record in records:
        rel_path = record.get("relative_path")
        expected_sha256 = record.get("sha256")
        expected_sha1 = record.get("sha1")
        expected_md5 = record.get("md5")

        target_file = case_dir / rel_path
        if not target_file.exists():
            results.append({
                "filename": record.get("filename"),
                "relative_path": rel_path,
                "status": "MISSING",
                "details": "Evidence file was deleted or moved.",
            })
            continue

        try:
            current = calculate_hashes(target_file)
            sha256_match = current["sha256"] == expected_sha256
            sha1_match = current["sha1"] == expected_sha1
            md5_match = current["md5"] == expected_md5

            if sha256_match and sha1_match and md5_match:
                status = "VERIFIED"
                details = "All hashes match recorded evidence values."
            else:
                status = "CORRUPTED_OR_TAMPERED"
                details = f"Hash mismatch! Recorded SHA256={expected_sha256}, Current SHA256={current['sha256']}"

            results.append({
                "filename": record.get("filename"),
                "relative_path": rel_path,
                "status": status,
                "expected_sha256": expected_sha256,
                "current_sha256": current["sha256"],
                "size_bytes": current["size_bytes"],
                "details": details,
            })
        except Exception as e:
            results.append({
                "filename": record.get("filename"),
                "relative_path": rel_path,
                "status": "ERROR",
                "details": str(e),
            })

    log_case_action(
        case_dir,
        "HASH_VERIFICATION",
        f"Verified {len(results)} evidence items. Mismatches/missing: {sum(1 for r in results if r.get('status') != 'VERIFIED')}",
    )
    return results
