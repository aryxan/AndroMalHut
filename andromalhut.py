#!/usr/bin/env python3
"""
AndroMalHut - Defensive Android Malware Forensics & Incident Response Toolkit
Author: aryxan (https://github.com/aryxan/AndroMalHut)
Educational and authorized defensive forensics CLI toolkit.
"""

import os
import sys
import argparse
import shutil
import json
import re
import hashlib
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from modules.case_manager import (
    init_case,
    get_or_create_scan,
    open_system_folder,
    get_active_case,
    set_active_case,
    list_cases,
    verify_case_hashes,
    record_evidence_file,
    get_default_base_dir,
    calculate_hashes,
)
from modules.device_inventory import (
    list_connected_devices,
    collect_device_info,
    inventory_installed_applications,
    export_inventory_files,
    inspect_package,
    pull_application_apk,
    is_adb_installed,
)
from modules.apk_analysis import (
    analyze_apk,
    check_installed_tool,
)
from modules.permission_analysis import (
    analyze_permissions,
)
from modules.network_analysis import (
    analyze_network_evidence,
    is_tshark_installed,
)
from modules.log_analysis import (
    collect_device_logs,
    parse_logcat_file,
)
from modules.sms_analysis import (
    attempt_adb_sms_export,
    import_and_analyze_sms_file,
)
from modules.timeline import (
    build_incident_timeline,
)
from modules.reporting import (
    generate_markdown_report,
    generate_pdf_report,
    REPORTLAB_AVAILABLE,
)
from modules.ollama_analysis import (
    check_ollama_status,
    run_case_ollama_explanation,
)
from modules.online_verifier import (
    resolve_friendly_app_name,
    verify_package_online,
)

import threading
import time

TOOL_VERSION = "1.0.0"
AUTHOR = "aryxan"
REPO_URL = "https://github.com/aryxan/AndroMalHut"

# High-contrast ANSI Color formatting
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_WHITE = "\033[1;97m"      # Maximum contrast crisp bold white
C_RED = "\033[1;91m"
C_GREEN = "\033[1;92m"
C_YELLOW = "\033[1;93m"
C_BLUE = "\033[1;94m"
C_CYAN = "\033[1;96m"
C_GRAY = "\033[90m"


def clear_screen() -> None:
    """Clear terminal screen for clean layout."""
    os.system("clear" if os.name != "nt" else "cls")


class ForensicSpinner:
    """Professional non-intrusive terminal progress spinner with animation."""
    def __init__(self, message: str = "Processing evidence..."):
        self.message = message
        self._stop_event = threading.Event()
        self._thread = None
        self.frames = ["[|]", "[/]", "[-]", "[\\]"]

    def _spin(self):
        idx = 0
        while not self._stop_event.is_set():
            frame = self.frames[idx % len(self.frames)]
            sys.stdout.write(f"\r  {C_CYAN}{frame}{C_RESET} {self.message} ")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.12)
        sys.stdout.write(f"\r  {C_GREEN}[DONE]{C_RESET} {self.message}\n")
        sys.stdout.flush()

    def __enter__(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop_event.set()
        if self._thread:
            self._thread.join()


def open_pdf_in_browser(pdf_path: Path) -> bool:
    """Launch the generated PDF forensic report directly inside a modern web browser."""
    if not pdf_path.exists():
        print(f"{C_RED}[!] PDF file does not exist: {pdf_path}{C_RESET}")
        return False

    browsers = ["firefox", "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "brave-browser", "xdg-open"]
    found_browser = None
    for b in browsers:
        if shutil.which(b):
            found_browser = b
            break

    if not found_browser:
        print(f"{C_YELLOW}[!] No web browser detected in PATH. File saved at: {pdf_path}{C_RESET}")
        return False

    try:
        abs_uri = f"file://{pdf_path.resolve()}"
        print(f"{C_CYAN}[➜] Opening PDF in browser ({found_browser}): {pdf_path.name}...{C_RESET}")
        subprocess.Popen(
            [found_browser, abs_uri],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True
    except Exception as e:
        print(f"{C_RED}[!] Failed to launch browser: {e}{C_RESET}")
        return False


def print_banner() -> None:
    """Render a polished forensic banner with real-time system and scan status badges."""
    active = get_active_case()
    case_name = active.name if active else "None (No Active Scan)"
    case_path = str(active) if active else "Select or Create via Option [6]"

    # ML Classifier status
    repo_model_dir = Path(__file__).resolve().parent / "ml_model"
    legacy_model_dir = Path.home() / "Android-Forensics/Datasets/Drebin/model"
    model_dir = repo_model_dir if (repo_model_dir / "drebin_rf.joblib").exists() else legacy_model_dir
    model_path = model_dir / "drebin_rf.joblib"
    if model_path.exists():
        ml_status = f"{C_GREEN}ONLINE{C_RESET} {C_GRAY}(GPU XGBoost • 25,722 samples){C_RESET}"
    else:
        ml_status = f"{C_YELLOW}STANDBY{C_RESET} {C_GRAY}(Fallback Heuristics){C_RESET}"

    # ADB Connected device status
    if is_adb_installed():
        devs = list_connected_devices()
        if devs:
            dev_model = devs[0].get("model") or devs[0].get("serial", "Android Device")
            adb_status = f"{C_GREEN}CONNECTED{C_RESET} {C_GRAY}({len(devs)} device: {dev_model}){C_RESET}"
        else:
            adb_status = f"{C_YELLOW}DISCONNECTED{C_RESET} {C_GRAY}(No USB debugging device){C_RESET}"
    else:
        adb_status = f"{C_RED}NOT INSTALLED{C_RESET}"

    # Ollama status
    ollama_ok, models, _ = check_ollama_status()
    if ollama_ok and models:
        ai_status = f"{C_GREEN}ONLINE{C_RESET} {C_GRAY}(Model: {models[0]}){C_RESET}"
    elif ollama_ok:
        ai_status = f"{C_YELLOW}STANDBY{C_RESET} {C_GRAY}(Ollama running, no model){C_RESET}"
    else:
        ai_status = f"{C_GRAY}OFFLINE (Optional Triage){C_RESET}"

    ascii_art = (
        "    _             _           __  __       _ _   _       _   \n"
        "   / \\   _ __   __| |_ __ ___|  \\/  | __ _| | | | |_   _| |_ \n"
        "  / _ \\ | '_ \\ / _` | '__/ _ \\ |\\/| |/ _` | | |_| | | | | __|\n"
        " / ___ \\| | | | (_| | | | (_) | |  | | (_| | |  _  | |_| | |_ \n"
        "/_/   \\_\\_| |_|\\__,_|_|  \\___/|_|  |_|\\__,_|_|_| |_|\\__,_|\\__|"
    )

    print(f"""
{C_WHITE}{ascii_art}{C_RESET}
  {C_WHITE}ANDROMALHUT{C_RESET} :: {C_CYAN}Android Malware Forensics & Incident Response v{TOOL_VERSION}{C_RESET}
  {C_GRAY}Author: {AUTHOR} | GitHub: {REPO_URL}{C_RESET}

{C_CYAN}+-----------------------------------------------------------------------------+
|                        LEGAL & COMPLIANCE NOTICE                            |
+-----------------------------------------------------------------------------+
|                                                                             |
|   AndroMalHut is strictly intended for educational, academic research,      |
|   and authorized defensive digital forensics and incident response.         |
|                                                                             |
|   Unauthorized acquisition, extraction, or compromise of mobile devices     |
|   without explicit written owner permission is strictly prohibited.         |
|                                                                             |
+-----------------------------------------------------------------------------+
| Active Scan : {C_GREEN if active else C_YELLOW}{case_name:<20}{C_RESET}{C_CYAN} | Folder: {C_GRAY}{case_path[:42]:<42}{C_RESET}{C_CYAN}|
| ML Engine   : {ml_status:<62}|
| Device ADB  : {adb_status:<62}|
| AI Triage   : {ai_status:<62}|
+-----------------------------------------------------------------------------+{C_RESET}""")


def check_tool_dependencies() -> Dict[str, Dict[str, Any]]:
    """Inspect all system binaries, Python libraries, and forensic models."""
    repo_model_dir = Path(__file__).resolve().parent / "ml_model"
    legacy_model_dir = Path.home() / "Android-Forensics/Datasets/Drebin/model"
    model_dir = repo_model_dir if (repo_model_dir / "drebin_rf.joblib").exists() else legacy_model_dir
    ml_model_file = model_dir / "drebin_rf.joblib"
    deps = {
        "python3": {
            "required": True,
            "installed": True,
            "path": sys.executable,
            "purpose": "Core forensic execution engine",
        },
        "ML Classifier": {
            "required": False,
            "installed": ml_model_file.exists(),
            "path": str(ml_model_file) if ml_model_file.exists() else "Not Found",
            "purpose": "GPU-accelerated XGBoost model (25,722 samples)",
            "install_cmd": "Pre-trained in ml_model/ or trained via ml_model/train.py",
        },
        "adb": {
            "required": False,
            "installed": is_adb_installed(),
            "path": shutil.which("adb") or "Not Found",
            "purpose": "Authorized Android device acquisition & app inventory",
            "install_cmd": "sudo apt install adb (or android-tools-adb)",
        },
        "tshark": {
            "required": False,
            "installed": is_tshark_installed(),
            "path": shutil.which("tshark") or "Not Found",
            "purpose": "PCAP/PCAPNG network packet dissection & C2 extraction",
            "install_cmd": "sudo apt install tshark",
        },
        "reportlab": {
            "required": False,
            "installed": REPORTLAB_AVAILABLE,
            "path": "Python Library" if REPORTLAB_AVAILABLE else "Not Installed",
            "purpose": "Cryptographic PDF forensic report generation",
            "install_cmd": "pip install reportlab",
        },
        "aapt / aapt2": {
            "required": False,
            "installed": check_installed_tool("aapt") or check_installed_tool("aapt2"),
            "path": shutil.which("aapt") or shutil.which("aapt2") or "Not Found",
            "purpose": "Android asset packaging tool for manifest badging dump",
            "install_cmd": "sudo apt install aapt",
        },
        "apktool": {
            "required": False,
            "installed": check_installed_tool("apktool"),
            "path": shutil.which("apktool") or "Not Found",
            "purpose": "APK resource reverse engineering and disassembly",
            "install_cmd": "sudo apt install apktool",
        },
        "jadx": {
            "required": False,
            "installed": check_installed_tool("jadx"),
            "path": shutil.which("jadx") or "Not Found",
            "purpose": "DEX-to-Java offline decompilation",
            "install_cmd": "sudo apt install jadx",
        },
        "apksigner": {
            "required": False,
            "installed": check_installed_tool("apksigner"),
            "path": shutil.which("apksigner") or "Not Found",
            "purpose": "APK signature block verification (v1, v2, v3, v4)",
            "install_cmd": "sudo apt install apksigner",
        },
    }
    return deps


def display_dependencies() -> None:
    """Print dependency status table."""
    deps = check_tool_dependencies()
    print(f"\n{C_CYAN}{C_BOLD}╭─────────────────────────────────────────────────────────────────╮{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}│             FORENSIC TOOL & DEPENDENCY AVAILABILITY             │{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}╰─────────────────────────────────────────────────────────────────╯{C_RESET}\n")
    print(f"{'Component':<18} {'Status':<16} {'Path / Details':<32} {'Purpose'}")
    print("-" * 92)

    for name, info in deps.items():
        if info["installed"]:
            status_str = f"{C_GREEN}[INSTALLED]{C_RESET}"
        else:
            status_str = f"{C_YELLOW}[OPTIONAL]{C_RESET}" if not info["required"] else f"{C_RED}[MISSING]{C_RESET}"
        print(f"{name:<18} {status_str:<25} {info['path'][:30]:<32} {info['purpose']}")
        if not info["installed"] and "install_cmd" in info:
            print(f"  {C_GRAY}↳ Install with: {info['install_cmd']}{C_RESET}")

    ollama_ok, models, ollama_msg = check_ollama_status()
    ollama_status = f"{C_GREEN}[RUNNING]{C_RESET}" if ollama_ok else f"{C_GRAY}[NOT DETECTED]{C_RESET}"
    print(f"{'ollama':<18} {ollama_status:<25} {'http://127.0.0.1:11434':<32} {ollama_msg}")
    print("-" * 92)


def prompt_scan_name(open_folder: bool = True) -> Path:
    """Prompt user for scan name. If scan exists, open folder. If new, create dedicated test subfolders and open."""
    base_dir = get_default_base_dir()
    print(f"\n{C_CYAN}{C_BOLD}╭─────────────────────────────────────────────────────────────────╮{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}│                    SELECT OR INITIALIZE SCAN                    │{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}╰─────────────────────────────────────────────────────────────────╯{C_RESET}")
    print(f"{C_GRAY}Scans root directory: {base_dir}{C_RESET}")

    existing_cases = list_cases(base_dir)
    if existing_cases:
        print(f"\n{C_BOLD}Recent Existing Scans:{C_RESET}")
        for i, c in enumerate(existing_cases[:5], 1):
            print(f"  [{i}] {C_CYAN}{c['case_id']}{C_RESET} - {c['description'][:45] or 'Android Forensic Scan'}")

    try:
        user_input = input(f"\n{C_BOLD}Enter Scan / Case Name (or number, or press Enter for auto):{C_RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        user_input = ""

    # Check numbered selection from existing
    if user_input.isdigit() and existing_cases:
        idx = int(user_input) - 1
        if 0 <= idx < len(existing_cases):
            selected_path = Path(existing_cases[idx]["path"])
            set_active_case(selected_path)
            print(f"{C_GREEN}[✓] Active scan set to: {existing_cases[idx]['case_id']}{C_RESET}")
            if open_folder:
                print(f"{C_CYAN}[➜] Opening scan folder in system file manager...{C_RESET}")
                open_system_folder(selected_path)
            return selected_path

    if user_input == "0":
        active = get_active_case()
        if active and active.exists():
            return active
        user_input = ""

    # Check named scan
    case_dir, already_existed = get_or_create_scan(
        scan_name=user_input,
        base_dir=base_dir,
        open_folder=open_folder,
    )
    if already_existed:
        print(f"\n{C_GREEN}{C_BOLD}[✓] Scan '{case_dir.name}' already exists!{C_RESET}")
    else:
        print(f"\n{C_GREEN}{C_BOLD}[+] New scan created: '{case_dir.name}'{C_RESET}")
        print(f"    Dedicated subfolders initialized for all test artifacts.")

    print(f"    Path: {case_dir}")
    if open_folder:
        print(f"{C_CYAN}[➜] Opening scan folder in system file manager...{C_RESET}")
        open_system_folder(case_dir)

    return case_dir


def require_case(explicit_case_path: Optional[str] = None) -> Path:
    """Ensure an active or specified case directory exists, or prompt user."""
    if explicit_case_path:
        p = Path(explicit_case_path)
        if p.exists() and (p / "case.json").exists():
            set_active_case(p)
            return p
        raise FileNotFoundError(f"Specified case directory does not exist or lacks case.json: {explicit_case_path}")

    active = get_active_case()
    if active and active.exists() and (active / "case.json").exists():
        return active

    return prompt_scan_name(open_folder=True)


def init_case_interactive() -> Path:
    """Backwards-compatible wrapper that prompts for scan name and opens folder."""
    return prompt_scan_name(open_folder=True)


def run_ml_classifier(apk_path: Path, case_dir: Path) -> Dict[str, Any]:
    """Execute the multi-source GPU-accelerated XGBoost classifier on suspect APK."""
    repo_model_dir = Path(__file__).resolve().parent / "ml_model"
    legacy_model_dir = Path.home() / "Android-Forensics/Datasets/Drebin/model"
    model_dir = repo_model_dir if (repo_model_dir / "scan_apk.py").exists() else legacy_model_dir
    scanner_script = model_dir / "scan_apk.py"
    venv_python = legacy_model_dir / "venv" / "bin" / "python"
    python_cmd = str(venv_python) if venv_python.exists() else sys.executable

    ml_out_dir = case_dir / "analysis" / "ml_classification"
    ml_out_dir.mkdir(parents=True, exist_ok=True)

    if not scanner_script.exists():
        return {
            "status": "UNAVAILABLE",
            "verdict": "UNAVAILABLE",
            "malware_probability": 0.0,
            "reason": f"Scanner script not found at {scanner_script}",
        }

    try:
        proc = subprocess.run(
            [python_cmd, str(scanner_script), str(apk_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        reports_dir = model_dir / "reports"
        matched_report = None
        case_report_file = None
        if reports_dir.exists():
            apk_hash = hashlib.sha256(apk_path.read_bytes()).hexdigest().lower()
            for r_file in sorted(reports_dir.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
                try:
                    data = json.loads(r_file.read_text(encoding="utf-8"))
                    if str(data.get("sha256", "")).lower() == apk_hash:
                        matched_report = data
                        case_report_file = ml_out_dir / f"ml_assessment_{apk_path.stem}.json"
                        case_report_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
                        break
                except Exception:
                    continue

        if matched_report:
            assessment = matched_report.get("maliciousness_assessment", {})
            return {
                "status": "SUCCESS",
                "verdict": assessment.get("verdict", "UNKNOWN"),
                "malware_probability": assessment.get("maliciousness_probability", 0.0),
                "benign_probability": assessment.get("benign_probability", 0.0),
                "classification": matched_report.get("classification", "UNKNOWN"),
                "highlighted_threats": assessment.get("highlighted_threats", []),
                "active_features": assessment.get("active_feature_count", 0),
                "report_file": str(case_report_file) if case_report_file else "",
                "raw": matched_report,
            }
        else:
            return {
                "status": "COMPLETED_NO_REPORT",
                "verdict": "INCONCLUSIVE",
                "malware_probability": 0.0,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "verdict": "ERROR",
            "malware_probability": 0.0,
            "reason": str(e),
        }


# ============================================================================
# Interactive Terminal Menu
# ============================================================================

def setup_case_workflow() -> Path:
    """Prompt user on startup to either start a new case or resume an existing case from a list."""
    clear_screen()
    base_dir = get_default_base_dir()
    existing_cases = list_cases(base_dir)
    active = get_active_case()

    print(f"\n{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}|                  CASE & INVESTIGATION SETUP                     |{C_RESET}")
    print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
    if active and active.exists():
        print(f"  Current Active Case : {C_GREEN}{active.name}{C_RESET} ({active})")
    else:
        print(f"  Current Active Case : {C_YELLOW}None (No Active Investigation){C_RESET}")

    print(f"\n{C_BOLD}Select Case Option:{C_RESET}")
    print(f"  {C_CYAN}[1]{C_RESET} {C_BOLD}Start a New Case / Scan{C_RESET} (Create dedicated test subfolders)")
    print(f"  {C_CYAN}[2]{C_RESET} {C_BOLD}Resume an Existing Case / Scan{C_RESET} (Select from list of cases)")
    if active and active.exists():
        print(f"  {C_CYAN}[3]{C_RESET} {C_BOLD}Continue with Current Active Case ({active.name}){C_RESET}")

    try:
        opt = input(f"\n{C_BOLD}Enter choice [1-3] (Default: 1):{C_RESET} ").strip()
    except (KeyboardInterrupt, EOFError):
        opt = "1"

    if opt in ("2", "resume"):
        if not existing_cases:
            print(f"\n{C_YELLOW}[!] No existing cases found in {base_dir}. Initializing new scan...{C_RESET}")
            return prompt_scan_name(open_folder=True)
        print(f"\n{C_BOLD}Existing Forensic Cases & Scans:{C_RESET}")
        for idx, c in enumerate(existing_cases, 1):
            is_active = active and (c["path"] == str(active))
            badge = f"{C_GREEN}[ACTIVE]{C_RESET}" if is_active else "        "
            print(f"  [{idx:2}] {badge} {C_CYAN}{c['case_id']:<22}{C_RESET} {c['created_at_utc'][:10]} | {c['description'][:35] or 'Android Forensic Scan'}")
        sel = input(f"\n{C_BOLD}Enter case number to activate and open (0 for new scan):{C_RESET} ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(existing_cases):
            selected = Path(existing_cases[int(sel) - 1]["path"])
            set_active_case(selected)
            print(f"{C_GREEN}[+] Activated case: {selected.name}{C_RESET}")
            print(f"{C_CYAN}[➜] Opening scan folder in system file manager...{C_RESET}")
            open_system_folder(selected)
            return selected
        elif sel == "0":
            return prompt_scan_name(open_folder=True)
        else:
            return prompt_scan_name(open_folder=True)
    elif opt == "3" and active and active.exists():
        return active
    else:
        return prompt_scan_name(open_folder=True)


def run_interactive_menu() -> None:
    """Run the main interactive forensic menu with unified workflows and subfolders."""
    # Always prompt the investigator on startup to start a new case or resume from existing cases
    setup_case_workflow()

    while True:
        clear_screen()
        print_banner()
        active = get_active_case()
        if not active or not active.exists():
            active = setup_case_workflow()

        print(f"\n{C_BOLD}Forensic Investigation Workflows:{C_RESET}")
        menu_items = [
            ("1", "Static APK Forensics & ML", "Decompile, inspect manifest, permissions & ML triage"),
            ("2", "Connected Phone Scanner", "Device hardware details, full app inventory & APK pull"),
            ("3", "Deep Application Inspector", "Component analysis, risk scoring & signature audit"),
            ("4", "Forensics & Telemetry", "Logcat extraction, SMS forensics, PCAP network dissection"),
            ("5", "Generate Forensic Reports", "Generate Dossier in PDF (with browser preview) & Markdown"),
            ("6", "Manage Scans & Evidence", "Switch scan, create scan folder or open in file manager"),
            ("7", "Verify Evidence Integrity", "Cryptographic Hash Manifest Verification (SHA-256)"),
            ("8", "System & Tool Diagnostics", "Inspect ADB, ML Models, Python environment & tools"),
            ("0", "Exit AndroMalHut", "Safely exit forensic toolkit"),
        ]

        for num, title, desc in menu_items:
            num_badge = f"{C_CYAN}{C_BOLD}[{num}]{C_RESET}"
            print(f"  {num_badge} {C_BOLD}{title:<30}{C_RESET} {C_GRAY}{desc}{C_RESET}")

        try:
            choice = input(f"\n{C_BOLD}Select workflow [0-8]:{C_RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting AndroMalHut. Stay safe.")
            break

        print()

        if choice == "1":
            # === [1] Static APK Forensics & ML ===
            clear_screen()
            case_dir = require_case()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [1] COMPREHENSIVE APK SCANNER & THREAT TRIAGE           |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")

            # Check for existing APKs in case evidence
            existing_apks: List[Path] = []
            for sub in ("original_apks", "device_apks"):
                ed = case_dir / "evidence" / sub
                if ed.exists():
                    existing_apks.extend(sorted(ed.glob("*.apk")))

            apk_target: Optional[Path] = None
            if existing_apks:
                print(f"\n{C_BOLD}Existing APKs discovered in active scan evidence:{C_RESET}")
                for i, ea in enumerate(existing_apks, 1):
                    print(f"  [{i}] {ea.name} ({ea.parent.name})")
                print(f"  [P] Specify a different local file path")
                sel = input(f"\n{C_BOLD}Select APK number or enter file path:{C_RESET} ").strip()
                if sel.isdigit() and 1 <= int(sel) <= len(existing_apks):
                    apk_target = existing_apks[int(sel) - 1]
                elif sel.lower() == "p" or sel:
                    clean_p = sel.strip("'\"")
                    if clean_p.lower() != "p":
                        apk_target = Path(clean_p)
                else:
                    input(f"\n{C_GRAY}Press Enter to return to main menu...{C_RESET}")
                    continue

            if apk_target is None:
                apk_in = input(f"{C_BOLD}Enter path to suspicious APK:{C_RESET} ").strip().strip("'\"")
                if not apk_in:
                    input(f"\n{C_GRAY}Press Enter to return to main menu...{C_RESET}")
                    continue
                apk_target = Path(apk_in)

            if not apk_target.exists() or not apk_target.is_file():
                print(f"{C_RED}[!] File not found: {apk_target}{C_RESET}")
                input(f"\n{C_GRAY}Press Enter to return to main menu...{C_RESET}")
                continue

            # Check if already preserved in case
            if str(case_dir) in str(apk_target.resolve()):
                preserved = apk_target
            else:
                print(f"[*] Preserving APK into case evidence: evidence/original_apks/...")
                preserved = record_evidence_file(
                    case_dir=case_dir,
                    source_file=apk_target,
                    target_subfolder="original_apks",
                    description=f"Imported suspicious APK: {apk_target.name}",
                )
                print(f"{C_GREEN}[+] Preserved evidence:{C_RESET} {preserved}")

            # Step 1: Machine Learning Classifier
            print(f"\n{C_BOLD}[1/3] Running ML Malware Classifier (Drebin + AndroZoo RF)...{C_RESET}")
            with ForensicSpinner("Analyzing features against 25,722 trained malware samples..."):
                ml_res = run_ml_classifier(preserved, case_dir)

            if ml_res.get("status") == "SUCCESS":
                v = ml_res.get("verdict", "UNKNOWN")
                p = ml_res.get("malware_probability", 0.0) * 100
                v_color = C_RED if "MALICIOUS" in v else (C_GREEN if "BENIGN" in v else C_YELLOW)
                print(f"    Verdict              : {v_color}{C_BOLD}{v}{C_RESET}")
                print(f"    Malware Probability  : {v_color}{p:.1f}%{C_RESET} (Benign: {100 - p:.1f}%)")
                print(f"    Active Risk Features : {ml_res.get('active_features', 0)}")
                for th in ml_res.get("highlighted_threats", []):
                    print(f"    {C_YELLOW}[!] {th}{C_RESET}")
                print(f"    ML Output Saved      : {ml_res.get('report_file')}")
            else:
                print(f"{C_YELLOW}[!] ML Classifier note: {ml_res.get('status')} ({ml_res.get('reason', '')}){C_RESET}")

            # Step 2: Deep Static Dissection & Indicator Extraction
            print(f"\n{C_BOLD}[2/3] Performing Static APK Dissection & Pattern Extraction...{C_RESET}")
            out_analysis = case_dir / "analysis" / "apk_analysis"
            with ForensicSpinner("Parsing manifest, DEX string pool, native libraries & network IOCs..."):
                res = analyze_apk(preserved, output_analysis_dir=out_analysis)
                json_save = out_analysis / f"apk_analysis_{preserved.stem}.json"
                json_save.write_text(json.dumps(res, indent=2), encoding="utf-8")

            m = res.get("manifest", {})
            pa = res.get("permissions_analysis", {})
            net = res.get("network_indicators", {})
            prov = res.get("provenance", {})

            print(f"    Package Identifier   : {m.get('package_name')} ({m.get('application_label') or 'Unknown App'})")
            print(f"    Download Source      : {C_BOLD}{prov.get('download_source', 'Unknown')}{C_RESET}")
            print(f"    Install / Acquisition: {prov.get('first_install_time', 'Unknown')}")
            print(f"    Version Info         : {m.get('version_name')} (code {m.get('version_code')})")
            print(f"    Permission Score     : {pa.get('risk_score', 0)}/100 ({pa.get('overall_severity', 'INFO')})")
            print(f"    Exported Components  : {len(m.get('exported_components', []))}")
            print(f"    Observed Capabilities: {', '.join(pa.get('capabilities', [])) or 'None'}")
            print(f"    Network IOCs Found   : {len(net.get('urls', []))} URLs, {len(net.get('ipv4', []))} IPs, {len(net.get('domains', []))} domains")
            print(f"    Static Analysis Saved: {json_save}")

            # Step 3: Local AI Triage (Ollama / Qwen)
            print(f"\n{C_BOLD}[3/3] AI Forensic Triage & Explanation...{C_RESET}")
            ollama_ok, models, _ = check_ollama_status()
            if ollama_ok and models:
                run_ai = input(f"Run local AI triage briefing using {models[0]}? [Y/n]: ").strip().lower()
                if run_ai in ("", "y", "yes"):
                    with ForensicSpinner(f"Querying Ollama model {models[0]} for defensive triage..."):
                        ai_res = run_case_ollama_explanation(case_dir, model_name=models[0])
                    if ai_res.get("status") == "SUCCESS":
                        triage_dir = case_dir / "analysis" / "ai_triage"
                        triage_dir.mkdir(parents=True, exist_ok=True)
                        triage_file = triage_dir / f"ai_triage_{preserved.stem}.md"
                        triage_file.write_text(ai_res.get("explanation_markdown", ""), encoding="utf-8")
                        print(f"{C_GREEN}[+] AI Forensic Briefing Saved:{C_RESET} {triage_file}")
                        print("\n" + ai_res.get("explanation_markdown", "")[:400] + "\n...")
            else:
                print(f"{C_GRAY}[i] Ollama offline or no models found; skipping AI narrative.{C_RESET}")

            # Immediate Report Generation
            gen_rep = input(f"\n{C_BOLD}Generate executive PDF and Markdown reports now? [Y/n]:{C_RESET} ").strip().lower()
            if gen_rep in ("", "y", "yes"):
                with ForensicSpinner("Compiling forensic reports and rendering PDF dossier..."):
                    md_path = generate_markdown_report(case_dir)
                    pdf_path, pdf_err = generate_pdf_report(case_dir)

                print(f"{C_GREEN}[+] Markdown Report:{C_RESET} {md_path}")
                if pdf_path:
                    print(f"{C_GREEN}[+] Executive PDF Dossier:{C_RESET} {pdf_path}")
                    print(f"\n{C_BOLD}Report Actions:{C_RESET}")
                    print("  [1] Open PDF Dossier in Web Browser (Firefox / Chrome / Chromium)")
                    print("  [2] Open Reports Folder in File Manager")
                    print("  [3] Continue")
                    rep_opt = input(f"\n{C_BOLD}Select action [1-3] (Default: 1):{C_RESET} ").strip()
                    if rep_opt in ("", "1"):
                        open_pdf_in_browser(pdf_path)
                    elif rep_opt == "2":
                        open_system_folder(pdf_path.parent)
                else:
                    print(f"{C_YELLOW}[!] PDF skipped: {pdf_err}{C_RESET}")

        elif choice == "2":
            # === [2] Connected Phone Scanner ===
            clear_screen()
            case_dir = require_case()
            if not is_adb_installed():
                print(f"{C_RED}[!] ADB is not installed. Install with: sudo apt install adb{C_RESET}")
            else:
                devs = list_connected_devices()
                if not devs:
                    print(f"{C_YELLOW}[!] No connected Android devices detected.{C_RESET}")
                    print("    1. Verify USB debugging is enabled in Developer Options.")
                    print("    2. Re-plug USB cable and authorize computer on the phone screen.")
                else:
                    print(f"{C_GREEN}[+] Connected Devices ({len(devs)}):{C_RESET}")
                    for d in devs:
                        print(f"    • Serial: {d['serial']} | State: {d['state']} | Model: {d['model']} ({d['product']})")

                    print(f"\n{C_BOLD}Device Operations:{C_RESET}")
                    print("  [1] Dump Hardware, Build & OS Properties (device_info.json)")
                    print("  [2] Dump Complete Application Inventory (JSON & CSV)")
                    print("  [3] Pull Application APK from Device")
                    print("  [0] Return to Main Menu")

                    dev_sub = input(f"\n{C_BOLD}Select operation [0-3]:{C_RESET} ").strip()
                    if dev_sub == "1":
                        info = collect_device_info()
                        if info.get("status") == "SUCCESS":
                            info_dir = case_dir / "evidence" / "device_inventory"
                            info_dir.mkdir(parents=True, exist_ok=True)
                            (info_dir / "device_info.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
                            print(f"{C_GREEN}[+] Device Information Collected:{C_RESET}")
                            for k, v in info.items():
                                print(f"    {k:<24}: {v}")
                            print(f"{C_GREEN}[+] Saved to:{C_RESET} {info_dir / 'device_info.json'}")
                        else:
                            print(f"{C_RED}[!] Device collection error: {info.get('error')}{C_RESET}")

                    elif dev_sub == "2":
                        print("[*] Querying package manager for installed applications...")
                        inv = inventory_installed_applications()
                        if inv.get("status") == "SUCCESS":
                            j_out, c_out = export_inventory_files(inv, case_dir)
                            print(f"{C_GREEN}[+] Inventory complete: {inv['total_apps']} apps ({inv['user_apps_count']} user apps).{C_RESET}")
                            print(f"    JSON Export: {j_out}")
                            print(f"    CSV Export:  {c_out}")
                        else:
                            print(f"{C_RED}[!] Application inventory error: {inv.get('error')}{C_RESET}")

                    elif dev_sub == "3":
                        pkg = input("Enter package name to pull (e.g. com.example.app): ").strip()
                        if pkg:
                            pull_res = pull_application_apk(pkg, case_dir)
                            if pull_res.get("status") == "SUCCESS":
                                preserved_apk = Path(pull_res["preserved_evidence_path"])
                                print(f"{C_GREEN}[+] APK pulled and preserved:{C_RESET} {preserved_apk}")
                                run_now = input("\nRun Comprehensive Malware Scanner on this APK now? [Y/n]: ").strip().lower()
                                if run_now in ("", "y", "yes"):
                                    # Trigger Option 1 workflow on pulled APK
                                    ml_res = run_ml_classifier(preserved_apk, case_dir)
                                    out_analysis = case_dir / "analysis" / "apk_analysis"
                                    res = analyze_apk(preserved_apk, output_analysis_dir=out_analysis)
                                    (out_analysis / f"apk_analysis_{preserved_apk.stem}.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
                                    print(f"{C_GREEN}[+] Analysis completed for {preserved_apk.name}{C_RESET}")
                            else:
                                print(f"{C_RED}[!] Error pulling APK: {pull_res.get('error')}{C_RESET}")

        elif choice == "3":
            # === [3] Deep Application Inspector ===
            clear_screen()
            case_dir = require_case()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [3] DEEP APPLICATION FORENSIC INSPECTOR                 |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            packages: List[Tuple[str, str]] = []
            inventory_dir = case_dir / "evidence" / "device_inventory"
            inventory_files = sorted(
                inventory_dir.glob("installed_apps_*.json"),
                key=lambda f: f.stat().st_mtime,
                reverse=True,
            ) if inventory_dir.exists() else []

            def collect_apps(obj):
                if isinstance(obj, dict):
                    pkg_name = next(
                        (obj.get(k) for k in ("package_name", "packageName", "package")
                         if isinstance(obj.get(k), str) and "." in obj.get(k)),
                        None,
                    )
                    label = next(
                        (obj.get(k) for k in ("application_label", "app_label", "label", "name")
                         if isinstance(obj.get(k), str) and obj.get(k).strip()),
                        "",
                    )
                    if pkg_name:
                        friendly = resolve_friendly_app_name(pkg_name, label)
                        packages.append((friendly, pkg_name))
                    else:
                        for value in obj.values():
                            collect_apps(value)
                elif isinstance(obj, list):
                    for value in obj:
                        collect_apps(value)

            if inventory_files:
                try:
                    collect_apps(json.loads(inventory_files[0].read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    pass

            try:
                raw = subprocess.run(
                    ["adb", "shell", "pm", "list", "packages", "-3"],
                    capture_output=True, text=True, timeout=30, check=True,
                ).stdout
                device_packages = sorted({
                    line.strip().removeprefix("package:")
                    for line in raw.splitlines()
                    if line.strip().startswith("package:")
                })
                labels = {pkg: label for label, pkg in packages}
                if device_packages:
                    packages = [(resolve_friendly_app_name(pkg, labels.get(pkg)), pkg) for pkg in device_packages]
            except Exception:
                packages = list({pkg: (label, pkg) for label, pkg in packages}.values())

            packages = sorted({pkg: (label, pkg) for label, pkg in packages}.values(), key=lambda item: item[0].lower())

            if not packages:
                print(f"{C_YELLOW}[!] No cached or live third-party packages found.{C_RESET}")
                pkg = input("Enter package name manually (e.g. com.example.app): ").strip()
            else:
                print(f"\n{C_BOLD}Installed User Applications — Select one to inspect:{C_RESET}")
                for idx, (label, package_id) in enumerate(packages, 1):
                    print(f"  {idx:3}. {label:<32} [{package_id}]")
                selection = input(f"\n{C_BOLD}Enter app number or package name (0 to cancel):{C_RESET} ").strip()
                if selection == "0" or not selection:
                    pkg = ""
                elif selection.isdigit() and 1 <= int(selection) <= len(packages):
                    label, pkg = packages[int(selection) - 1]
                    print(f"[*] Selected: {label} ({pkg})")
                else:
                    pkg = selection

            if pkg:
                res = inspect_package(pkg)
                if res.get("status") == "SUCCESS":
                    friendly_name = resolve_friendly_app_name(pkg, res.get("app_name"))
                    meta = res.get("dumpsys_metadata", {})
                    apk_paths = res.get("apk_paths", [])

                    # Attempt fast on-device SHA256 calculation
                    on_device_hash = ""
                    if apk_paths and is_adb_installed():
                        try:
                            h_proc = subprocess.run(
                                ["adb", "shell", "sha256sum", apk_paths[0]],
                                capture_output=True, text=True, timeout=15
                            )
                            if h_proc.returncode == 0 and h_proc.stdout.strip():
                                on_device_hash = h_proc.stdout.strip().split()[0].strip()
                        except Exception:
                            pass

                    print(f"\n{C_GREEN}[+] Deep Application Inspection: {friendly_name} ({pkg}){C_RESET}")
                    print(f"    Application Name : {C_BOLD}{friendly_name}{C_RESET}")
                    print(f"    Package ID       : {pkg}")
                    print(f"    Classification   : {'System App' if res['is_system_app'] else 'Third-Party / User App'}")
                    print(f"    Currently Running: {'YES' if res['is_running'] else 'No'}")
                    print(f"    APK Path(s)      : {', '.join(res['apk_paths'])}")
                    print(f"    Download Source  : {C_CYAN}{meta.get('download_source', 'Unknown')}{C_RESET}")
                    if on_device_hash:
                        print(f"    SHA-256 (Device) : {C_GRAY}{on_device_hash}{C_RESET}")
                    print(f"    Version          : {meta.get('version_name')} (code {meta.get('version_code')})")
                    print(f"    First Install    : {meta.get('first_install_time')}")
                    print(f"    Last Update      : {meta.get('last_update_time')}")
                    print(f"    Requested Perms  : {len(meta.get('requested_permissions', []))} permissions")
                    print(f"    Runtime Granted  : {len(meta.get('runtime_permissions', []))} permissions")

                    print(f"\n{C_BOLD}Investigation Actions for this Application:{C_RESET}")
                    print(f"  {C_CYAN}[1]{C_RESET} Verify App Name & Threat Reputation Online via Hash (SHA-256)")
                    print(f"  {C_CYAN}[2]{C_RESET} Pull APK from device into case evidence & run ML Malware Scanner")
                    print(f"  {C_CYAN}[0]{C_RESET} Return to Application List")

                    act = input(f"\n{C_BOLD}Select action [0-2] (Default: 1):{C_RESET} ").strip()
                    if act in ("", "1"):
                        print(f"\n[*] Querying Google Play, CIRCL NSRL and threat registries for {pkg}...")
                        with ForensicSpinner("Verifying application identity and hash reputation online..."):
                            online_res = verify_package_online(pkg, on_device_hash)
                        print(f"\n{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
                        print(f"{C_CYAN}{C_BOLD}|             ONLINE HASH & APP REPUTATION VERIFICATION           |{C_RESET}")
                        print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
                        print(f"  Package Identifier : {C_BOLD}{online_res.get('package_name')}{C_RESET}")
                        print(f"  Verified App Name  : {C_GREEN}{online_res.get('app_name')}{C_RESET}")
                        print(f"  Download Source    : {online_res.get('verified_source')}")
                        print(f"  Play Store Status  : {online_res.get('play_store_status')}")
                        rep_color = C_GREEN if ("BENIGN" in online_res.get("threat_reputation", "") or "CLEAN" in online_res.get("threat_reputation", "")) else C_RED
                        print(f"  Threat Reputation  : {rep_color}{online_res.get('threat_reputation')}{C_RESET}")
                        if online_res.get("details"):
                            for d in online_res["details"]:
                                print(f"    • {d}")
                        print(f"{C_CYAN}+-----------------------------------------------------------------+{C_RESET}")
                        pull_after = input("\nPull this APK from device into case evidence now? [y/N]: ").strip().lower()
                        if pull_after == "y":
                            act = "2"

                    if act == "2":
                        pull_res = pull_application_apk(pkg, case_dir)
                        if pull_res.get("status") == "SUCCESS":
                            preserved_apk = Path(pull_res["preserved_evidence_path"])
                            print(f"{C_GREEN}[+] APK pulled to:{C_RESET} {preserved_apk}")
                            run_scan = input("\nRun Comprehensive Malware Scanner on this APK now? [Y/n]: ").strip().lower()
                            if run_scan in ("", "y", "yes"):
                                run_ml_classifier(preserved_apk, case_dir)
                                out_analysis = case_dir / "analysis" / "apk_analysis"
                                a_res = analyze_apk(preserved_apk, output_analysis_dir=out_analysis)
                                (out_analysis / f"apk_analysis_{preserved_apk.stem}.json").write_text(json.dumps(a_res, indent=2), encoding="utf-8")
                                print(f"{C_GREEN}[+] Static and ML analysis complete.{C_RESET}")
                        else:
                            print(f"{C_RED}[!] Error pulling APK: {pull_res.get('error')}{C_RESET}")
                else:
                    print(f"{C_RED}[!] Error inspecting package: {res.get('error')}{C_RESET}")

        elif choice == "4":
            # === [4] Forensics & Telemetry ===
            clear_screen()
            case_dir = require_case()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [4] FORENSICS, TELEMETRY & NETWORK IOCs                 |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print("  [1] Collect Device Logcat & System Logs")
            print("  [2] Extract / Import SMS Evidence (Phishing & 2FA Analysis)")
            print("  [3] Dissect Network PCAP / PCAPNG & Extract C2 Traffic")
            print("  [4] Aggregate Network & C2 Indicators across All Evidence")
            print("  [5] Correlate Chronological Incident Timeline")
            print("  [0] Return to Main Menu")

            tele_sub = input(f"\n{C_BOLD}Select forensics operation [0-5]:{C_RESET} ").strip()
            if tele_sub == "1":
                print("[*] Collecting available device logs via ADB...")
                with ForensicSpinner("Collecting logcat and system logs..."):
                    log_res = collect_device_logs(case_dir)
                if log_res.get("status") == "SUCCESS":
                    print(f"{C_GREEN}[+] Successfully collected {log_res['collected_logs_count']} log streams:{C_RESET}")
                    for item in log_res.get("files", []):
                        print(f"    • {item['name']}: {item['path']}")
                else:
                    print(f"{C_RED}[!] Error collecting device logs: {log_res.get('error')}{C_RESET}")

            elif tele_sub == "2":
                print(f"\n{C_BOLD}SMS Evidence Collection & Ingestion:{C_RESET}")
                print("  [1] Authorized read-only ADB query")
                print("  [2] Import external SMS backup file (XML / JSON / CSV)")
                sms_opt = input("Select [1-2]: ").strip()
                if sms_opt == "1":
                    adb_res = attempt_adb_sms_export(case_dir)
                    if adb_res.get("status") == "SUCCESS":
                        print(f"{C_GREEN}[+] Preserved {adb_res['exported_count']} raw SMS records.{C_RESET}")
                    else:
                        print(f"{C_YELLOW}[!] {adb_res.get('status')}:{C_RESET} {adb_res.get('reason')}")
                elif sms_opt == "2":
                    sms_path_in = input("Enter path to SMS backup file: ").strip().strip("'\"")
                    if sms_path_in:
                        sp = Path(sms_path_in)
                        if not sp.exists():
                            print(f"{C_RED}[!] File does not exist: {sp}{C_RESET}")
                        else:
                            sres = import_and_analyze_sms_file(sp, case_dir)
                            an = sres.get("analysis", {})
                            print(f"{C_GREEN}[+] Analyzed {an.get('total_messages')} messages.{C_RESET}")
                            print(f"    Suspicious / 2FA messages: {an.get('flagged_messages_count')}")
                            print(f"    Extracted URLs: {an.get('extracted_urls_count')}")

            elif tele_sub == "3":
                cap_in = input("Enter path to network capture (PCAP/PCAPNG) or network text log: ").strip().strip("'\"")
                if cap_in:
                    cap_path = Path(cap_in)
                    if not cap_path.exists():
                        print(f"{C_RED}[!] File not found: {cap_path}{C_RESET}")
                    else:
                        preserved = record_evidence_file(
                            case_dir=case_dir,
                            source_file=cap_path,
                            target_subfolder="network_captures",
                            description=f"Imported network capture: {cap_path.name}",
                        )
                        print(f"{C_GREEN}[+] Evidence recorded:{C_RESET} {preserved}")
                        print("[*] Dissecting network packets and extracting C2 indicators...")
                        with ForensicSpinner("Running tshark protocol dissection & extracting IOCs..."):
                            res = analyze_network_evidence(preserved, case_dir=case_dir)
                        if res.get("status") == "SUCCESS":
                            print(f"{C_GREEN}[+] Discovered {res['indicators_count']} indicators.{C_RESET}")
                            for ind in res.get("indicators", [])[:10]:
                                print(f"    • [{ind.get('indicator_type')}] {ind.get('indicator')} (Conf: {ind.get('confidence')})")
                        else:
                            print(f"{C_RED}[!] Network analysis error: {res.get('error')}{C_RESET}")

            elif tele_sub == "4":
                print(f"\n{C_BOLD}Aggregating Discovered C2 Indicators across Case Evidence...{C_RESET}")
                apk_dir = case_dir / "analysis" / "apk_analysis"
                net_dir = case_dir / "analysis" / "network_analysis"
                found = 0
                if apk_dir.exists():
                    for f in apk_dir.glob("*.json"):
                        data = json.loads(f.read_text(encoding="utf-8"))
                        net = data.get("network_indicators", {})
                        for u in net.get("urls", []):
                            found += 1
                            print(f"  [APK URL]    {u['indicator']} ({u['source']})")
                        for ip in net.get("ipv4", []):
                            found += 1
                            print(f"  [APK IPv4]   {ip['indicator']} ({ip['source']})")
                        for dom in net.get("domains", []):
                            found += 1
                            print(f"  [APK Domain] {dom['indicator']} ({dom['source']})")

                if net_dir.exists():
                    for f in net_dir.glob("*.json"):
                        data = json.loads(f.read_text(encoding="utf-8"))
                        for ind in data.get("indicators", []):
                            found += 1
                            print(f"  [{ind.get('indicator_type')}] {ind.get('indicator')} ({ind.get('confidence')} - {ind.get('reason')})")

                if found == 0:
                    print(f"{C_YELLOW}[!] No network indicators currently discovered.{C_RESET}")

            elif tele_sub == "5":
                print("[*] Correlating incident timeline across all case artifacts...")
                with ForensicSpinner("Compiling timeline across device events and evidence..."):
                    events = build_incident_timeline(case_dir)
                print(f"{C_GREEN}[+] Successfully correlated {len(events)} chronological events.{C_RESET}")
                if events:
                    print(f"\n{C_BOLD}Recent Timeline Events:{C_RESET}")
                    for ev in events[-10:]:
                        print(f"  [{ev.get('timestamp_utc')[:19]}] {ev.get('event_type'):<20} | {ev.get('description')[:70]}")

        elif choice == "5":
            # === [5] Generate Forensic Reports ===
            clear_screen()
            case_dir = require_case()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [5] GENERATE FORENSIC DOSSIER & REPORTS                 |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print("  [1] Complete 16-Section Markdown Forensic Report")
            print("  [2] Professional Executive PDF Dossier (ReportLab)")
            print("  [3] Generate Both (Markdown & PDF)")
            print("  [0] Return to Main Menu")

            rep_sub = input(f"\n{C_BOLD}Select report format [0-3]:{C_RESET} ").strip()
            pdf_path = None
            if rep_sub in ("1", "3"):
                with ForensicSpinner("Rendering 16-section Markdown forensic report..."):
                    md_path = generate_markdown_report(case_dir)
                print(f"{C_GREEN}[+] Markdown Report:{C_RESET} {md_path}")
            if rep_sub in ("2", "3"):
                with ForensicSpinner("Generating cryptographic PDF forensic report..."):
                    pdf_path, pdf_err = generate_pdf_report(case_dir)
                if pdf_path:
                    print(f"{C_GREEN}[+] Executive PDF Dossier:{C_RESET} {pdf_path}")
                else:
                    print(f"{C_RED}[!] PDF generation failed: {pdf_err}{C_RESET}")

            if pdf_path:
                print(f"\n{C_BOLD}Forensic Report Options:{C_RESET}")
                print("  [1] Open PDF Report directly in Web Browser (Firefox / Chrome / Chromium)")
                print("  [2] Open Reports Folder in File Manager")
                print("  [3] Return to Main Menu")
                rep_opt = input(f"\n{C_BOLD}Select option [1-3] (Default: 1):{C_RESET} ").strip()
                if rep_opt in ("", "1"):
                    open_pdf_in_browser(pdf_path)
                elif rep_opt == "2":
                    open_system_folder(pdf_path.parent)

        elif choice == "6":
            # === [6] Manage Scans & Folders ===
            clear_screen()
            base_dir = get_default_base_dir()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [6] SCAN & EVIDENCE FOLDER MANAGER                      |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            active = get_active_case()
            print(f"{C_BOLD}Active Scan:{C_RESET} {C_GREEN if active else C_YELLOW}{active.name if active else 'None'}{C_RESET}")
            print(f"{C_BOLD}Location   :{C_RESET} {active if active else 'N/A'}")
            print("\n  [1] Open Active Scan Folder in File Manager")
            print("  [2] Enter Scan Name (Switch / Open or Create New)")
            print("  [3] List All Existing Scans & Switch")
            print("  [0] Return to Main Menu")

            mgr_sub = input(f"\n{C_BOLD}Select option [0-3]:{C_RESET} ").strip()
            if mgr_sub == "1":
                if active:
                    print(f"{C_CYAN}[➜] Opening active scan folder: {active}{C_RESET}")
                    open_system_folder(active)
                else:
                    print(f"{C_YELLOW}[!] No active scan selected.{C_RESET}")

            elif mgr_sub == "2":
                prompt_scan_name(open_folder=True)

            elif mgr_sub == "3":
                cases = list_cases(base_dir)
                if not cases:
                    print(f"{C_YELLOW}[!] No scans found in {base_dir}.{C_RESET}")
                else:
                    print(f"\n{C_BOLD}Existing Forensic Scans:{C_RESET}")
                    for i, c in enumerate(cases, 1):
                        is_active = active and (c["path"] == str(active))
                        badge = f"{C_GREEN}[ACTIVE]{C_RESET}" if is_active else "        "
                        print(f"  [{i}] {badge} {C_CYAN}{c['case_id']:<24}{C_RESET} {c['created_at_utc'][:10]} | {c['description'][:35]}")
                    sel = input(f"\n{C_BOLD}Select scan number to activate and open (0 to cancel):{C_RESET} ").strip()
                    if sel.isdigit() and 1 <= int(sel) <= len(cases):
                        target_path = Path(cases[int(sel) - 1]["path"])
                        set_active_case(target_path)
                        print(f"{C_GREEN}[+] Activated scan: {target_path.name}{C_RESET}")
                        print(f"{C_CYAN}[➜] Opening scan folder in system file manager...{C_RESET}")
                        open_system_folder(target_path)

        elif choice == "7":
            # === [7] Verify Evidence Integrity ===
            clear_screen()
            case_dir = require_case()
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}|         [7] EVIDENCE INTEGRITY & HASH VERIFICATION              |{C_RESET}")
            print(f"{C_CYAN}{C_BOLD}+-----------------------------------------------------------------+{C_RESET}")
            with ForensicSpinner("Validating SHA-256, SHA-1, and MD5 hashes across preserved evidence..."):
                results = verify_case_hashes(case_dir)
            if not results:
                print(f"{C_YELLOW}[!] No evidence hash manifest recorded for this case.{C_RESET}")
            else:
                verified_count = sum(1 for r in results if r.get("status") == "VERIFIED")
                print(f"Total evidence items: {len(results)} | Verified: {verified_count}")
                for r in results:
                    st = r.get("status")
                    st_str = f"{C_GREEN}[VERIFIED]{C_RESET}" if st == "VERIFIED" else f"{C_RED}[{st}]{C_RESET}"
                    print(f"  {st_str} {r.get('filename')}: {r.get('details')}")

        elif choice == "8":
            # === [8] System Diagnostics ===
            clear_screen()
            display_dependencies()

        elif choice == "0":
            print(f"{C_CYAN}Exiting AndroMalHut. Stay vigilant.{C_RESET}")
            break

        else:
            print(f"{C_RED}[!] Invalid option. Please select 0-8.{C_RESET}")

        input(f"\n{C_GRAY}Press Enter to return to main menu...{C_RESET}")


# ============================================================================
# CLI Command Dispatcher
# ============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="andromalhut",
        description="AndroMalHut - Defensive Android Malware Forensics & Threat Triage Toolkit by aryxan",
        epilog="Authorized educational & defensive forensics. Strictly read-only, never executes malware.",
    )
    parser.add_argument("--case", dest="case_path", help="Path to specific case directory to operate on")
    parser.add_argument("--device", "-s", dest="device_serial", help="Target Android device serial for ADB commands")

    subparsers = parser.add_subparsers(dest="command", help="Forensic Subcommands")

    # init-case
    p_init = subparsers.add_parser("init-case", help="Initialize a new investigation case")
    p_init.add_argument("--desc", default="", help="Case description")
    p_init.add_argument("--investigator", default="", help="Investigator name")
    p_init.add_argument("--device-name", default="", help="Target device name / identifier")

    # check-deps
    subparsers.add_parser("check-deps", help="Verify forensic tools and library availability")

    # devices
    subparsers.add_parser("devices", help="List connected Android devices")

    # collect-adb (device-info)
    subparsers.add_parser("collect-adb", help="Collect device build, properties, and OS metadata via ADB")

    # inventory
    subparsers.add_parser("inventory", help="Inventory all user and system applications installed on device")

    # inspect-app
    p_insp = subparsers.add_parser("inspect-app", help="Inspect a specific installed application package")
    p_insp.add_argument("package", help="Application package name (e.g. com.target.app)")

    # pull-apk
    p_pull = subparsers.add_parser("pull-apk", help="Extract APK file from connected device into case evidence")
    p_pull.add_argument("package", help="Application package name to pull")

    # analyze-apk
    p_apk = subparsers.add_parser("analyze-apk", help="Perform offline static analysis on an APK file")
    p_apk.add_argument("apk_path", help="Path to suspect APK file")

    # analyze-perms
    subparsers.add_parser("analyze-perms", help="Analyze permissions and threat patterns of analyzed APKs")

    # find-c2
    subparsers.add_parser("find-c2", help="Display all extracted C2, IP, and domain indicators")

    # analyze-network
    p_net = subparsers.add_parser("analyze-network", help="Dissect PCAP/PCAPNG capture or parse network log for C2")
    p_net.add_argument("capture_file", help="Path to PCAP/PCAPNG capture or text network log")

    # collect-logs
    subparsers.add_parser("collect-logs", help="Dump logcat and system network stats via ADB")

    # export-sms
    subparsers.add_parser("export-sms", help="Attempt authorized read-only export of SMS messages via ADB")

    # import-sms
    p_sms = subparsers.add_parser("import-sms", help="Import SMS backup file (XML, JSON, CSV) into case")
    p_sms.add_argument("sms_file", help="Path to SMS export file")

    # timeline
    subparsers.add_parser("timeline", help="Correlate chronological incident timeline from case evidence")

    # report
    subparsers.add_parser("report", help="Generate complete 16-section Markdown forensic report")

    # report-pdf
    subparsers.add_parser("report-pdf", help="Generate professional PDF forensic report")

    # explain-ollama
    p_ai = subparsers.add_parser("explain-ollama", help="Generate AI-assisted findings narrative using local Ollama")
    p_ai.add_argument("--model", default="llama3", help="Installed Ollama model name to use")

    # verify-hashes
    subparsers.add_parser("verify-hashes", help="Cryptographically verify preserved evidence against manifest")

    args = parser.parse_args()

    # If no subcommand supplied, open interactive menu
    if not args.command:
        run_interactive_menu()
        return

    # Subcommand Execution
    cmd = args.command

    if cmd == "check-deps":
        display_dependencies()
        return

    if cmd == "init-case":
        case_dir = init_case(
            description=args.desc or "Forensic investigation of Android device/APK",
            investigator=args.investigator,
            device_identifier=args.device_name,
        )
        print(f"[+] Initialized case: {case_dir.name} -> {case_dir}")
        return

    if cmd == "devices":
        devs = list_connected_devices()
        if not devs:
            print("[!] No connected Android devices found.")
        else:
            print(f"[+] Connected Android Devices ({len(devs)}):")
            for d in devs:
                print(f"    • Serial: {d['serial']} | State: {d['state']} | Model: {d['model']}")
        return

    # All commands below require a case directory
    case_dir = require_case(args.case_path)

    if cmd == "collect-adb":
        info = collect_device_info(serial=args.device_serial)
        if info.get("status") == "SUCCESS":
            print(f"[+] Device Information Collected for {info.get('device_serial')}:")
            for k, v in info.items():
                print(f"    {k:<24}: {v}")
        else:
            print(f"[!] Error: {info.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "inventory":
        inv = inventory_installed_applications(serial=args.device_serial)
        if inv.get("status") == "SUCCESS":
            j_out, c_out = export_inventory_files(inv, case_dir)
            print(f"[+] Application inventory completed: {inv['total_apps']} total apps.")
            print(f"    JSON Export: {j_out}")
            print(f"    CSV Export:  {c_out}")
        else:
            print(f"[!] Error: {inv.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "inspect-app":
        res = inspect_package(args.package, serial=args.device_serial)
        if res.get("status") == "SUCCESS":
            print(f"[+] Package: {res['package_name']}")
            print(f"    Classification: {'System' if res['is_system_app'] else 'Third-Party'}")
            print(f"    APK Path(s): {', '.join(res['apk_paths'])}")
            meta = res.get("dumpsys_metadata", {})
            print(f"    Version: {meta.get('version_name')} (code {meta.get('version_code')})")
            print(f"    Install Time: {meta.get('first_install_time')}")
            print(f"    Requested Perms ({len(meta.get('requested_permissions', []))}): {', '.join(meta.get('requested_permissions', [])[:5])}...")
        else:
            print(f"[!] Error: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "pull-apk":
        res = pull_application_apk(args.package, case_dir, serial=args.device_serial)
        if res.get("status") == "SUCCESS":
            print(f"[+] Pulled APK to evidence: {res['preserved_evidence_path']}")
        else:
            print(f"[!] Error: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "analyze-apk":
        src_path = Path(args.apk_path)
        if not src_path.exists():
            print(f"[!] File not found: {src_path}", file=sys.stderr)
            sys.exit(1)
        preserved = record_evidence_file(
            case_dir=case_dir,
            source_file=src_path,
            target_subfolder="original_apks",
            description=f"Analyzed APK file: {src_path.name}",
        )
        out_analysis = case_dir / "analysis" / "apk_analysis"
        res = analyze_apk(preserved, output_analysis_dir=out_analysis)
        import json
        json_save = out_analysis / f"apk_analysis_{preserved.stem}.json"
        json_save.write_text(json.dumps(res, indent=2), encoding="utf-8")
        pa = res.get("permissions_analysis", {})
        m = res.get("manifest", {})
        print(f"[+] Analysis Complete for {m.get('package_name')}:")
        print(f"    Threat Severity: {pa.get('overall_severity')} (Risk Score: {pa.get('risk_score')}/100)")
        print(f"    Identified Capabilities: {', '.join(pa.get('capabilities', []))}")
        print(f"    Analysis JSON: {json_save}")

    elif cmd == "analyze-perms":
        apk_dir = case_dir / "analysis" / "apk_analysis"
        for f in apk_dir.glob("*.json"):
            import json
            data = json.loads(f.read_text(encoding="utf-8"))
            pa = data.get("permissions_analysis", {})
            m = data.get("manifest", {})
            print(f"[+] {m.get('package_name')} Threat: {pa.get('overall_severity')} (Score: {pa.get('risk_score')}/100)")
            for pat in pa.get("matched_threat_patterns", []):
                print(f"    • {pat.get('name')}: {pat.get('description')}")

    elif cmd == "find-c2":
        apk_dir = case_dir / "analysis" / "apk_analysis"
        net_dir = case_dir / "analysis" / "network_analysis"
        import json
        print(f"[+] Indicators of Compromise / Network C2:")
        if apk_dir.exists():
            for f in apk_dir.glob("*.json"):
                data = json.loads(f.read_text(encoding="utf-8"))
                for u in data.get("network_indicators", {}).get("urls", []):
                    print(f"    • [URL] {u['indicator']} ({u['source']})")
                for ip in data.get("network_indicators", {}).get("ipv4", []):
                    print(f"    • [IPv4] {ip['indicator']} ({ip['source']})")
        if net_dir.exists():
            for f in net_dir.glob("*.json"):
                data = json.loads(f.read_text(encoding="utf-8"))
                for ind in data.get("indicators", []):
                    print(f"    • [{ind.get('indicator_type')}] {ind.get('indicator')} (Conf: {ind.get('confidence')})")

    elif cmd == "analyze-network":
        net_file = Path(args.capture_file)
        if not net_file.exists():
            print(f"[!] Network evidence file not found: {net_file}", file=sys.stderr)
            sys.exit(1)
        preserved = record_evidence_file(
            case_dir=case_dir,
            source_file=net_file,
            target_subfolder="network_captures",
            description=f"Analyzed network capture / log: {net_file.name}",
        )
        res = analyze_network_evidence(preserved, case_dir=case_dir)
        if res.get("status") == "SUCCESS":
            print(f"[+] Network analysis complete: {res['indicators_count']} indicators identified.")
        else:
            print(f"[!] Error: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "collect-logs":
        res = collect_device_logs(case_dir, serial=args.device_serial)
        if res.get("status") == "SUCCESS":
            print(f"[+] Collected {res['collected_logs_count']} log files into case evidence.")
        else:
            print(f"[!] Error: {res.get('error')}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "export-sms":
        res = attempt_adb_sms_export(case_dir, serial=args.device_serial)
        if res.get("status") == "SUCCESS":
            print(f"[+] Exported {res['exported_count']} SMS records via ADB.")
        else:
            print(f"[!] Note: {res.get('reason')}")

    elif cmd == "import-sms":
        sms_file = Path(args.sms_file)
        if not sms_file.exists():
            print(f"[!] SMS file not found: {sms_file}", file=sys.stderr)
            sys.exit(1)
        res = import_and_analyze_sms_file(sms_file, case_dir)
        an = res.get("analysis", {})
        print(f"[+] Analyzed {an.get('total_messages')} SMS messages. Flagged: {an.get('flagged_messages_count')}")

    elif cmd == "timeline":
        events = build_incident_timeline(case_dir)
        print(f"[+] Incident timeline compiled: {len(events)} events correlated.")

    elif cmd == "report":
        p = generate_markdown_report(case_dir)
        print(f"[+] Generated Markdown Report: {p}")

    elif cmd == "report-pdf":
        p, err = generate_pdf_report(case_dir)
        if p:
            print(f"[+] Generated PDF Report: {p}")
        else:
            print(f"[!] PDF Report failed: {err}", file=sys.stderr)
            sys.exit(1)

    elif cmd == "explain-ollama":
        res = run_case_ollama_explanation(case_dir, model_name=args.model)
        if res.get("status") == "SUCCESS":
            print(f"[+] Ollama briefing saved: {res.get('saved_file')}")
        else:
            print(f"[!] Ollama Error: {res.get('error')}", file=sys.stderr)

    elif cmd == "verify-hashes":
        results = verify_case_hashes(case_dir)
        verified = sum(1 for r in results if r.get("status") == "VERIFIED")
        print(f"[+] Verification completed: {verified}/{len(results)} items matched recorded hashes.")


if __name__ == "__main__":
    main()
