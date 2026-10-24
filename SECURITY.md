# Security Policy

## Overview

AndroMalHut is an Android malware forensics and reverse engineering toolkit. As a forensic tool, maintaining a strict boundary between untrusted evidentiary binaries and the host operating system is critical to investigator safety and evidentiary integrity.

---

## Static vs. Dynamic Analysis Execution Boundaries

### 1. Static Analysis (Default Mode)
- **Zero Untrusted Execution:** All primary workflows—including APK manifest parsing, bytecode DEX scanning, permissions evaluation, hardcoded credentials detection, network indicator extraction, and machine learning inference—are conducted **statically**.
- **No Binaries Executed:** At no point during static analysis is the application loaded, installed, or executed. DEX parsing and string extraction are implemented using pure-Python and standard binary parsing tools (`aapt`, `androguard`, `zipfile`).
- **Cryptographic Model Loading:** ML models are loaded from native XGBoost JSON representation (`andromalhut_xgboost.json`). Legacy `.joblib` model weights are cryptographically verified against pinned SHA-256 checksums before deserialization to prevent arbitrary code execution via pickle attacks.

### 2. Dynamic Sandbox Analysis (Strictly Opt-In)
- **Explicit Opt-In Required:** Dynamic analysis is completely disabled by default. It can only be invoked by explicitly passing `--dynamic` in the CLI or selecting the dynamic sandbox option in the interactive console.
- **Emulator-Only by Default:** The dynamic engine restricts execution to virtual Android emulators (`emulator-*`).
- **Physical Device Protection:** Connecting and attempting to run dynamic analysis against a physical Android device will be **refused** by default. To execute untrusted APKs on a physical test device, an operator must supply `--allow-physical` and provide the typed confirmation `"I ACCEPT RISK"`.
- **Restricted Permissions:** Automatic runtime permission granting (`adb install -g`) is disabled by default. Permissions are only pre-granted if the operator explicitly enables `--grant-permissions`.

---

## Input Validation & Subprocess Safety

- **Package Name Validation:** All package names passed to device queries or ADB commands are strictly validated against `^[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+$` with a 255-character maximum. Any input containing shell metacharacters, spaces, semicolons, quotes, newlines, or command flags is rejected.
- **APK Path Validation:** APK paths are resolved, checked for file existence, and validated to ensure they possess a `.apk` file extension.
- **No Shell Execution:** All internal system and ADB commands are executed using argument arrays via `subprocess.run` or `subprocess.Popen` with `shell=False`.

---

## Data Privacy & Network Boundaries

- **Offline by Default:** All static analysis, rule matching, and ML classifications execute locally on the host machine without network connectivity.
- **Opt-In Online Lookups:** Threat intelligence lookups (Google Play Store, CIRCL hash lookup, VirusTotal) require the explicit `--online` flag. Before any external request is dispatched, an explicit privacy disclosure is displayed detailing the exact metadata transmitted (package name and SHA-256 digest). APK binaries and DEX files are never transmitted externally.

---

## Reporting Security Vulnerabilities

If you discover a security vulnerability or execution escape in AndroMalHut, please report it responsibly:

- **Maintainer:** aryxan
- **Contact:** Open a private security advisory on GitHub via the [AndroMalHut Security Advisory Portal](https://github.com/aryxan/AndroMalHut/security/advisories) or contact the maintainer directly via GitHub profile details.
- Please include reproduction steps, affected versions, and a proof-of-concept if possible.
- Security reports will be acknowledged within 48 hours, and patches will be prioritized on a dedicated release branch.
