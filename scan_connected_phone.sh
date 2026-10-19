#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACTIVE_CASE_FILE="$ROOT/.andromalhut_active_case"
if [[ -f "$ACTIVE_CASE_FILE" ]]; then
    CASE="$(cat "$ACTIVE_CASE_FILE")"
else
    CASE="$HOME/Desktop/Android-Forensics/CASE-AUTO-$(date +%Y%m%d)"
fi
SCANNER="$HOME/Android-Forensics/Datasets/Drebin/model/scan_apk.py"
PYTHON="$HOME/Android-Forensics/Datasets/Drebin/model/venv/bin/python"
EVIDENCE="$CASE/evidence/device_apks"
REPORTS="$CASE/reports"
LOG="$REPORTS/device_scan.log"

mkdir -p "$EVIDENCE" "$REPORTS"

for cmd in adb sha256sum; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing dependency: $cmd"
        echo "Install ADB with: sudo apt install android-tools-adb"
        exit 1
    fi
done

if [[ ! -f "$SCANNER" || ! -x "$PYTHON" ]]; then
    echo "Scanner or project Python environment not found."
    echo "Expected scanner: $SCANNER"
    exit 1
fi

echo "[1/4] Checking Android device..."
adb start-server >/dev/null
adb devices -l

if ! adb get-state >/dev/null 2>&1; then
    echo "No authorized device. Enable USB debugging, connect the phone,"
    echo "unlock it, accept the RSA authorization prompt, then rerun."
    exit 1
fi

echo "[2/4] Listing installed third-party apps..."
adb shell pm list packages -3 | tr -d '\r' |
    sed 's/^package://' | sort -u > "$REPORTS/device_packages.txt"

if [[ ! -s "$REPORTS/device_packages.txt" ]]; then
    echo "No third-party packages found."
    exit 1
fi

: > "$LOG"
pulled=0
failed=0

while IFS= read -r package; do
    [[ -n "$package" ]] || continue
    safe="${package//[^A-Za-z0-9._-]/_}"
    dest="$EVIDENCE/$safe"
    mkdir -p "$dest"

    echo "[3/4] Acquiring $package"
    if ! adb shell pm path "$package" 2>/dev/null |
        tr -d '\r' | sed 's/^package://' |
        while IFS= read -r remote; do
            [[ -n "$remote" ]] || continue
            name="${remote##*/}"
            adb pull "$remote" "$dest/$name" >/dev/null || exit 1
        done; then
        echo "ACQUISITION_FAILED $package" | tee -a "$LOG"
        failed=$((failed + 1))
        continue
    fi

    while IFS= read -r -d '' apk; do
        sha256sum "$apk" >> "$REPORTS/device_apk_sha256.txt"
        echo "[4/4] Scanning $package / $(basename "$apk")" |
            tee -a "$LOG"

        # Keep the scanner's output and errors for each acquired APK.
        if "$PYTHON" "$SCANNER" "$apk" >> "$LOG" 2>&1; then
            echo "SCAN_COMMAND_EXITED_OK $apk" >> "$LOG"
            pulled=$((pulled + 1))
        else
            echo "SCAN_COMMAND_FAILED $apk" >> "$LOG"
            failed=$((failed + 1))
        fi
    done < <(find "$dest" -type f -name '*.apk' -print0)
done < "$REPORTS/device_packages.txt"

echo
echo "Acquisition and scan attempts finished."
echo "APK evidence: $EVIDENCE"
echo "Package list: $REPORTS/device_packages.txt"
echo "SHA-256 hashes: $REPORTS/device_apk_sha256.txt"
echo "Scan log: $LOG"
echo "Successful scanner exits: $pulled | Failures: $failed"
echo "Review the log to verify that reports were actually generated."
