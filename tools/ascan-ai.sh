#!/usr/bin/env bash
# ANDROMALHUT_AUTO_PDF_V1
set +e
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
APK="${1:-}"

if [ -z "$APK" ]; then
    echo "Usage: $0 /path/to/application.apk"
    exit 2
fi

bash "$ROOT/tools/ascan-ai-core.sh" "$APK"
SCAN_STATUS=$?

if [ "$SCAN_STATUS" -ne 0 ]; then
    echo "[!] Scanner exited with status $SCAN_STATUS; attempting report generation."
fi

if [ ! -f "$APK" ]; then
    echo "[!] APK not found after scan: $APK"
    exit "$SCAN_STATUS"
fi

REPORT_OUTPUT="$(python3 "$ROOT/tools/build-apk-report.py" "$APK" 2>&1)"
REPORT_STATUS=$?
printf '%s\n' "$REPORT_OUTPUT"

PDF="$(printf '%s\n' "$REPORT_OUTPUT" | sed -n 's/^PDF_REPORT=//p' | tail -n 1)"
if [ "$REPORT_STATUS" -eq 0 ] && [ -n "$PDF" ] && [ -f "$PDF" ]; then
    echo "[+] Opening PDF report: $PDF"
    if command -v firefox >/dev/null 2>&1; then
        firefox "file://$PDF" >/dev/null 2>&1 &
    elif command -v chromium >/dev/null 2>&1; then
        chromium "file://$PDF" >/dev/null 2>&1 &
    elif command -v chromium-browser >/dev/null 2>&1; then
        chromium-browser "file://$PDF" >/dev/null 2>&1 &
    else
        echo "[!] Firefox/Chromium not found. Open manually: $PDF"
    fi
else
    echo "[!] PDF report generation failed. Review the output above."
fi

exit "$SCAN_STATUS"
