#!/usr/bin/env bash
set -u
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

if [ -t 1 ]; then
    CYAN=$'\033[1;36m'
    BLUE=$'\033[1;34m'
    GREEN=$'\033[1;32m'
    RESET=$'\033[0m'
else
    CYAN='' BLUE='' GREEN='' RESET=''
fi

clear 2>/dev/null || true
printf '%s\n' "${CYAN}╔══════════════════════════════════════════════════════════╗"
printf '%s\n' "║              A N D R O M A L H U T                       ║"
printf '%s\n' "║         ANDROID FORENSICS & SECURITY TOOLKIT             ║"
printf '%s\n' "╚══════════════════════════════════════════════════════════╝${RESET}"
printf '\n%s\n' "${BLUE}Author:${RESET} aryxan (https://github.com/aryxan/AndroMalHut)"
printf '%s\n' "${BLUE}Workspace:${RESET} $ROOT"
printf '%s\n\n' "${GREEN}Evidence-preserving analysis | Static APK inspection | ML & AI triage${RESET}"

exec bash "$ROOT/launch.sh"
