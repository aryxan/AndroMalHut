#!/usr/bin/env bash
# ==============================================================================
# AndroMalHut - Android Malware Forensics CLI Launcher
# Author: aryxan (https://github.com/aryxan/AndroMalHut)
# ==============================================================================

set -euo pipefail

# Resolve script directory portably
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SCRIPT_DIR}"

# 1. Check for Python 3
if ! command -v python3 &>/dev/null; then
    echo -e "\033[31m[ERROR] Python 3 is required but not installed or not in PATH.\033[0m" >&2
    echo -e "Install Python 3 with: sudo apt update && sudo apt install -y python3 python3-pip python3-venv" >&2
    exit 1
fi

# 2. Check for entry point
if [[ -f "${SCRIPT_DIR}/andromalhut.py" ]]; then
    MAIN_SCRIPT="${SCRIPT_DIR}/andromalhut.py"
elif [[ -f "${SCRIPT_DIR}/droidsleuth.py" ]]; then
    MAIN_SCRIPT="${SCRIPT_DIR}/droidsleuth.py"
else
    echo -e "\033[31m[ERROR] Main entry script not found in ${SCRIPT_DIR}\033[0m" >&2
    exit 1
fi

# 3. Check and activate virtual environment if present
VENV_ACTIVATED=false
for venv_dir in "${SCRIPT_DIR}/.venv" "${SCRIPT_DIR}/venv" "${SCRIPT_DIR}/env"; do
    if [[ -f "${venv_dir}/bin/activate" ]]; then
        # shellcheck disable=SC1091
        source "${venv_dir}/bin/activate"
        VENV_ACTIVATED=true
        break
    fi
done

# 4. Execute droidsleuth.py with all passed arguments or open interactive menu
exec python3 "${MAIN_SCRIPT}" "$@"
