#!/usr/bin/env bash
# ==============================================================================
# AndroMalHut Dependency Checker & Installer for Kali Linux / Debian
# Author: aryxan (https://github.com/aryxan/AndroMalHut)
# Safe, transparent inspection of required and optional forensic tools.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "${SCRIPT_DIR}"

C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[31m"
C_GREEN="\033[32m"
C_YELLOW="\033[33m"
C_BLUE="\033[34m"
C_CYAN="\033[36m"
C_GRAY="\033[90m"

echo -e "${C_CYAN}${C_BOLD}"
echo "===================================================================="
echo "          AndroMalHut Forensic Toolkit Dependency Auditor           "
echo "       Author: aryxan (https://github.com/aryxan/AndroMalHut)       "
echo "===================================================================="
echo -e "${C_RESET}"

echo -e "Auditing system for Android forensic tools and dependencies...\n"

MISSING_CORE=0
MISSING_OPTIONAL=0
DEB_PACKAGES=()
PIP_PACKAGES=()

# Helper function
check_cmd() {
    local cmd="$1"
    local name="$2"
    local deb_pkg="$3"
    local is_required="$4"
    local desc="$5"

    if command -v "${cmd}" &>/dev/null; then
        local bin_path
        bin_path="$(command -v "${cmd}")"
        echo -e "  [${C_GREEN}INSTALLED${C_RESET}] ${C_BOLD}${name}${C_RESET} (${bin_path})"
        echo -e "              ${C_GRAY}${desc}${C_RESET}"
    else
        if [[ "${is_required}" == "true" ]]; then
            echo -e "  [${C_RED}MISSING REQUIRED${C_RESET}] ${C_BOLD}${name}${C_RESET}"
            echo -e "              ${C_GRAY}${desc}${C_RESET}"
            MISSING_CORE=$((MISSING_CORE + 1))
        else
            echo -e "  [${C_YELLOW}OPTIONAL MISSING${C_RESET}] ${C_BOLD}${name}${C_RESET}"
            echo -e "              ${C_GRAY}${desc}${C_RESET}"
            MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
        fi
        if [[ -n "${deb_pkg}" ]]; then
            DEB_PACKAGES+=("${deb_pkg}")
        fi
    fi
}

echo -e "${C_BOLD}--- Core Forensic Execution Tools ---${C_RESET}"
check_cmd "python3" "Python 3" "python3 python3-pip python3-venv" "true" "Core script execution environment"

echo -e "\n${C_BOLD}--- Android Device Acquisition Tools ---${C_RESET}"
check_cmd "adb" "Android Debug Bridge (adb)" "adb" "false" "Read-only collection of device properties, app inventory & logcat"

echo -e "\n${C_BOLD}--- APK Static Reverse Engineering Tools ---${C_RESET}"
check_cmd "aapt" "Android Asset Packaging Tool (aapt)" "aapt" "false" "Dumps badging and XML trees from compiled APK assets"
check_cmd "apktool" "Apktool" "apktool" "false" "Decodes resources and smali bytecode disassembly"
check_cmd "jadx" "JADX Decompiler" "jadx" "false" "Offline DEX-to-Java source code decompilation"
check_cmd "apksigner" "APK Signature Verifier (apksigner)" "apksigner" "false" "Verifies APK signature schemes v1 through v4"

echo -e "\n${C_BOLD}--- Network & Packet Dissection Tools ---${C_RESET}"
check_cmd "tshark" "Wireshark / TShark CLI" "tshark" "false" "Dissects PCAP/PCAPNG network captures to extract C2 traffic"

echo -e "\n${C_BOLD}--- Python Forensic Reporting & Analysis Libraries ---${C_RESET}"
if python3 -c "import reportlab" &>/dev/null; then
    echo -e "  [${C_GREEN}INSTALLED${C_RESET}] ${C_BOLD}ReportLab${C_RESET} (Python library)"
    echo -e "              ${C_GRAY}Required for PDF forensic report generation${C_RESET}"
else
    echo -e "  [${C_YELLOW}OPTIONAL MISSING${C_RESET}] ${C_BOLD}ReportLab${C_RESET} (Python library)"
    echo -e "              ${C_GRAY}Required for PDF forensic report generation${C_RESET}"
    PIP_PACKAGES+=("reportlab")
    MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
fi

if python3 -c "import androguard" &>/dev/null; then
    echo -e "  [${C_GREEN}INSTALLED${C_RESET}] ${C_BOLD}androguard${C_RESET} (Python library)"
    echo -e "              ${C_GRAY}Static APK & DEX reverse engineering engine${C_RESET}"
else
    echo -e "  [${C_YELLOW}OPTIONAL MISSING${C_RESET}] ${C_BOLD}androguard${C_RESET} (Python library, pinned: androguard>=4.0.0,<5.0.0)"
    echo -e "              ${C_GRAY}Static APK & DEX reverse engineering engine${C_RESET}"
    PIP_PACKAGES+=("androguard>=4.0.0,<5.0.0")
    MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
fi

if python3 -c "import cryptography" &>/dev/null; then
    echo -e "  [${C_GREEN}INSTALLED${C_RESET}] ${C_BOLD}cryptography${C_RESET} (Python library)"
    echo -e "              ${C_GRAY}Cryptographic APK signing verification${C_RESET}"
else
    echo -e "  [${C_YELLOW}OPTIONAL MISSING${C_RESET}] ${C_BOLD}cryptography${C_RESET} (Python library, pinned: cryptography>=40.0.0)"
    echo -e "              ${C_GRAY}Cryptographic APK signing verification${C_RESET}"
    PIP_PACKAGES+=("cryptography>=40.0.0")
    MISSING_OPTIONAL=$((MISSING_OPTIONAL + 1))
fi

echo -e "\n${C_BOLD}--- Optional Local AI Model Engine ---${C_RESET}"
if command -v "ollama" &>/dev/null; then
    echo -e "  [${C_GREEN}INSTALLED${C_RESET}] ${C_BOLD}Ollama CLI${C_RESET}"
    echo -e "              ${C_GRAY}Local offline LLM for threat narrative explanation${C_RESET}"
else
    echo -e "  [${C_GRAY}NOT DETECTED${C_RESET}] ${C_BOLD}Ollama CLI${C_RESET}"
    echo -e "              ${C_GRAY}Optional: install from https://ollama.ai if local AI interpretation is desired${C_RESET}"
fi

echo -e "\n--------------------------------------------------------------------"
if [[ ${MISSING_CORE} -eq 0 && ${MISSING_OPTIONAL} -eq 0 ]]; then
    echo -e "${C_GREEN}${C_BOLD}[✓] All recommended forensic tools and libraries are present!${C_RESET}"
    echo -e "You can launch AndroMalHut immediately via: ${C_BOLD}./launch.sh${C_RESET}"
    exit 0
fi

echo -e "${C_YELLOW}${C_BOLD}[i] Audit Summary: ${MISSING_CORE} required missing, ${MISSING_OPTIONAL} optional tools missing.${C_RESET}"
echo -e "Note: AndroMalHut includes internal pure-Python parsers for AXML, DEX, and network indicators,"
echo -e "so it remains fully operational even without all external reverse engineering tools.\n"

if [[ ${#DEB_PACKAGES[@]} -gt 0 ]]; then
    echo -e "${C_BOLD}Recommended Debian / Kali Linux package installation command:${C_RESET}"
    echo -e "  ${C_CYAN}sudo apt update && sudo apt install -y ${DEB_PACKAGES[*]}${C_RESET}\n"
fi

if [[ ${#PIP_PACKAGES[@]} -gt 0 ]]; then
    echo -e "${C_BOLD}Recommended Python virtual environment setup:${C_RESET}"
    echo -e "  ${C_CYAN}python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt${C_RESET}\n"
fi

# Interactive prompt if running in interactive terminal
if [[ -t 0 ]]; then
    read -rp "Would you like to setup a Python virtual environment and install requirements now? [y/N]: " setup_choice
    if [[ "${setup_choice,,}" == "y" ]]; then
        echo -e "\n[*] Creating virtual environment in ${SCRIPT_DIR}/.venv..."
        python3 -m venv "${SCRIPT_DIR}/.venv"
        # shellcheck disable=SC1091
        source "${SCRIPT_DIR}/.venv/bin/activate"
        echo "[*] Installing requirements into virtual environment..."
        pip install --upgrade pip
        pip install -r "${SCRIPT_DIR}/requirements.txt"
        echo -e "${C_GREEN}[+] Virtual environment successfully configured!${C_RESET}"
        echo -e "Run ${C_BOLD}./launch.sh${C_RESET} to start AndroMalHut."
    fi
fi
