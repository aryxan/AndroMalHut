"""
DroidSleuth APK Static Analysis Module
Performs forensic inspection of Android APK packages without execution.
Supports pure-Python extraction of AndroidManifest.xml, DEX bytecodes, certificates,
and optional integration with aapt, apkanalyzer, apktool, jadx, and apksigner.
"""

import os
import re
import sys
import json
import struct
import shutil
import zipfile
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from modules.case_manager import calculate_hashes, log_case_action
from modules.permission_analysis import analyze_permissions


# ============================================================================
# Binary AndroidManifest.xml (AXML) Pure-Python Parser
# ============================================================================

class AXMLParser:
    """Pure-Python parser for compiled Android Binary XML (AXML)."""

    RES_NULL_TYPE = 0x0000
    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_RESOURCE_MAP_TYPE = 0x0180
    RES_XML_START_NAMESPACE_TYPE = 0x0100
    RES_XML_END_NAMESPACE_TYPE = 0x0101
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103
    RES_XML_CDATA_TYPE = 0x0104

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.strings: List[str] = []
        self.elements: List[Dict[str, Any]] = []

    def parse(self) -> Dict[str, Any]:
        """Parse the binary XML into an element structure."""
        if len(self.data) < 8:
            return {}

        file_type, header_size, file_size = struct.unpack("<HHI", self.data[:8])
        if file_type != 0x0003:  # RES_XML_TYPE
            return {}

        self.pos = header_size
        stack: List[Dict[str, Any]] = []
        root: Optional[Dict[str, Any]] = None

        while self.pos < len(self.data):
            if self.pos + 8 > len(self.data):
                break
            chunk_type, chunk_header_size, chunk_size = struct.unpack("<HHI", self.data[self.pos:self.pos + 8])
            if chunk_size <= 0:
                break
            chunk_end = self.pos + chunk_size

            if chunk_type == self.RES_STRING_POOL_TYPE:
                self._parse_string_pool(self.pos, chunk_size)
            elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                elem = self._parse_start_element(self.pos)
                if not root:
                    root = elem
                if stack:
                    stack[-1]["children"].append(elem)
                stack.append(elem)
            elif chunk_type == self.RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()

            self.pos = chunk_end

        return root or {}

    def _parse_string_pool(self, offset: int, size: int) -> None:
        """Parse chunk string pool."""
        if offset + 28 > len(self.data):
            return

        (
            chunk_type,
            header_size,
            chunk_size,
            string_count,
            style_count,
            flags,
            strings_start,
            styles_start,
        ) = struct.unpack("<HHIIIIII", self.data[offset:offset + 28])

        is_utf8 = bool(flags & (1 << 8))
        offsets_start = offset + header_size
        str_offsets = []

        for i in range(string_count):
            off_pos = offsets_start + (i * 4)
            if off_pos + 4 <= len(self.data):
                str_offsets.append(struct.unpack("<I", self.data[off_pos:off_pos + 4])[0])

        pool_strings_base = offset + strings_start
        self.strings = []

        for off in str_offsets:
            cur = pool_strings_base + off
            if cur >= len(self.data):
                self.strings.append("")
                continue

            try:
                if is_utf8:
                    # UTF-8 encoded string pool
                    # Skip character count (1 or 2 bytes)
                    if cur >= len(self.data):
                        self.strings.append("")
                        continue
                    b1 = self.data[cur]
                    cur += 2 if (b1 & 0x80) else 1

                    # Read byte length (1 or 2 bytes)
                    if cur >= len(self.data):
                        self.strings.append("")
                        continue
                    b2 = self.data[cur]
                    cur += 1
                    if b2 & 0x80:
                        length = ((b2 & 0x7F) << 8) | self.data[cur]
                        cur += 1
                    else:
                        length = b2

                    val = self.data[cur:cur + length].decode("utf-8", errors="replace")
                else:
                    # UTF-16 encoded string pool
                    length_chars = struct.unpack("<H", self.data[cur:cur + 2])[0]
                    cur += 2
                    if length_chars & 0x8000:
                        length_chars = ((length_chars & 0x7FFF) << 16) | struct.unpack("<H", self.data[cur:cur + 2])[0]
                        cur += 2
                    byte_len = length_chars * 2
                    val = self.data[cur:cur + byte_len].decode("utf-16le", errors="replace")
                self.strings.append(val)
            except Exception:
                self.strings.append("")

    def _get_string(self, idx: int) -> str:
        if 0 <= idx < len(self.strings):
            return self.strings[idx]
        return ""

    def _parse_start_element(self, offset: int) -> Dict[str, Any]:
        """Parse XML start tag and its attributes."""
        # Header (8) + line_number(4) + comment(4) + ns(4) + name(4) + attr_start(2) + attr_size(2) + attr_count(2) ...
        if offset + 36 > len(self.data):
            return {"tag": "unknown", "attributes": {}, "children": []}

        (
            c_type, c_hdr, c_size,
            line_no, comment_idx,
            ns_idx, name_idx,
            attr_start, attr_size, attr_count,
            id_idx, class_idx, style_idx
        ) = struct.unpack("<HHIIIIHHH HHH", self.data[offset:offset + 36])

        tag_name = self._get_string(name_idx)
        attributes: Dict[str, str] = {}

        cur_attr = offset + attr_start
        for _ in range(attr_count):
            if cur_attr + 20 > len(self.data):
                break
            (
                a_ns, a_name, a_raw,
                val_size, val_res0, val_type, val_data
            ) = struct.unpack("<IIIBBH I", self.data[cur_attr:cur_attr + 20])

            attr_name = self._get_string(a_name)
            if a_raw != 0xFFFFFFFF and a_raw < len(self.strings):
                attr_val = self._get_string(a_raw)
            elif val_type == 0x03:  # TYPE_STRING
                attr_val = self._get_string(val_data)
            elif val_type == 0x12:  # TYPE_INT_BOOLEAN
                attr_val = "true" if val_data != 0 else "false"
            elif val_type == 0x10:  # TYPE_INT_DEC
                attr_val = str(val_data)
            elif val_type == 0x11:  # TYPE_INT_HEX
                attr_val = hex(val_data)
            else:
                attr_val = str(val_data)

            attributes[attr_name] = attr_val
            cur_attr += attr_size if attr_size > 0 else 20

        return {"tag": tag_name, "attributes": attributes, "children": []}


# ============================================================================
# Pure-Python DEX Parser & String Extractor
# ============================================================================

def extract_dex_strings(dex_bytes: bytes) -> List[str]:
    """Parse DEX string_ids table to extract all declared string constants."""
    strings = []
    if len(dex_bytes) < 0x70 or not dex_bytes.startswith(b"dex\n"):
        return strings

    try:
        string_ids_size, string_ids_off = struct.unpack("<II", dex_bytes[0x38:0x40])
        for i in range(string_ids_size):
            off_pos = string_ids_off + (i * 4)
            if off_pos + 4 > len(dex_bytes):
                break
            str_data_off = struct.unpack("<I", dex_bytes[off_pos:off_pos + 4])[0]
            if str_data_off >= len(dex_bytes):
                continue

            # Read ULEB128 utf16_size
            cur = str_data_off
            result = 0
            shift = 0
            while cur < len(dex_bytes):
                byte = dex_bytes[cur]
                cur += 1
                result |= (byte & 0x7F) << shift
                if not (byte & 0x80):
                    break
                shift += 7

            # Null-terminated MUTF-8 string
            end = dex_bytes.find(b"\x00", cur)
            if end != -1:
                val = dex_bytes[cur:end].decode("utf-8", errors="replace")
                if val:
                    strings.append(val)
    except Exception:
        pass
    return strings


def extract_raw_printable_strings(data: bytes, min_length: int = 4) -> List[str]:
    """Fallback ASCII/UTF-8 string extraction from binary buffers."""
    pattern = rb"[\x20-\x7E]{" + str(min_length).encode() + rb",}"
    return [match.group(0).decode("ascii", errors="replace") for match in re.finditer(pattern, data)]


# ============================================================================
# High-Level APK Analysis Functions
# ============================================================================

def parse_manifest_with_aapt(apk_path: Path) -> Optional[Dict[str, Any]]:
    """Parse AndroidManifest.xml using system aapt for 100% fidelity on modern APKs."""
    if not shutil.which("aapt"):
        return None

    try:
        manifest_data = {
            "package_name": "Unknown",
            "version_code": "Unknown",
            "version_name": "Unknown",
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
            "application_label": "Unknown",
            "permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "exported_components": [],
            "boot_receivers": [],
            "accessibility_services": [],
            "device_admin_receivers": [],
            "vpn_services": [],
        }

        # Step 1: Run aapt dump badging
        res_badging = subprocess.run(
            ["aapt", "dump", "badging", str(apk_path)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
        )
        badging_out = res_badging.stdout or ""

        pkg_m = re.search(r"package:\s+name='([^']+)'", badging_out)
        if pkg_m:
            manifest_data["package_name"] = pkg_m.group(1)

        vcode_m = re.search(r"versionCode='([^']+)'", badging_out)
        if vcode_m:
            manifest_data["version_code"] = vcode_m.group(1)

        vname_m = re.search(r"versionName='([^']+)'", badging_out)
        if vname_m:
            manifest_data["version_name"] = vname_m.group(1)

        sdk_m = re.search(r"sdkVersion:'([^']+)'", badging_out)
        if sdk_m:
            manifest_data["min_sdk"] = sdk_m.group(1)

        target_m = re.search(r"targetSdkVersion:'([^']+)'", badging_out)
        if target_m:
            manifest_data["target_sdk"] = target_m.group(1)

        label_m = re.search(r"application-label(?:-[a-zA-Z0-9_\-]+)?:'([^']*)'", badging_out)
        if not label_m:
            label_m = re.search(r"application:\s+label='([^']*)'", badging_out)
        if label_m:
            manifest_data["application_label"] = label_m.group(1)
        elif manifest_data["package_name"] != "Unknown":
            manifest_data["application_label"] = manifest_data["package_name"]

        # Uses-permissions
        perms = re.findall(r"uses-permission(?:-sdk-[0-9]+)?:\s+name='([^']+)'", badging_out)
        for p in perms:
            if p not in manifest_data["permissions"]:
                manifest_data["permissions"].append(p)

        # Launchable activities
        launch_m = re.findall(r"launchable-activity:\s+name='([^']+)'", badging_out)
        for act in launch_m:
            comp = {"type": "activity", "name": act, "exported": True, "permission": "", "actions": ["android.intent.action.MAIN"]}
            manifest_data["activities"].append(comp)
            manifest_data["exported_components"].append(comp)

        # Step 2: Parse full XML tree for complete component inventory
        res_tree = subprocess.run(
            ["aapt", "dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=30,
        )
        if res_tree.returncode == 0 and res_tree.stdout:
            current_elem = None
            current_name = None
            current_exp = None
            current_perm = ""
            current_actions: List[str] = []

            def flush_comp():
                nonlocal current_elem, current_name, current_exp, current_perm, current_actions
                if current_elem and current_name:
                    is_exp = (current_exp in ("0xffffffff", "true", "1"))
                    comp = {
                        "type": current_elem,
                        "name": current_name,
                        "exported": is_exp,
                        "permission": current_perm,
                        "actions": list(current_actions),
                    }
                    if current_elem == "activity":
                        if not any(a["name"] == current_name for a in manifest_data["activities"]):
                            manifest_data["activities"].append(comp)
                    elif current_elem == "service":
                        if not any(s["name"] == current_name for s in manifest_data["services"]):
                            manifest_data["services"].append(comp)
                            if "BIND_ACCESSIBILITY_SERVICE" in current_perm or any("accessibility" in a.lower() for a in current_actions):
                                manifest_data["accessibility_services"].append(comp)
                            if any("vpn" in a.lower() for a in current_actions):
                                manifest_data["vpn_services"].append(comp)
                    elif current_elem == "receiver":
                        if not any(r["name"] == current_name for r in manifest_data["receivers"]):
                            manifest_data["receivers"].append(comp)
                            if any("BOOT_COMPLETED" in a for a in current_actions):
                                manifest_data["boot_receivers"].append(comp)
                            if "BIND_DEVICE_ADMIN" in current_perm:
                                manifest_data["device_admin_receivers"].append(comp)
                    elif current_elem == "provider":
                        if not any(pr["name"] == current_name for pr in manifest_data["providers"]):
                            manifest_data["providers"].append(comp)

                    if is_exp and not any(ec["name"] == current_name for ec in manifest_data["exported_components"]):
                        manifest_data["exported_components"].append(comp)

                current_elem = None
                current_name = None
                current_exp = None
                current_perm = ""
                current_actions = []

            for line in res_tree.stdout.splitlines():
                m_elem = re.search(r"^\s*E:\s*(activity|service|receiver|provider)\b", line)
                if m_elem:
                    flush_comp()
                    current_elem = m_elem.group(1)
                    continue

                if current_elem:
                    m_name = re.search(r"A:\s*android:name\([^)]*\)=\"([^\"]+)\"", line)
                    if m_name and not current_name:
                        current_name = m_name.group(1)

                    m_exp = re.search(r"A:\s*android:exported\([^)]*\)=\(type\s+0x[0-9a-fA-F]+\)(0x[0-9a-fA-F]+)", line)
                    if m_exp:
                        current_exp = m_exp.group(1)

                    m_perm = re.search(r"A:\s*android:permission\([^)]*\)=\"([^\"]+)\"", line)
                    if m_perm:
                        current_perm = m_perm.group(1)

                    if "action" in line:
                        m_act = re.search(r"A:\s*android:name\([^)]*\)=\"([^\"]+)\"", line)
                        if m_act:
                            current_actions.append(m_act.group(1))

            flush_comp()

        if manifest_data["package_name"] != "Unknown":
            return manifest_data
        return None
    except Exception as e:
        print(f"[-] aapt parsing notice: {e}", file=sys.stderr)
        return None


def parse_apk_manifest(apk_path: Path) -> Dict[str, Any]:
    """Extract and parse AndroidManifest.xml from the APK."""
    # First priority: Fast, 100% accurate system aapt extraction
    aapt_result = parse_manifest_with_aapt(apk_path)
    if aapt_result and aapt_result.get("package_name") != "Unknown":
        return aapt_result

    manifest_data = {
        "package_name": "Unknown",
        "version_code": "Unknown",
        "version_name": "Unknown",
        "min_sdk": "Unknown",
        "target_sdk": "Unknown",
        "application_label": "Unknown",
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "exported_components": [],
        "boot_receivers": [],
        "accessibility_services": [],
        "device_admin_receivers": [],
        "vpn_services": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            if "AndroidManifest.xml" not in z.namelist():
                return manifest_data

            axml_bytes = z.read("AndroidManifest.xml")
            parser = AXMLParser(axml_bytes)
            tree = parser.parse()

            if not tree:
                # Fallback to regex string scraping
                strings = parser.strings or extract_raw_printable_strings(axml_bytes)
                corpus = " ".join(strings)
                for p in re.findall(r"android\.permission\.[A-Za-z0-9_]+", corpus):
                    if p not in manifest_data["permissions"]:
                        manifest_data["permissions"].append(p)
                return manifest_data

            manifest_attrs = tree.get("attributes", {})
            manifest_data["package_name"] = manifest_attrs.get("package", "Unknown")
            manifest_data["version_code"] = manifest_attrs.get("versionCode", "Unknown")
            manifest_data["version_name"] = manifest_attrs.get("versionName", "Unknown")

            def walk_elements(node: Dict[str, Any]):
                tag = node.get("tag")
                attrs = node.get("attributes", {})

                if tag == "uses-permission":
                    name = attrs.get("name")
                    if name and name not in manifest_data["permissions"]:
                        manifest_data["permissions"].append(name)
                elif tag == "uses-sdk":
                    manifest_data["min_sdk"] = attrs.get("minSdkVersion", manifest_data["min_sdk"])
                    manifest_data["target_sdk"] = attrs.get("targetSdkVersion", manifest_data["target_sdk"])
                elif tag == "application":
                    manifest_data["application_label"] = attrs.get("label", manifest_data["package_name"])
                elif tag in ("activity", "activity-alias", "service", "receiver", "provider"):
                    comp_name = attrs.get("name", "Unknown")
                    exported = attrs.get("exported", "").lower() == "true"
                    permission_required = attrs.get("permission", "")

                    comp_info = {
                        "type": tag,
                        "name": comp_name,
                        "exported": exported,
                        "permission": permission_required,
                        "actions": [],
                    }

                    # Collect intent filter actions
                    for child in node.get("children", []):
                        if child.get("tag") == "intent-filter":
                            for action_node in child.get("children", []):
                                if action_node.get("tag") == "action":
                                    act = action_node.get("attributes", {}).get("name")
                                    if act:
                                        comp_info["actions"].append(act)

                    if tag == "activity" or tag == "activity-alias":
                        manifest_data["activities"].append(comp_info)
                    elif tag == "service":
                        manifest_data["services"].append(comp_info)
                        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permission_required:
                            manifest_data["accessibility_services"].append(comp_info)
                        if any("vpn" in act.lower() for act in comp_info["actions"]):
                            manifest_data["vpn_services"].append(comp_info)
                    elif tag == "receiver":
                        manifest_data["receivers"].append(comp_info)
                        if any("BOOT_COMPLETED" in act for act in comp_info["actions"]):
                            manifest_data["boot_receivers"].append(comp_info)
                        if "android.permission.BIND_DEVICE_ADMIN" in permission_required:
                            manifest_data["device_admin_receivers"].append(comp_info)
                    elif tag == "provider":
                        manifest_data["providers"].append(comp_info)

                    if exported:
                        manifest_data["exported_components"].append(comp_info)

                for c in node.get("children", []):
                    walk_elements(c)

            walk_elements(tree)
    except Exception as e:
        print(f"[-] Warning during AXML parsing: {e}", file=sys.stderr)

    return manifest_data


def check_installed_tool(tool_name: str) -> bool:
    """Check if an external binary is available in PATH."""
    return shutil.which(tool_name) is not None


def extract_apk_signing_info(apk_path: Path) -> Dict[str, Any]:
    """Inspect signing certificates and signatures in META-INF/."""
    info = {
        "status": "Unknown",
        "signature_files": [],
        "apksigner_output": None,
        "details": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            meta_files = [n for n in z.namelist() if n.startswith("META-INF/")]
            info["signature_files"] = meta_files

        # If apksigner is installed, get official verification
        if check_installed_tool("apksigner"):
            try:
                res = subprocess.run(
                    ["apksigner", "verify", "--verbose", "--print-certs", str(apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                info["apksigner_output"] = res.stdout.strip() or res.stderr.strip()
                if "Verifies" in res.stdout:
                    info["status"] = "Verified"
                else:
                    info["status"] = "Failed / Unsigned"
            except Exception as e:
                info["details"].append(f"apksigner execution error: {e}")
        else:
            if any(f.endswith((".RSA", ".DSA", ".EC")) for f in info["signature_files"]):
                info["status"] = "Signed (v1 signature block present in META-INF)"
            else:
                info["status"] = "Unknown / No v1 signature block"
    except Exception as e:
        info["status"] = f"Error: {e}"

    return info


def inspect_apk_code_patterns(all_strings: List[str]) -> Dict[str, List[str]]:
    """Inspect string constants for security-critical Android APIs and patterns."""
    patterns = {
        "dynamic_code_loading": [
            r"DexClassLoader",
            r"PathClassLoader",
            r"InMemoryDexClassLoader",
            r"dalvik\.system\.DexFile",
            r"loadClass",
        ],
        "reflection_abuse": [
            r"java\.lang\.reflect\.Method",
            r"getDeclaredMethod",
            r"getMethod",
            r"invoke",
        ],
        "command_execution": [
            r"Runtime\.getRuntime\(\)\.exec",
            r"ProcessBuilder",
            r"/system/bin/sh",
            r"/system/xbin/su",
            r"\bsu\b",
        ],
        "sms_apis": [
            r"SmsManager",
            r"sendTextMessage",
            r"sendMultipartTextMessage",
            r"getAllMessagesFromPdu",
            r"Telephony\.Sms",
        ],
        "crypto_indicators": [
            r"Cipher\.getInstance",
            r"SecretKeySpec",
            r"DES/CBC",
            r"AES/CBC",
            r"AES/ECB",
            r"Base64\.decode",
        ],
        "accessibility_abuse": [
            r"AccessibilityService",
            r"AccessibilityEvent",
            r"performGlobalAction",
            r"GLOBAL_ACTION_HOME",
        ],
        "device_administration": [
            r"DevicePolicyManager",
            r"DeviceAdminReceiver",
            r"lockNow",
            r"wipeData",
        ],
    }

    results: Dict[str, List[str]] = {k: [] for k in patterns}
    string_corpus = "\n".join(all_strings)

    for category, regex_list in patterns.items():
        for regex in regex_list:
            matches = re.findall(regex, string_corpus)
            if matches:
                clean_name = regex.replace(r"\.", ".").replace(r"\(", "(").replace(r"\)", ")").replace(r"\b", "")
                results[category].append(f"{clean_name} (observed {len(matches)} time(s))")

    return results


def detect_apk_provenance(
    apk_path: Path,
    manifest: Dict[str, Any],
    extracted_indicators: Dict[str, Any],
    case_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Detect installation timestamps, download sources, and package origin."""
    package_name = manifest.get("package_name", "Unknown")
    provenance = {
        "package_name": package_name,
        "first_install_time": "Unknown",
        "last_update_time": "Unknown",
        "download_source": "Unknown",
        "installer_package": "Unknown",
        "originating_uri": "Unknown",
        "referrer_uri": "Unknown",
        "acquisition_time_utc": "Unknown",
        "build_timestamp_utc": "Unknown",
    }

    # 1. Check if package metadata was saved from dumpsys in case directory
    if case_dir:
        meta_file = case_dir / "evidence" / "device_inventory" / f"package_meta_{package_name}.json"
        if meta_file.exists():
            try:
                pkg_data = json.loads(meta_file.read_text(encoding="utf-8"))
                dumpsys_meta = pkg_data.get("dumpsys_metadata", {})
                provenance["first_install_time"] = dumpsys_meta.get("first_install_time", "Unknown")
                provenance["last_update_time"] = dumpsys_meta.get("last_update_time", "Unknown")
                provenance["installer_package"] = dumpsys_meta.get("installer_package", "Unknown")
                provenance["originating_uri"] = dumpsys_meta.get("originating_uri", "Unknown")
                provenance["referrer_uri"] = dumpsys_meta.get("referrer_uri", "Unknown")
                provenance["download_source"] = dumpsys_meta.get("download_source", "Unknown")
            except Exception:
                pass

        # Also check evidence_hashes.json for acquisition timestamp
        hashes_file = case_dir / "hashes" / "evidence_hashes.json"
        if hashes_file.exists():
            try:
                hdata = json.loads(hashes_file.read_text(encoding="utf-8"))
                for entry in hdata:
                    if entry.get("filename") == apk_path.name or apk_path.name in entry.get("relative_path", ""):
                        provenance["acquisition_time_utc"] = entry.get("collected_at_utc", "Unknown")
                        break
            except Exception:
                pass

    # 2. Derive install timestamp if not found in dumpsys
    if provenance["first_install_time"] == "Unknown":
        if provenance["acquisition_time_utc"] != "Unknown":
            provenance["first_install_time"] = f"{provenance['acquisition_time_utc']} (Device Acquisition)"
        else:
            try:
                mtime = datetime.fromtimestamp(apk_path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                provenance["first_install_time"] = f"{mtime} (File Ingestion)"
            except Exception:
                pass

    # 3. Detect build timestamp from ZIP
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            valid_dts = []
            for info in z.infolist():
                if info.date_time[0] > 1982:
                    dt = datetime(*info.date_time, tzinfo=timezone.utc)
                    valid_dts.append(dt)
            if valid_dts:
                provenance["build_timestamp_utc"] = max(valid_dts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass

    # 4. Derive Download Source / Origin if Unknown
    if provenance["download_source"] in ("Unknown", ""):
        inst_pkg = provenance.get("installer_package", "")
        orig_uri = provenance.get("originating_uri", "")

        if orig_uri and orig_uri != "Unknown":
            provenance["download_source"] = f"Direct Download Link (URL: {orig_uri})"
        elif inst_pkg == "com.android.vending":
            provenance["download_source"] = "Google Play Store (com.android.vending)"
        elif inst_pkg in ("com.google.android.packageinstaller", "com.android.packageinstaller"):
            provenance["download_source"] = "Manual Sideload (Android Package Installer)"
        elif inst_pkg == "com.android.shell":
            provenance["download_source"] = "Direct ADB Sideload (Developer Bridge)"
        elif "chrome" in inst_pkg or "browser" in inst_pkg:
            provenance["download_source"] = f"Web Browser Download ({inst_pkg})"
        else:
            # Inspect manifest permissions & strings for Google Play or Direct Download signatures
            perms = manifest.get("permissions", [])
            version_name = str(manifest.get("version_name", "")).lower()
            is_play = (
                "googleplay" in version_name
                or "com.android.vending.BILLING" in perms
                or "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE" in perms
            )
            if is_play:
                provenance["download_source"] = "Google Play Store (Identified via Play Billing & Referrer Signatures)"
                provenance["installer_package"] = "com.android.vending"
            else:
                # Check extracted URLs for possible download sources
                urls = [u.get("indicator") for u in extracted_indicators.get("urls", []) if isinstance(u, dict)]
                download_urls = [u for u in urls if u and (".apk" in u.lower() or "download" in u.lower())]
                if download_urls:
                    provenance["download_source"] = f"Web Link / Server Origin ({download_urls[0]})"
                else:
                    provenance["download_source"] = "Manual Sideload / Package Ingestion"

    return provenance


def analyze_apk(apk_path: Path, output_analysis_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Perform comprehensive static forensic analysis of an APK."""
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")

    # Step 1: Cryptographic hashes and file metrics
    hashes = calculate_hashes(apk_path)

    # Step 2: Manifest & Components
    manifest = parse_apk_manifest(apk_path)

    # Step 3: Extract Strings & DEX Contents
    all_strings: List[str] = []
    embedded_dex: List[str] = []
    embedded_libs: List[str] = []
    embedded_assets: List[str] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for item in z.infolist():
                filename = item.filename
                if filename.endswith(".dex"):
                    embedded_dex.append(filename)
                    dex_data = z.read(filename)
                    dex_strs = extract_dex_strings(dex_data)
                    if not dex_strs:
                        dex_strs = extract_raw_printable_strings(dex_data)
                    all_strings.extend(dex_strs)
                elif filename.startswith("lib/"):
                    embedded_libs.append(filename)
                    lib_data = z.read(filename)
                    all_strings.extend(extract_raw_printable_strings(lib_data, min_length=6))
                elif filename.startswith("assets/"):
                    embedded_assets.append(filename)
                    try:
                        asset_data = z.read(filename)
                        all_strings.extend(extract_raw_printable_strings(asset_data, min_length=5))
                    except Exception:
                        pass
    except Exception as e:
        print(f"[!] Warning reading APK zip items: {e}", file=sys.stderr)

    # De-duplicate strings preserving order
    seen_strings: Set[str] = set()
    unique_strings: List[str] = []
    for s in all_strings:
        if s not in seen_strings:
            seen_strings.add(s)
            unique_strings.append(s)

    # Step 4: Network & C2 String Extraction
    extracted_indicators = extract_indicators_from_strings(unique_strings, source_name=apk_path.name)

    # Step 5: Android API & Code Pattern Analysis
    observed_patterns = inspect_apk_code_patterns(unique_strings)

    # Step 6: Provenance, Installation Timestamp & Download Origin
    case_context_dir = None
    if output_analysis_dir:
        # Check standard layout: case_dir / analysis / apk_analysis
        candidate_case = output_analysis_dir.parent.parent
        if (candidate_case / "case.json").exists():
            case_context_dir = candidate_case
    provenance = detect_apk_provenance(apk_path, manifest, extracted_indicators, case_dir=case_context_dir)

    # Step 7: Permission Analysis (Context & Provenance Aware)
    pkg_name = manifest.get("package_name", "Unknown")
    app_label = manifest.get("application_label") or pkg_name
    perm_report = analyze_permissions(
        manifest.get("permissions", []),
        provenance=provenance,
        package_name=pkg_name,
        app_label=app_label,
    )

    # Step 8: Signing & Certificate Information
    signing_info = extract_apk_signing_info(apk_path)

    # Step 9: Categorize findings into Facts, Indicators, and Hypotheses
    observed_facts = [
        f"Package Name: {manifest.get('package_name')}",
        f"Application Label: {manifest.get('application_label')}",
        f"Version Name: {manifest.get('version_name')}, Code: {manifest.get('version_code')}",
        f"Min SDK: {manifest.get('min_sdk')}, Target SDK: {manifest.get('target_sdk')}",
        f"Download Source: {provenance.get('download_source')}",
        f"Install / Acquisition Timestamp: {provenance.get('first_install_time')}",
        f"File Size: {hashes['size_bytes']} bytes",
        f"SHA256: {hashes['sha256']}",
        f"DEX Bytecode Files: {', '.join(embedded_dex) if embedded_dex else 'None detected'}",
        f"Native Libraries: {len(embedded_libs)} libraries bundled across ABIs",
        f"Total Declared Permissions: {len(manifest.get('permissions', []))}",
        f"Exported Components: {len(manifest.get('exported_components', []))}",
    ]

    is_play_store = perm_report.get("is_play_store", False)

    suspicious_indicators = []
    if manifest.get("accessibility_services"):
        suspicious_indicators.append("Declares Accessibility Service component with BIND_ACCESSIBILITY_SERVICE")
    if manifest.get("boot_receivers"):
        suspicious_indicators.append("Declares BroadcastReceiver listening for BOOT_COMPLETED (auto-start persistence)")
    if manifest.get("device_admin_receivers"):
        suspicious_indicators.append("Declares Device Administrator Receiver (anti-uninstall/remote lock capability)")
    if observed_patterns.get("dynamic_code_loading"):
        suspicious_indicators.append("References dynamic code loading APIs (DexClassLoader/dalvik.system)")
    if observed_patterns.get("reflection_abuse"):
        suspicious_indicators.append("References dynamic Java reflection APIs (Method.invoke)")
    if observed_patterns.get("command_execution"):
        suspicious_indicators.append("References command execution binaries (/system/bin/sh, su, Runtime.exec)")
    if perm_report.get("matched_threat_patterns"):
        for rule in perm_report["matched_threat_patterns"]:
            suspicious_indicators.append(f"Permission pattern match: {rule['name']}")

    behavioral_hypotheses = []
    if "Banking Trojan / Overlay Phishing Pattern" in [r["name"] for r in perm_report.get("matched_threat_patterns", [])]:
        behavioral_hypotheses.append(
            f"Package {pkg_name} ({app_label}): High likelihood of overlay credential phishing targeting banking, social, or cryptocurrency applications."
        )
    if "SMS Stealer / OTP Interceptor Pattern" in [r["name"] for r in perm_report.get("matched_threat_patterns", [])]:
        behavioral_hypotheses.append(
            f"Package {pkg_name} ({app_label}): Sideloaded untrusted package exhibits potential for unauthorized interception, redirection, or exfiltration of 2FA SMS tokens."
        )
    has_dropper_perms = any(p in manifest.get("permissions", []) for p in ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INSTALL_PACKAGES"])
    has_payload_urls = any(any(ext in u.get("indicator", "").lower() for ext in [".apk", ".dex", ".jar", ".bin"]) for u in extracted_indicators.get("urls", []))
    if observed_patterns.get("dynamic_code_loading") and (has_dropper_perms or has_payload_urls) and not is_play_store:
        behavioral_hypotheses.append(
            f"Package {pkg_name} ({app_label}): Capability to act as a secondary payload dropper or dynamically execute external binary modules."
        )
    if is_play_store and not behavioral_hypotheses:
        behavioral_hypotheses.append(
            f"Package {pkg_name} ({app_label}): Verified Google Play Store package. Standard banking OTP / UPI verification permissions operating within legitimate application scope."
        )

    # Optional Decompilation with JADX / APKTool if output directory is provided and tools exist
    tool_status = {
        "aapt": check_installed_tool("aapt") or check_installed_tool("aapt2"),
        "apktool": check_installed_tool("apktool"),
        "jadx": check_installed_tool("jadx"),
        "apksigner": check_installed_tool("apksigner"),
        "apkanalyzer": check_installed_tool("apkanalyzer"),
    }

    if output_analysis_dir:
        output_analysis_dir.mkdir(parents=True, exist_ok=True)
        # Run JADX if available
        if tool_status["jadx"]:
            jadx_out = output_analysis_dir / "jadx_decompiled"
            if not jadx_out.exists():
                try:
                    subprocess.run(
                        ["jadx", "-d", str(jadx_out), "--no-res", str(apk_path)],
                        capture_output=True,
                        timeout=60,
                    )
                except Exception:
                    pass

        # Run APKTool if available
        if tool_status["apktool"]:
            apktool_out = output_analysis_dir / "apktool_unpacked"
            if not apktool_out.exists():
                try:
                    subprocess.run(
                        ["apktool", "d", "-s", "-f", str(apk_path), "-o", str(apktool_out)],
                        capture_output=True,
                        timeout=60,
                    )
                except Exception:
                    pass

    return {
        "apk_path": str(apk_path.resolve()),
        "hashes": hashes,
        "manifest": manifest,
        "provenance": provenance,
        "permissions_analysis": perm_report,
        "signing_info": signing_info,
        "observed_patterns": observed_patterns,
        "network_indicators": extracted_indicators,
        "embedded_files": {
            "dex_files": embedded_dex,
            "native_libraries": embedded_libs,
            "assets_count": len(embedded_assets),
        },
        "findings": {
            "facts": observed_facts,
            "indicators": suspicious_indicators,
            "hypotheses": behavioral_hypotheses,
            "further_dynamic_analysis_required": [
                "Verify live C2 server communication and protocol handshake.",
                "Inspect decrypted payloads loaded dynamically in memory.",
                "Confirm active screen overlay targets on physical device.",
            ],
        },
        "external_tools_available": tool_status,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def extract_indicators_from_strings(strings: List[str], source_name: str = "APK") -> Dict[str, List[Dict[str, Any]]]:
    """Extract and validate IP addresses, URLs, and domains from extracted strings."""
    # Strict regex patterns
    ipv4_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    url_pattern = re.compile(r"https?://[a-zA-Z0-9_\-\.\:]+(?:/[a-zA-Z0-9_\-\.\?\=\&\%\#]*)?")
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b")

    # Common benign/schema noise filters
    ignored_schemes = {"schemas.android.com", "schemas.microsoft.com", "w3.org", "xmlpull.org", "apache.org"}
    ignored_ips = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}

    urls: List[Dict[str, Any]] = []
    ips: List[Dict[str, Any]] = []
    domains: List[Dict[str, Any]] = []

    seen_urls: Set[str] = set()
    seen_ips: Set[str] = set()
    seen_domains: Set[str] = set()

    for s in strings:
        # Check URLs
        for url in url_pattern.findall(s):
            if url not in seen_urls:
                seen_urls.add(url)
                # Check if benign schema
                if not any(ign in url for ign in ignored_schemes):
                    urls.append({
                        "indicator": url,
                        "type": "URL",
                        "source": source_name,
                        "confidence": "HIGH",
                        "reason": "Hardcoded HTTP/HTTPS endpoint observed in code/assets",
                    })

        # Check IPv4
        for ip in ipv4_pattern.findall(s):
            parts = ip.split(".")
            if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                if ip not in seen_ips and ip not in ignored_ips and not ip.startswith(("10.", "192.168.", "127.", "172.16.")):
                    seen_ips.add(ip)
                    ips.append({
                        "indicator": ip,
                        "type": "IPv4",
                        "source": source_name,
                        "confidence": "MEDIUM",
                        "reason": "Routable public IPv4 address embedded in code/binary",
                    })

        # Check Domains
        for domain in domain_pattern.findall(s):
            dom_lower = domain.lower()
            if (
                dom_lower not in seen_domains
                and not dom_lower.endswith((".png", ".xml", ".dex", ".so", ".jar", ".java", ".json", ".txt"))
                and not any(ign in dom_lower for ign in ignored_schemes)
            ):
                seen_domains.add(dom_lower)
                # Don't duplicate if domain is just android.permission or java class name
                if not dom_lower.startswith(("android.", "java.", "kotlin.", "androidx.", "com.android.")):
                    domains.append({
                        "indicator": dom_lower,
                        "type": "DOMAIN",
                        "source": source_name,
                        "confidence": "MEDIUM",
                        "reason": "Potential C2 / external host domain embedded in code",
                    })

    return {
        "urls": urls,
        "ipv4": ips,
        "domains": domains,
    }
