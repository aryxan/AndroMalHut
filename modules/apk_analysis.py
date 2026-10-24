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
from modules.permission_analysis import analyze_permissions, build_mitre_attack_matrix

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False



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
    """Inspect signing certificates and signatures, schemes v1-v4, validity, and fingerprints."""
    info: Dict[str, Any] = {
        "status": "Unknown",
        "signature_files": [],
        "schemes": {
            "v1_scheme": False,
            "v2_scheme": False,
            "v3_scheme": False,
            "v4_scheme": False,
        },
        "certificates": [],
        "apksigner_output": None,
        "details": [],
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            meta_files = [n for n in z.namelist() if n.startswith("META-INF/")]
            info["signature_files"] = meta_files

        if check_installed_tool("apksigner"):
            try:
                res = subprocess.run(
                    ["apksigner", "verify", "--verbose", "--print-certs-pem", str(apk_path)],
                    capture_output=True,
                    text=True,
                    timeout=25,
                )
                raw_out = res.stdout.strip() or res.stderr.strip()
                info["apksigner_output"] = raw_out

                if "Verifies" in res.stdout:
                    info["status"] = "Verified"
                elif "WARNING" in res.stdout and "Verifies" in res.stdout:
                    info["status"] = "Verified (With Warnings)"
                else:
                    info["status"] = "Failed / Unsigned"

                # Parse signature schemes
                info["schemes"]["v1_scheme"] = "Verified using v1 scheme (JAR signing): true" in res.stdout
                info["schemes"]["v2_scheme"] = "Verified using v2 scheme (APK Signature Scheme v2): true" in res.stdout
                info["schemes"]["v3_scheme"] = "Verified using v3 scheme (APK Signature Scheme v3): true" in res.stdout
                info["schemes"]["v4_scheme"] = "Verified using v4 scheme (APK Signature Scheme v4): true" in res.stdout

                # Parse PEM certificates using cryptography
                if CRYPTOGRAPHY_AVAILABLE:
                    pems: List[str] = []
                    curr: List[str] = []
                    for line in res.stdout.splitlines():
                        if "-----BEGIN CERTIFICATE-----" in line:
                            curr = [line]
                        elif "-----END CERTIFICATE-----" in line:
                            curr.append(line)
                            pems.append("\n".join(curr))
                            curr = []
                        elif curr:
                            curr.append(line)

                    for idx, pem in enumerate(pems, 1):
                        try:
                            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
                            info["certificates"].append({
                                "signer_index": idx,
                                "subject_dn": cert.subject.rfc4514_string(),
                                "issuer_dn": cert.issuer.rfc4514_string(),
                                "serial_number": hex(cert.serial_number),
                                "valid_from": cert.not_valid_before_utc.isoformat(),
                                "valid_to": cert.not_valid_after_utc.isoformat(),
                                "fingerprint_sha256": cert.fingerprint(crypto_hashes.SHA256()).hex(),
                                "fingerprint_sha1": cert.fingerprint(crypto_hashes.SHA1()).hex(),
                                "fingerprint_md5": cert.fingerprint(crypto_hashes.MD5()).hex(),
                                "signature_algorithm": cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "Unknown",
                            })
                        except Exception as ce:
                            info["details"].append(f"PEM cert {idx} parse notice: {ce}")
            except Exception as e:
                info["details"].append(f"apksigner execution error: {e}")
        else:
            if any(f.endswith((".RSA", ".DSA", ".EC")) for f in info["signature_files"]):
                info["status"] = "Signed (v1 signature block present in META-INF)"
                info["schemes"]["v1_scheme"] = True
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
        "contacts_apis": [
            r"ContactsContract",
            r"ContactsContract\.Contacts",
            r"ContactsContract\.CommonDataKinds\.Phone",
            r"content://com\.android\.contacts",
        ],
        "calls_telephony_apis": [
            r"CallLog\.Calls",
            r"getDeviceId",
            r"getImei",
            r"getSimSerialNumber",
            r"getSubscriberId",
            r"getLine1Number",
            r"android\.intent\.action\.CALL",
        ],
        "camera_apis": [
            r"android\.hardware\.Camera",
            r"android\.hardware\.camera2",
            r"openCamera",
            r"takePicture",
        ],
        "microphone_audio_apis": [
            r"AudioRecord",
            r"MediaRecorder",
            r"setAudioSource",
            r"AudioSource\.MIC",
        ],
        "location_apis": [
            r"LocationManager",
            r"FusedLocationProviderClient",
            r"getLastKnownLocation",
            r"requestLocationUpdates",
            r"getLatitude",
            r"getLongitude",
        ],
        "clipboard_apis": [
            r"ClipboardManager",
            r"getPrimaryClip",
            r"setPrimaryClip",
            r"addPrimaryClipChangedListener",
        ],
        "file_storage_apis": [
            r"getExternalStorageDirectory",
            r"getExternalFilesDir",
            r"FileInputStream",
            r"FileOutputStream",
            r"openFileInput",
            r"openFileOutput",
            r"Environment\.getExternalStorageState",
        ],
        "package_management_apis": [
            r"getInstalledPackages",
            r"getInstalledApplications",
            r"PackageInstaller",
            r"pm install",
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


def extract_secrets_and_credentials(strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Identify hardcoded API keys, tokens, credentials, email IDs and embedded secrets."""
    secret_rules = [
        ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z-_]{34,36}\b"), "HIGH", "Embedded Google Cloud / Firebase API key"),
        ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL", "Amazon Web Services IAM User Access Key"),
        ("JWT / Bearer Token", re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b"), "HIGH", "JSON Web Token embedded in application bytecode"),
        ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "CRITICAL", "Hardcoded Cryptographic Private Key header"),
        ("Telegram Bot Token", re.compile(r"\b[0-9]{9,10}:[a-zA-Z0-9_-]{35}\b"), "HIGH", "Telegram Bot API authentication token"),
        ("Discord Webhook", re.compile(r"https://discord\.com/api/webhooks/[0-9]{18,19}/[a-zA-Z0-9_-]{68}"), "HIGH", "Discord C2 / logging webhook URL"),
        ("Slack Webhook", re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"), "HIGH", "Slack incoming webhook endpoint"),
        ("Generic Password / Secret Match", re.compile(r"(?i)(?:api_key|app_secret|client_secret|auth_token|secret_key)\s*[:=]\s*['\"]([a-zA-Z0-9_\-\.]{12,64})['\"]"), "MEDIUM", "Hardcoded API secret assignment"),
        ("Email Address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "LOW", "Embedded email identifier"),
    ]

    findings: Dict[str, List[Dict[str, Any]]] = {
        "api_keys": [],
        "cloud_tokens": [],
        "private_keys": [],
        "emails": [],
        "webhooks": [],
        "other_secrets": [],
    }

    seen_secrets: Set[str] = set()
    ignored_emails = {"android@android.com", "example@example.com", "user@domain.com"}

    for s in strings:
        for name, regex, severity, desc in secret_rules:
            matches = regex.findall(s)
            for m in matches:
                val = m if isinstance(m, str) else m[0]
                val = val.strip("'\"")
                if len(val) < 8 or val in seen_secrets:
                    continue

                if name == "Email Address":
                    val_lower = val.lower()
                    if val_lower in ignored_emails or val_lower.endswith((".png", ".xml", "google.com", "android.com", "w3.org")):
                        continue
                    seen_secrets.add(val)
                    findings["emails"].append({
                        "type": name,
                        "value": val,
                        "severity": severity,
                        "description": desc,
                    })
                elif name in ("Google API Key", "AWS Access Key ID"):
                    seen_secrets.add(val)
                    findings["api_keys"].append({
                        "type": name,
                        "value": val,
                        "severity": severity,
                        "description": desc,
                    })
                elif name == "JWT / Bearer Token":
                    seen_secrets.add(val)
                    findings["cloud_tokens"].append({
                        "type": name,
                        "value": val[:40] + "... [truncated]",
                        "severity": severity,
                        "description": desc,
                    })
                elif name == "Private Key Block":
                    seen_secrets.add(val)
                    findings["private_keys"].append({
                        "type": name,
                        "value": val,
                        "severity": severity,
                        "description": desc,
                    })
                elif "Webhook" in name or "Bot Token" in name:
                    seen_secrets.add(val)
                    findings["webhooks"].append({
                        "type": name,
                        "value": val,
                        "severity": severity,
                        "description": desc,
                    })
                else:
                    seen_secrets.add(val)
                    findings["other_secrets"].append({
                        "type": name,
                        "value": val,
                        "severity": severity,
                        "description": desc,
                    })

    findings["secrets_found_count"] = sum(len(v) for v in findings.values())
    return findings


def detect_cloud_services(strings: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Identify Firebase databases, cloud storage buckets, and backend infrastructure."""
    patterns = [
        ("Firebase Realtime Database", re.compile(r"https?://[a-zA-Z0-9_\-]+\.firebaseio\.com[^\s\'\"]*"), "HIGH", "Firebase Realtime NoSQL Database endpoint"),
        ("Firebase Storage / Appspot", re.compile(r"https?://[a-zA-Z0-9_\-]+\.appspot\.com[^\s\'\"]*"), "MEDIUM", "Firebase Cloud Storage Appspot bucket"),
        ("Firebase Hosting / API", re.compile(r"https?://[a-zA-Z0-9_\-]+\.firebaseapp\.com[^\s\'\"]*"), "MEDIUM", "Firebase App hosting endpoint"),
        ("AWS S3 Bucket", re.compile(r"https?://(?:[a-zA-Z0-9_\-\.]+\.)?s3(?:[.-][a-zA-Z0-9_\-]+)?\.amazonaws\.com/[a-zA-Z0-9_\-\.\/]*|s3://[a-zA-Z0-9_\-\.\/]+"), "HIGH", "Amazon S3 Object Storage Bucket"),
        ("Google Cloud Storage", re.compile(r"https?://storage\.googleapis\.com/[a-zA-Z0-9_\-\.\/]+"), "HIGH", "Google Cloud Storage Bucket (GCS)"),
        ("Azure Blob Storage", re.compile(r"https?://[a-zA-Z0-9_\-]+\.blob\.core\.windows\.net/[a-zA-Z0-9_\-\.\/]*"), "HIGH", "Microsoft Azure Blob Storage endpoint"),
        ("Supabase Backend", re.compile(r"https?://[a-zA-Z0-9_\-]+\.supabase\.co[^\s\'\"]*"), "MEDIUM", "Supabase PostgreSQL backend endpoint"),
    ]

    results: Dict[str, List[Dict[str, Any]]] = {
        "firebase_endpoints": [],
        "cloud_storage_buckets": [],
        "other_cloud_services": [],
    }

    seen: Set[str] = set()
    for s in strings:
        for name, regex, sev, desc in patterns:
            for match in regex.findall(s):
                clean_url = match.strip("'\"")
                if clean_url in seen:
                    continue
                seen.add(clean_url)
                entry = {
                    "service_name": name,
                    "endpoint": clean_url,
                    "severity": sev,
                    "description": desc,
                }
                if "Firebase" in name:
                    results["firebase_endpoints"].append(entry)
                elif "S3" in name or "Storage" in name or "Blob" in name:
                    results["cloud_storage_buckets"].append(entry)
                else:
                    results["other_cloud_services"].append(entry)

    return results


def detect_packers_and_anti_analysis(
    apk_path: Path,
    zip_filenames: List[str],
    strings: List[str],
) -> Dict[str, Any]:
    """Identify commercial/custom packers, obfuscation tools, and anti-analysis checks."""
    packer_signatures = {
        "Bangcle / Secneo": [r"libsecexe\.so", r"libSecShell\.so", r"libAPKProtect\.so", r"bangcleClasses\.jar"],
        "Tencent Legu": [r"libshellx\.so", r"libtxshell\.so", r"00O000ll111l\.dat", r"libtup\.so"],
        "Qihoo 360 / Jiagu": [r"libjiagu\.so", r"libjiagu_art\.so", r"libjgdtc\.so", r"libprotectClass\.so"],
        "Ijiami": [r"libexec\.so", r"libexecmain\.so", r"ijiami\.dat", r"ijm_rom\.dat"],
        "DexGuard / ProGuard": [r"dexguard", r"DexGuard", r"dexguard\.util"],
        "Baidu Protect": [r"libbaiduprotect\.so", r"baiduprotect1\.jar"],
        "Alibaba / Mobisec": [r"libmobisec\.so", r"libalisecrypto\.so"],
    }

    anti_analysis_rules = {
        "Root Detection (su / test-keys)": [r"/system/bin/su", r"/system/xbin/su", r"\bwhich su\b", r"test-keys", r"Superuser\.apk"],
        "RootBeer Library Check": [r"com\.scottyab\.rootbeer\.RootBeer", r"isRooted", r"isRootedWithBusyBoxCheck"],
        "Debugger Evasion": [r"isDebuggerConnected", r"waitForDebugger", r"TracerPid", r"/proc/self/status"],
        "Emulator / Sandbox Evasion": [r"\bgoldfish\b", r"\branchu\b", r"\bqemu\b", r"\bgenymotion\b", r"generic_x86", r"ro\.hardware\.virtual"],
        "Hooking / Frida Detection": [r"frida-server", r"frida-agent", r"\bxposed\b", r"\bsubstrate\b", r"FridaHook"],
    }

    files_joined = "\n".join(zip_filenames)
    strings_joined = "\n".join(strings)

    detected_packers = []
    for packer, sigs in packer_signatures.items():
        for sig in sigs:
            if re.search(sig, files_joined, re.IGNORECASE) or re.search(sig, strings_joined, re.IGNORECASE):
                detected_packers.append(packer)
                break

    detected_anti_analysis = []
    for technique, sigs in anti_analysis_rules.items():
        for sig in sigs:
            if re.search(sig, strings_joined, re.IGNORECASE):
                detected_anti_analysis.append(technique)
                break

    return {
        "is_packed": len(detected_packers) > 0,
        "detected_packers": detected_packers,
        "anti_analysis_detected": detected_anti_analysis,
        "anti_analysis_count": len(detected_anti_analysis),
        "assessment": (
            f"Packed application detected ({', '.join(detected_packers)}) with anti-analysis mechanisms."
            if detected_packers
            else ("Anti-analysis checks present." if detected_anti_analysis else "Standard non-packed binary.")
        ),
    }


def analyze_native_libraries(apk_path: Path, embedded_libs: List[str]) -> Dict[str, Any]:
    """Examine bundled .so native shared libraries, identify ABIs, JNI exports, and suspicious calls."""
    abis: Set[str] = set()
    libraries_by_abi: Dict[str, List[str]] = {}

    for lib_path in embedded_libs:
        parts = lib_path.split("/")
        if len(parts) >= 3:
            abi = parts[1]
            lib_name = parts[-1]
            abis.add(abi)
            libraries_by_abi.setdefault(abi, []).append(lib_name)

    suspicious_native_calls = [
        "ptrace", "dlopen", "dlsym", "mprotect", "system",
        "popen", "execve", "fork", "socket", "connect", "kill"
    ]

    exported_jni_functions: List[str] = []
    observed_native_calls: List[str] = []

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for lib in embedded_libs[:6]:  # Inspect first few representative libraries
                lib_data = z.read(lib)
                raw_strs = extract_raw_printable_strings(lib_data, min_length=4)
                for s in raw_strs:
                    if s.startswith("Java_") or s == "JNI_OnLoad":
                        if s not in exported_jni_functions:
                            exported_jni_functions.append(s)
                    for sc in suspicious_native_calls:
                        if s == sc and sc not in observed_native_calls:
                            observed_native_calls.append(sc)
    except Exception:
        pass

    return {
        "total_libraries": len(embedded_libs),
        "supported_abis": sorted(list(abis)),
        "libraries_by_abi": libraries_by_abi,
        "exported_jni_symbols": exported_jni_functions[:30],
        "suspicious_native_imports": observed_native_calls,
        "has_native_code": len(embedded_libs) > 0,
    }


def analyze_accessibility_and_overlay(manifest: Dict[str, Any], strings: List[str]) -> Dict[str, Any]:
    """Detail accessibility abuse and overlay credential phishing attack capabilities."""
    perms = set(manifest.get("permissions", []))
    string_corpus = "\n".join(strings)

    has_overlay_perm = "android.permission.SYSTEM_ALERT_WINDOW" in perms
    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms or len(manifest.get("accessibility_services", [])) > 0

    overlay_patterns = []
    if "TYPE_APPLICATION_OVERLAY" in string_corpus:
        overlay_patterns.append("TYPE_APPLICATION_OVERLAY (Modern Android 8.0+ system overlay window)")
    if "TYPE_SYSTEM_ALERT" in string_corpus:
        overlay_patterns.append("TYPE_SYSTEM_ALERT (Legacy full-screen alert overlay window)")
    if "FLAG_NOT_TOUCHABLE" in string_corpus or "FLAG_NOT_FOCUSABLE" in string_corpus:
        overlay_patterns.append("Click-through transparent overlay flags (tapjacking)")

    accessibility_capabilities = []
    if has_accessibility:
        accessibility_capabilities.extend([
            "Full screen UI element observation & text scraping",
            "Automated click injection and gesture synthesis",
            "Keystroke and password interception (keylogging)",
            "Self-granting administrative & runtime permissions",
            "Interception of 2FA SMS tokens and banking prompts",
        ])

    return {
        "overlay_permission_granted": has_overlay_perm,
        "accessibility_service_declared": has_accessibility,
        "overlay_mechanisms_observed": overlay_patterns,
        "accessibility_capabilities": accessibility_capabilities,
        "overlay_threat_level": "CRITICAL" if (has_overlay_perm and has_accessibility) else ("HIGH" if has_overlay_perm else "LOW"),
        "justification": (
            "Requests both SYSTEM_ALERT_WINDOW and BIND_ACCESSIBILITY_SERVICE, strongly characteristic of banking trojan overlay attacks."
            if (has_overlay_perm and has_accessibility)
            else ("Requests overlay display capability; may draw screens over other apps." if has_overlay_perm else "No active overlay threat detected.")
        ),
    }


def analyze_device_admin(manifest: Dict[str, Any], strings: List[str]) -> Dict[str, Any]:
    """Analyze Device Administrator registration and persistence mechanisms."""
    perms = set(manifest.get("permissions", []))
    receivers = manifest.get("device_admin_receivers", [])
    has_admin_perm = "android.permission.BIND_DEVICE_ADMIN" in perms or len(receivers) > 0

    string_corpus = "\n".join(strings)
    admin_apis = []
    if "lockNow" in string_corpus:
        admin_apis.append("lockNow() - Instantly lock device screen")
    if "wipeData" in string_corpus:
        admin_apis.append("wipeData() - Factory reset and wipe device storage")
    if "resetPassword" in string_corpus:
        admin_apis.append("resetPassword() - Programmatically change device PIN/password")

    return {
        "device_admin_declared": has_admin_perm,
        "admin_receivers": receivers,
        "observed_admin_apis": admin_apis,
        "persistence_capability": "CRITICAL (Anti-Uninstall & Remote Lockout)" if has_admin_perm else "NONE",
        "description": (
            "Declares Device Administrator Receiver. App can prevent uninstallation and execute privileged device lock/wipe commands."
            if has_admin_perm
            else "Standard non-administrative application."
        ),
    }


def analyze_data_exfiltration(
    manifest: Dict[str, Any],
    observed_patterns: Dict[str, Any],
    network_indicators: Dict[str, Any],
) -> Dict[str, Any]:
    """Correlate sensitive local data sources with communication sinks to identify exfiltration paths."""
    perms = set(manifest.get("permissions", []))
    patterns = observed_patterns or {}
    urls = network_indicators.get("urls", [])
    ips = network_indicators.get("ipv4", [])

    has_network = "android.permission.INTERNET" in perms or len(urls) > 0 or len(ips) > 0

    sources = []
    if any(p in perms for p in ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"]) or patterns.get("sms_apis"):
        sources.append("SMS Messages & 2FA Codes")
    if "android.permission.READ_CONTACTS" in perms or patterns.get("contacts_apis"):
        sources.append("Address Book Contacts")
    if "android.permission.READ_CALL_LOG" in perms or patterns.get("calls_telephony_apis"):
        sources.append("Call Records & Hardware IMEI/IMSI")
    if any(p in perms for p in ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"]) or patterns.get("location_apis"):
        sources.append("Live GPS / Cell Location Coordinates")
    if "android.permission.RECORD_AUDIO" in perms or patterns.get("microphone_audio_apis"):
        sources.append("Microphone Audio Recordings")
    if "android.permission.CAMERA" in perms or patterns.get("camera_apis"):
        sources.append("Camera Images & Video")
    if "android.permission.READ_EXTERNAL_STORAGE" in perms or "android.permission.MANAGE_EXTERNAL_STORAGE" in perms or patterns.get("file_storage_apis"):
        sources.append("Local Files & Stored Documents")
    if patterns.get("clipboard_apis"):
        sources.append("System Clipboard Data")

    channels = []
    if has_network:
        channels.append(f"External HTTP/HTTPS POST & Socket Endpoints ({len(urls)} URLs, {len(ips)} Public IPs)")
    if "android.permission.SEND_SMS" in perms:
        channels.append("Outbound SMS Transmission (Toll Fraud / Covert Exfil)")

    exfil_potential = "HIGH" if (sources and channels) else ("MEDIUM" if sources else "LOW")

    return {
        "sensitive_sources_accessed": sources,
        "exfiltration_channels": channels,
        "exfiltration_risk_level": exfil_potential,
        "summary": (
            f"Potential data exfiltration detected: App accesses {', '.join(sources)} and has outbound transmission capabilities via {', '.join(channels)}."
            if (sources and channels)
            else "No high-risk data exfiltration pathway identified."
        ),
    }


def build_unified_ioc_list(
    hashes: Dict[str, Any],
    manifest: Dict[str, Any],
    network_indicators: Dict[str, Any],
    cloud_services: Dict[str, Any],
    suspicious_files: List[str],
) -> Dict[str, Any]:
    """Prepare a consolidated Indicator of Compromise (IOC) record."""
    pkg_name = manifest.get("package_name", "Unknown")

    return {
        "hashes": {
            "sha256": hashes.get("sha256", ""),
            "sha1": hashes.get("sha1", ""),
            "md5": hashes.get("md5", ""),
        },
        "package_names": [pkg_name] if pkg_name != "Unknown" else [],
        "domains": [d.get("indicator") for d in network_indicators.get("domains", []) if isinstance(d, dict)],
        "urls": [u.get("indicator") for u in network_indicators.get("urls", []) if isinstance(u, dict)],
        "ipv4_addresses": [ip.get("indicator") for ip in network_indicators.get("ipv4", []) if isinstance(ip, dict)],
        "cloud_infrastructure": [
            f"{c.get('service_name')}: {c.get('endpoint')}"
            for sub in cloud_services.values()
            for c in sub if isinstance(c, dict)
        ],
        "suspicious_filenames": suspicious_files,
    }



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
    apk_path = Path(apk_path).expanduser().resolve()
    if not apk_path.exists():
        raise FileNotFoundError(f"APK file not found: {apk_path}")
    if not apk_path.is_file():
        raise ValueError(f"Target path is not a regular file: {apk_path}")
    if apk_path.suffix.lower() != ".apk":
        raise ValueError(f"Target file must have .apk extension, got '{apk_path.suffix}': {apk_path}")

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

    # Step 6: Secrets, Cloud Services, Packers, Native, Overlay & Exfiltration
    secrets_detected = extract_secrets_and_credentials(unique_strings)
    cloud_services = detect_cloud_services(unique_strings)
    packer_info = detect_packers_and_anti_analysis(apk_path, embedded_dex + embedded_libs + embedded_assets, unique_strings)
    native_analysis = analyze_native_libraries(apk_path, embedded_libs)
    accessibility_analysis = analyze_accessibility_and_overlay(manifest, unique_strings)
    device_admin_analysis = analyze_device_admin(manifest, unique_strings)
    data_exfiltration = analyze_data_exfiltration(manifest, observed_patterns, extracted_indicators)
    unified_iocs = build_unified_ioc_list(hashes, manifest, extracted_indicators, cloud_services, embedded_dex + embedded_libs)

    # Step 7: Provenance, Installation Timestamp & Download Origin
    case_context_dir = None
    if output_analysis_dir:
        # Check standard layout: case_dir / analysis / apk_analysis
        candidate_case = output_analysis_dir.parent.parent
        if (candidate_case / "case.json").exists():
            case_context_dir = candidate_case
    provenance = detect_apk_provenance(apk_path, manifest, extracted_indicators, case_dir=case_context_dir)

    # Step 8: Permission Analysis (Context & Provenance Aware)
    pkg_name = manifest.get("package_name", "Unknown")
    app_label = manifest.get("application_label") or pkg_name
    perm_report = analyze_permissions(
        manifest.get("permissions", []),
        provenance=provenance,
        package_name=pkg_name,
        app_label=app_label,
    )

    # Step 9: Signing & Certificate Information (v1-v4 schemes, X.509 validity, fingerprints)
    signing_info = extract_apk_signing_info(apk_path)

    # Step 10: MITRE ATT&CK Mobile Matrix Mapping
    mitre_matrix = build_mitre_attack_matrix(
        manifest=manifest,
        permission_analysis=perm_report,
        observed_patterns=observed_patterns,
        packer_anti_analysis=packer_info,
        network_indicators=extracted_indicators,
        native_analysis=native_analysis,
    )

    # Step 11: Categorize findings into Facts, Indicators, and Hypotheses
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
        f"Native Libraries: {len(embedded_libs)} libraries bundled across ABIs ({', '.join(native_analysis.get('supported_abis', [])) or 'No native libs'})",
        f"Total Declared Permissions: {len(manifest.get('permissions', []))}",
        f"Exported Components: {len(manifest.get('exported_components', []))}",
        f"Signing Status: {signing_info.get('status')} (Schemes: v1={signing_info.get('schemes', {}).get('v1_scheme')}, v2={signing_info.get('schemes', {}).get('v2_scheme')}, v3={signing_info.get('schemes', {}).get('v3_scheme')})",
    ]

    is_play_store = perm_report.get("is_play_store", False)

    suspicious_indicators = []
    if manifest.get("accessibility_services"):
        suspicious_indicators.append("Declares Accessibility Service component with BIND_ACCESSIBILITY_SERVICE")
    if manifest.get("boot_receivers"):
        suspicious_indicators.append("Declares BroadcastReceiver listening for BOOT_COMPLETED (auto-start persistence)")
    if manifest.get("device_admin_receivers"):
        suspicious_indicators.append("Declares Device Administrator Receiver (anti-uninstall/remote lock capability)")
    if packer_info.get("is_packed"):
        suspicious_indicators.append(f"Commercial/custom APK packer detected: {', '.join(packer_info.get('detected_packers', []))}")
    if packer_info.get("anti_analysis_detected"):
        suspicious_indicators.append(f"Anti-analysis evasions detected: {', '.join(packer_info.get('anti_analysis_detected', []))}")
    if secrets_detected.get("api_keys") or secrets_detected.get("private_keys"):
        sec_count = len(secrets_detected.get("api_keys", [])) + len(secrets_detected.get("private_keys", []))
        suspicious_indicators.append(f"Hardcoded API keys / private cryptographic secrets embedded in code ({sec_count} found)")
    if cloud_services.get("firebase_endpoints"):
        suspicious_indicators.append(f"Exposes Firebase Realtime Database / backend endpoints ({len(cloud_services['firebase_endpoints'])} found)")
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
        "secrets_detected": secrets_detected,
        "cloud_services": cloud_services,
        "packer_and_anti_analysis": packer_info,
        "native_library_analysis": native_analysis,
        "accessibility_analysis": accessibility_analysis,
        "device_admin_analysis": device_admin_analysis,
        "data_exfiltration_analysis": data_exfiltration,
        "unified_iocs": unified_iocs,
        "mitre_attack_matrix": mitre_matrix,
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
