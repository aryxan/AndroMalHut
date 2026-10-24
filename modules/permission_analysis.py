"""
DroidSleuth Permission Analysis Module
Analyzes Android permissions, assesses threats, detects dangerous combinations,
and maps permissions to MITRE ATT&CK for Mobile and forensic risk categories.
"""

from typing import Dict, Any, List, Set, Tuple, Optional

# Mapping of known dangerous and special permissions to risk metadata
DANGEROUS_PERMISSIONS: Dict[str, Dict[str, str]] = {
    # SMS / 2FA Interception
    "android.permission.RECEIVE_SMS": {
        "group": "SMS",
        "risk": "HIGH",
        "description": "Intercept incoming SMS messages (used for OTP verification or abused for OTP theft).",
        "capability": "SMS_INTERCEPTION",
    },
    "android.permission.READ_SMS": {
        "group": "SMS",
        "risk": "MEDIUM",
        "description": "Read stored SMS messages and verification notifications.",
        "capability": "SMS_EXFILTRATION",
    },
    "android.permission.SEND_SMS": {
        "group": "SMS",
        "risk": "HIGH",
        "description": "Send SMS messages (toll fraud or SMS verification).",
        "capability": "SMS_TOLL_FRAUD",
    },
    "android.permission.RECEIVE_MMS": {
        "group": "SMS",
        "risk": "MEDIUM",
        "description": "Monitor and intercept incoming multimedia messages.",
        "capability": "SMS_INTERCEPTION",
    },
    "android.permission.RECEIVE_WAP_PUSH": {
        "group": "SMS",
        "risk": "MEDIUM",
        "description": "Monitor WAP push messages.",
        "capability": "SMS_INTERCEPTION",
    },

    # Special Access & Abusable System Controls
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "group": "OVERLAY",
        "risk": "CRITICAL",
        "description": "Draw overlays on top of other applications (banking credential phishing / cloaking).",
        "capability": "OVERLAY_ATTACK",
    },
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "group": "ACCESSIBILITY",
        "risk": "CRITICAL",
        "description": "Full access to user screen content, keystrokes, UI automation, and self-granting permissions.",
        "capability": "ACCESSIBILITY_HIJACK",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "group": "ADMIN",
        "risk": "CRITICAL",
        "description": "Device administration privileges, preventing app uninstallation and allowing remote wipe/lock.",
        "capability": "PERSISTENCE_ADMIN",
    },
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": {
        "group": "NOTIFICATIONS",
        "risk": "HIGH",
        "description": "Intercept all device notifications, including chat messages and 2FA authentication codes.",
        "capability": "NOTIFICATION_INTERCEPTION",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "group": "DROPPER",
        "risk": "HIGH",
        "description": "Request installation of additional APK packages (dropper / secondary payload).",
        "capability": "APP_DROPPER",
    },
    "android.permission.INSTALL_PACKAGES": {
        "group": "DROPPER",
        "risk": "CRITICAL",
        "description": "Privileged package installation without standard user prompts.",
        "capability": "SILENT_INSTALLER",
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "group": "SURVEILLANCE",
        "risk": "HIGH",
        "description": "Monitor which app is currently in foreground to trigger contextual overlays.",
        "capability": "APP_MONITORING",
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "group": "RECON",
        "risk": "MEDIUM",
        "description": "Query all installed apps to identify targets (e.g. banking, crypto, messaging).",
        "capability": "DEVICE_RECONNAISSANCE",
    },

    # Phone, Calls & Identity
    "android.permission.READ_PHONE_STATE": {
        "group": "PHONE",
        "risk": "MEDIUM",
        "description": "Access device phone number, cellular network info, and ongoing call status.",
        "capability": "DEVICE_PROFILING",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "group": "PHONE",
        "risk": "MEDIUM",
        "description": "Read phone numbers configured on the device.",
        "capability": "DEVICE_PROFILING",
    },
    "android.permission.CALL_PHONE": {
        "group": "PHONE",
        "risk": "HIGH",
        "description": "Initiate outgoing phone calls without entering the Dialer UI.",
        "capability": "TOLL_CALL",
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "group": "PHONE",
        "risk": "HIGH",
        "description": "Intercept and redirect outgoing phone calls.",
        "capability": "CALL_INTERCEPTION",
    },
    "android.permission.READ_CALL_LOG": {
        "group": "CALL_LOG",
        "risk": "HIGH",
        "description": "Access phone call history, timestamps, and caller details.",
        "capability": "SURVEILLANCE_CALLS",
    },
    "android.permission.WRITE_CALL_LOG": {
        "group": "CALL_LOG",
        "risk": "HIGH",
        "description": "Modify call log records (erasing traces of unauthorized calls).",
        "capability": "ANTI_FORENSICS",
    },

    # Contacts & Audio/Camera Surveillance
    "android.permission.READ_CONTACTS": {
        "group": "CONTACTS",
        "risk": "MEDIUM",
        "description": "Access the user's address book and contact list.",
        "capability": "DATA_EXFILTRATION",
    },
    "android.permission.RECORD_AUDIO": {
        "group": "MICROPHONE",
        "risk": "MEDIUM",
        "description": "Capture microphone audio (standard in voice messaging and VoIP).",
        "capability": "AUDIO_SURVEILLANCE",
    },
    "android.permission.CAMERA": {
        "group": "CAMERA",
        "risk": "MEDIUM",
        "description": "Capture photos and videos (standard in photo/video/social apps).",
        "capability": "VIDEO_SURVEILLANCE",
    },

    # Location
    "android.permission.ACCESS_FINE_LOCATION": {
        "group": "LOCATION",
        "risk": "MEDIUM",
        "description": "Obtain precise GPS coordinates.",
        "capability": "LOCATION_TRACKING",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "group": "LOCATION",
        "risk": "LOW",
        "description": "Obtain approximate cell/Wi-Fi location.",
        "capability": "LOCATION_TRACKING",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "group": "LOCATION",
        "risk": "HIGH",
        "description": "Track device location continuously in the background.",
        "capability": "BACKGROUND_TRACKING",
    },

    # Storage
    "android.permission.READ_EXTERNAL_STORAGE": {
        "group": "STORAGE",
        "risk": "LOW",
        "description": "Read files stored on shared storage (photos, documents, downloads).",
        "capability": "FILE_EXFILTRATION",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "group": "STORAGE",
        "risk": "LOW",
        "description": "Write or modify files on shared storage.",
        "capability": "FILE_TAMPERING",
    },
    "android.permission.MANAGE_EXTERNAL_STORAGE": {
        "group": "STORAGE",
        "risk": "HIGH",
        "description": "Broad access to all shared storage files on Android 11+.",
        "capability": "BROAD_STORAGE_ACCESS",
    },

    # Boot & Persistence
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "group": "PERSISTENCE",
        "risk": "LOW",
        "description": "Auto-start background services immediately upon phone reboot.",
        "capability": "AUTOSTART_PERSISTENCE",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "group": "PERSISTENCE",
        "risk": "INFORMATIONAL",
        "description": "Run background services with persistent notification.",
        "capability": "BACKGROUND_EXECUTION",
    },
    "android.permission.WAKE_LOCK": {
        "group": "SYSTEM",
        "risk": "INFORMATIONAL",
        "description": "Keep processor awake to prevent phone sleep.",
        "capability": "KEEP_AWAKE",
    },
    "android.permission.INTERNET": {
        "group": "NETWORK",
        "risk": "INFORMATIONAL",
        "description": "Open standard network sockets and transmit data.",
        "capability": "NETWORK_COMMUNICATION",
    },
}

# Standard Android runtime dangerous permissions (Android Developer Reference)
ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.UWB_RANGING",
}

# Special, signature, or high-risk abusable permissions (Overlay, Accessibility, Admin, Install)
SPECIAL_SUSPICIOUS_PERMISSIONS = {
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.WRITE_SETTINGS",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.INTERNAL_SYSTEM_WINDOW",
    "android.permission.SYSTEM_OVERLAY_WINDOW",
    "android.permission.ACCESS_SUPERUSER",
    "android.permission.BIND_VPN_SERVICE",
}

# Dangerous combination rules indicating specific attack patterns
COMBINATION_RULES = [
    {
        "name": "Banking Trojan / Overlay Phishing Pattern",
        "required_permissions": {
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        },
        "severity": "CRITICAL",
        "description": (
            "Requests both Overlay (SYSTEM_ALERT_WINDOW) and Accessibility Service permissions. "
            "Overwhelmingly associated with Android banking trojans (e.g. Cerberus, Anatsa) "
            "to draw fake login dialogs over financial apps and intercept user credentials."
        ),
        "mitre_id": "T1411 (Exploit Abuse: Input Capture / Overlay)",
    },
    {
        "name": "SMS Stealer / OTP Interceptor Pattern",
        "required_permissions": {
            "android.permission.RECEIVE_SMS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.INTERNET",
        },
        "severity": "CRITICAL",
        "description": (
            "Requests SMS interception alongside boot persistence and Internet communication. "
            "Enables stealthy exfiltration of SMS 2FA codes and bank verification messages right after reboot."
        ),
        "mitre_id": "T1412 (Capture SMS Messages)",
    },
    {
        "name": "Stealth Background Spyware Surveillance Pattern",
        "required_permissions": {
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_CONTACTS",
        },
        "severity": "CRITICAL",
        "description": (
            "Possesses broad covert background surveillance capabilities across ambient microphone recording, "
            "camera capture, persistent background GPS tracking, and address book harvesting."
        ),
        "mitre_id": "T1430 (Location Tracking) / T1429 (Audio Capture)",
    },
    {
        "name": "Ransomware / Device Hijacker Pattern",
        "required_permissions": {
            "android.permission.BIND_DEVICE_ADMIN",
            "android.permission.SYSTEM_ALERT_WINDOW",
        },
        "severity": "CRITICAL",
        "description": (
            "Combines Device Administrator rights with overlay permissions. "
            "Frequently used by mobile ransomware to lock the screen, prevent uninstallation, "
            "and reset device passwords."
        ),
        "mitre_id": "T1453 (Device Lockout)",
    },
    {
        "name": "Arbitrary Package Installer / Secondary Payload Capability",
        "required_permissions": {
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        },
        "severity": "MEDIUM",
        "description": (
            "Capable of downloading arbitrary APK binaries from the Internet and prompting the user "
            "or attempting to install them as secondary payloads (legitimate for web browsers/app stores; "
            "suspicious in games or single-purpose utility apps)."
        ),
        "mitre_id": "T1475 (Deliver Malicious App)",
    },
    {
        "name": "Notification / 2FA Interceptor Pattern",
        "required_permissions": {
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.INTERNET",
        },
        "severity": "HIGH",
        "description": (
            "Monitors push notifications and transmits content over the Internet. "
            "Can steal ephemeral 2FA tokens sent by apps like WhatsApp, Telegram, or banking apps."
        ),
        "mitre_id": "T1517 (Access Notifications)",
    },
]


def normalize_permission_name(perm: str) -> str:
    """Normalize permission string by stripping whitespace and comments."""
    return perm.strip().split()[-1] if perm else ""


def analyze_permissions(
    declared_permissions: List[str],
    granted_permissions: Optional[List[str]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    package_name: Optional[str] = None,
    app_label: Optional[str] = None,
) -> Dict[str, Any]:
    """Perform calibrated, context-aware threat analysis of declared and granted permissions."""
    declared_set = {normalize_permission_name(p) for p in declared_permissions if p}
    granted_set = {normalize_permission_name(p) for p in (granted_permissions or []) if p}

    # Determine if package has verified Google Play Store origin
    is_play_store = False
    if provenance:
        dl_source = str(provenance.get("download_source", "")).lower()
        inst_pkg = str(provenance.get("installer_package", "")).lower()
        if "play store" in dl_source or "com.android.vending" in dl_source or inst_pkg == "com.android.vending":
            is_play_store = True

    # Also detect Play Store billing / install referrer signatures if not explicitly sideloaded
    if not is_play_store and provenance:
        dl_source = str(provenance.get("download_source", "")).lower()
        if "sideload" not in dl_source and "direct" not in dl_source:
            if "com.android.vending.BILLING" in declared_set or "com.google.android.finsky.permission.BIND_GET_INSTALL_REFERRER_SERVICE" in declared_set:
                is_play_store = True

    findings = []
    capabilities = set()
    risk_score = 0
    max_possible_score = 100

    categorized = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "normal": [],
        "unknown_custom": [],
    }

    for perm in sorted(declared_set):
        norm_perm = perm
        is_granted = norm_perm in granted_set if granted_permissions is not None else None

        if norm_perm in DANGEROUS_PERMISSIONS:
            meta = DANGEROUS_PERMISSIONS[norm_perm]
            risk = meta["risk"]
            capabilities.add(meta["capability"])

            entry = {
                "permission": norm_perm,
                "group": meta["group"],
                "risk": risk,
                "description": meta["description"],
                "capability": meta["capability"],
                "is_granted": is_granted,
            }

            if risk == "CRITICAL":
                categorized["critical"].append(entry)
                risk_score += 25
            elif risk == "HIGH":
                categorized["high"].append(entry)
                risk_score += 12
            elif risk == "MEDIUM":
                categorized["medium"].append(entry)
                risk_score += 4
            elif risk == "LOW":
                categorized["low"].append(entry)
                risk_score += 1
            else:
                categorized["normal"].append(entry)
        elif norm_perm.startswith("android.permission."):
            categorized["normal"].append({
                "permission": norm_perm,
                "group": "STANDARD",
                "risk": "INFORMATIONAL",
                "description": "Standard Android system permission.",
                "capability": "STANDARD",
                "is_granted": is_granted,
            })
        else:
            # Custom app-defined permission
            categorized["unknown_custom"].append({
                "permission": norm_perm,
                "group": "CUSTOM",
                "risk": "INFORMATIONAL",
                "description": "Custom or vendor-specific permission.",
                "capability": "CUSTOM",
                "is_granted": is_granted,
            })

    # Evaluate combination rules
    matched_rules = []
    has_critical_exploit_rule = False

    for rule in COMBINATION_RULES:
        req = rule["required_permissions"]
        if req.issubset(declared_set):
            rule_name = rule["name"]

            # Contextual calibration: SMS pattern on verified Play Store apps is standard OTP verification, not SMS Stealer
            if rule_name == "SMS Stealer / OTP Interceptor Pattern" and is_play_store:
                benign_rule = {
                    "name": "Standard Banking / 2FA SMS Verification Capability",
                    "required_permissions": sorted(list(req)),
                    "severity": "LOW",
                    "description": (
                        "Requests SMS reception alongside boot persistence and network communication. "
                        "In verified Google Play Store applications (such as official banking, UPI payment, and messaging apps), "
                        "this pattern is standard for automated SMS OTP verification and NPCI/UPI SIM binding."
                    ),
                    "mitre_id": "T1412 (Standard Banking OTP Verification)",
                }
                matched_rules.append(benign_rule)
                # For legitimate Play Store apps, add minimal operational weight instead of critical penalty
                risk_score += 2
                continue

            serializable_rule = dict(rule)
            serializable_rule["required_permissions"] = sorted(list(rule["required_permissions"]))
            matched_rules.append(serializable_rule)
            if rule["severity"] == "CRITICAL":
                has_critical_exploit_rule = True
                risk_score += 30
            elif rule["severity"] == "HIGH":
                risk_score += 15
            elif rule["severity"] == "MEDIUM":
                risk_score += 8

    # Calibration for verified Play Store applications
    # If the app is verified from Google Play Store and does not possess active trojan exploit combinations
    # (such as accessibility hijacking or overlay phishing), cap its baseline risk score to normal operational levels.
    if is_play_store and not has_critical_exploit_rule:
        risk_score = min(risk_score, 18)

    risk_score = min(risk_score, max_possible_score)

    # Calibrated industry severity bands
    if is_play_store and not has_critical_exploit_rule:
        overall_severity = "LOW"
    elif risk_score >= 75:
        overall_severity = "CRITICAL"
    elif risk_score >= 50:
        overall_severity = "HIGH"
    elif risk_score >= 25:
        overall_severity = "MEDIUM"
    else:
        overall_severity = "LOW"

    # Explicit forensic classification into Normal, Dangerous, and Suspicious
    normal_perms: List[str] = []
    dangerous_perms: List[str] = []
    suspicious_perms: List[str] = []
    custom_perms: List[str] = []

    for perm in sorted(declared_set):
        if perm in SPECIAL_SUSPICIOUS_PERMISSIONS or perm in ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN", "android.permission.REQUEST_INSTALL_PACKAGES"]:
            suspicious_perms.append(perm)
        elif perm in ANDROID_DANGEROUS_PERMISSIONS or (perm in DANGEROUS_PERMISSIONS and DANGEROUS_PERMISSIONS[perm]["risk"] in ("CRITICAL", "HIGH", "MEDIUM")):
            dangerous_perms.append(perm)
        elif perm.startswith("android.permission."):
            normal_perms.append(perm)
        else:
            custom_perms.append(perm)

    return {
        "total_declared": len(declared_set),
        "total_granted": len(granted_set) if granted_permissions is not None else "Not Available (Static Analysis)",
        "risk_score": risk_score,
        "overall_severity": overall_severity,
        "capabilities": sorted(list(capabilities)),
        "matched_threat_patterns": matched_rules,
        "categorized_permissions": categorized,
        "dangerous_count": len(categorized["critical"]) + len(categorized["high"]) + len(categorized["medium"]),
        "permission_breakdown": {
            "normal": normal_perms,
            "dangerous": dangerous_perms,
            "suspicious": suspicious_perms,
            "custom": custom_perms,
        },
        "is_play_store": is_play_store,
        "provenance_note": (
            "Verified Google Play Store Application (legitimate OTP/SIM binding permissions)"
            if is_play_store
            else "Standard / Untrusted Origin"
        ),
    }


def build_mitre_attack_matrix(
    manifest: Dict[str, Any],
    permission_analysis: Dict[str, Any],
    observed_patterns: Dict[str, Any],
    packer_anti_analysis: Optional[Dict[str, Any]] = None,
    network_indicators: Optional[Dict[str, Any]] = None,
    native_analysis: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Map detected static & behavioral indicators to MITRE ATT&CK for Mobile matrix."""
    matrix: List[Dict[str, Any]] = []
    perms = set(manifest.get("permissions", []))
    patterns = observed_patterns or {}
    packer_info = packer_anti_analysis or {}
    net = network_indicators or {}

    # 1. Credential Access: T1411 - Input Capture (Overlay & Accessibility)
    if (
        "android.permission.SYSTEM_ALERT_WINDOW" in perms
        or "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms
        or patterns.get("accessibility_abuse")
    ):
        matrix.append({
            "tactic": "Credential Access",
            "technique_id": "T1411",
            "technique_name": "Input Capture: Fake Login Overlay / Keylogging",
            "confidence": "HIGH",
            "evidence": "Requests Overlay (SYSTEM_ALERT_WINDOW) or Accessibility Service APIs for screen interception.",
        })

    # 2. Collection: T1412 - Capture SMS Messages
    if (
        any(p in perms for p in ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS"])
        or patterns.get("sms_apis")
    ):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1412",
            "technique_name": "Capture SMS Messages & 2FA Tokens",
            "confidence": "HIGH",
            "evidence": "Requests SMS interception/reading permissions or directly invokes SmsManager / Telephony APIs.",
        })

    # 3. Collection: T1430 - Location Tracking
    if (
        any(p in perms for p in ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"])
        or patterns.get("location_apis")
    ):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1430",
            "technique_name": "Location Tracking",
            "confidence": "HIGH",
            "evidence": "Requests GPS or cell location tracking permissions / APIs.",
        })

    # 4. Collection: T1432 - Access Contact List
    if "android.permission.READ_CONTACTS" in perms or patterns.get("contacts_apis"):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1432",
            "technique_name": "Access Contact List",
            "confidence": "HIGH",
            "evidence": "Requests READ_CONTACTS or references ContactsContract content queries.",
        })

    # 5. Collection: T1433 - Access Call Log
    if "android.permission.READ_CALL_LOG" in perms or patterns.get("calls_telephony_apis"):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1433",
            "technique_name": "Access Call Log & Telephony Profiling",
            "confidence": "HIGH",
            "evidence": "Queries CallLog or retrieves hardware identity (IMEI, SIM serial, IMSI).",
        })

    # 6. Collection: T1429 - Capture Audio
    if "android.permission.RECORD_AUDIO" in perms or patterns.get("microphone_audio_apis"):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1429",
            "technique_name": "Audio Capture / Ambient Eavesdropping",
            "confidence": "HIGH",
            "evidence": "Requests microphone recording permission or instantiates AudioRecord / MediaRecorder.",
        })

    # 7. Collection: T1414 - Capture Clipboard
    if patterns.get("clipboard_apis"):
        matrix.append({
            "tactic": "Collection",
            "technique_id": "T1414",
            "technique_name": "Capture Clipboard Data",
            "confidence": "MEDIUM",
            "evidence": "Monitors or extracts system clipboard entries via ClipboardManager.",
        })

    # 8. Persistence: T1406 - Device Administrator
    if (
        "android.permission.BIND_DEVICE_ADMIN" in perms
        or manifest.get("device_admin_receivers")
        or patterns.get("device_administration")
    ):
        matrix.append({
            "tactic": "Persistence",
            "technique_id": "T1406",
            "technique_name": "Device Administrator Abuse",
            "confidence": "HIGH",
            "evidence": "Registers DeviceAdminReceiver or calls DevicePolicyManager lockNow/wipeData APIs.",
        })

    # 9. Persistence: T1624 - Event-Triggered Execution
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perms or manifest.get("boot_receivers"):
        matrix.append({
            "tactic": "Persistence",
            "technique_id": "T1624",
            "technique_name": "Event-Triggered Execution: Boot Autostart",
            "confidence": "HIGH",
            "evidence": "Registers BroadcastReceiver listening for BOOT_COMPLETED to execute on device reboot.",
        })

    # 10. Execution: T1407 - Dynamic Code Loading
    if patterns.get("dynamic_code_loading"):
        matrix.append({
            "tactic": "Execution",
            "technique_id": "T1407",
            "technique_name": "Download New Code at Runtime (Dynamic Loading)",
            "confidence": "HIGH",
            "evidence": "Instantiates DexClassLoader, PathClassLoader, or InMemoryDexClassLoader.",
        })

    # 11. Execution / Delivery: T1475 - Deliver Malicious App (Dropper)
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms or "android.permission.INSTALL_PACKAGES" in perms:
        matrix.append({
            "tactic": "Initial Access / Delivery",
            "technique_id": "T1475",
            "technique_name": "Deliver Malicious App (Dropper / Side-loader)",
            "confidence": "HIGH",
            "evidence": "Requests REQUEST_INSTALL_PACKAGES capability to prompt or side-load secondary APKs.",
        })

    # 12. Defense Evasion: T1628 - Obfuscated / Packed Application
    if packer_info.get("is_packed") or patterns.get("reflection_abuse"):
        packers_found = ", ".join(packer_info.get("detected_packers", [])) or "Dynamic Java Reflection"
        matrix.append({
            "tactic": "Defense Evasion",
            "technique_id": "T1628",
            "technique_name": "Obfuscated / Packed Application",
            "confidence": "HIGH",
            "evidence": f"Detected commercial/custom packer signatures ({packers_found}) or extensive reflection.",
        })

    # 13. Defense Evasion: T1629 - Virtualization / Anti-Analysis Evasion
    if packer_info.get("anti_analysis_detected"):
        checks = ", ".join(packer_info.get("anti_analysis_detected", []))
        matrix.append({
            "tactic": "Defense Evasion",
            "technique_id": "T1629",
            "technique_name": "Virtualization / Sandbox Evasion",
            "confidence": "HIGH",
            "evidence": f"Implements runtime environment checks: {checks}",
        })

    # 14. Privilege Escalation: T1404 - OS Exploitation / Root Access
    if patterns.get("command_execution"):
        matrix.append({
            "tactic": "Privilege Escalation",
            "technique_id": "T1404",
            "technique_name": "Exploitation for Privilege Escalation (su / Shell)",
            "confidence": "MEDIUM",
            "evidence": "Attempts execution of system shell binaries (/system/bin/sh, su) or Runtime.exec.",
        })

    # 15. Command and Control: T1437 - Application Layer Protocol C2
    if net.get("urls") or net.get("ipv4"):
        matrix.append({
            "tactic": "Command and Control",
            "technique_id": "T1437",
            "technique_name": "Application Layer Protocol: HTTP/HTTPS C2",
            "confidence": "HIGH",
            "evidence": f"Hardcoded remote endpoints embedded in bytecode: {len(net.get('urls', []))} URLs, {len(net.get('ipv4', []))} public IPs.",
        })

    return matrix


