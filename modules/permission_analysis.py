"""
DroidSleuth Permission Analysis Module
Analyzes Android permissions, assesses threats, detects dangerous combinations,
and maps permissions to MITRE ATT&CK for Mobile and forensic risk categories.
"""

from typing import Dict, Any, List, Set, Tuple

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

    return {
        "total_declared": len(declared_set),
        "total_granted": len(granted_set) if granted_permissions is not None else "Not Available (Static Analysis)",
        "risk_score": risk_score,
        "overall_severity": overall_severity,
        "capabilities": sorted(list(capabilities)),
        "matched_threat_patterns": matched_rules,
        "categorized_permissions": categorized,
        "dangerous_count": len(categorized["critical"]) + len(categorized["high"]) + len(categorized["medium"]),
        "is_play_store": is_play_store,
        "provenance_note": (
            "Verified Google Play Store Application (legitimate OTP/SIM binding permissions)"
            if is_play_store
            else "Standard / Untrusted Origin"
        ),
    }

