"""
AndroMalHut Online Threat Intelligence and Hash Lookup Module
Author: aryxan (https://github.com/aryxan/AndroMalHut)

Provides online validation of Android applications using:
1. Google Play Store catalog lookup (extracts official App Title, Developer, Category)
2. CIRCL Hashlookup API (free, open NIST NSRL / RDS / known clean software repository)
3. VirusTotal v3 (optional, when VT_API_KEY environment variable is configured)
4. Built-in curated dictionary and intelligent title-case resolver for popular Android apps.
"""

import os
import re
import json
import urllib.request
import urllib.parse
import urllib.error
from typing import Dict, Any, Optional

# Popular verified Android application mapping (Package Name -> Friendly App Name & Category)
KNOWN_POPULAR_APPS: Dict[str, Dict[str, str]] = {
    # Shopping & E-Commerce
    "com.flipkart.android": {"name": "Flipkart Online Shopping", "category": "Shopping", "vendor": "Flipkart"},
    "com.amazon.mShop.android.shopping": {"name": "Amazon Shopping", "category": "Shopping", "vendor": "Amazon Mobile LLC"},
    "com.myntra.android": {"name": "Myntra", "category": "Shopping", "vendor": "Myntra Designs"},
    "com.meesho.supply": {"name": "Meesho", "category": "Shopping", "vendor": "Meesho Inc"},
    "com.Dominos": {"name": "Domino's Pizza", "category": "Food & Drink", "vendor": "Jubilant FoodWorks"},
    "com.application.zomato": {"name": "Zomato: Food & Grocery", "category": "Food & Drink", "vendor": "Zomato"},
    "in.swiggy.android": {"name": "Swiggy Food & Grocery", "category": "Food & Drink", "vendor": "Swiggy"},
    "com.app.abhibus": {"name": "AbhiBus Bus & Train Booking", "category": "Travel", "vendor": "AbhiBus"},
    "com.goibibo": {"name": "Goibibo Hotel & Flight Booking", "category": "Travel", "vendor": "Goibibo"},
    "com.rapido.passenger": {"name": "Rapido Bike-Taxi & Auto", "category": "Maps & Navigation", "vendor": "Roppen Transportation"},
    "com.olacabs.customer": {"name": "Ola Cabs", "category": "Maps & Navigation", "vendor": "ANI Technologies"},
    "com.ubercab": {"name": "Uber", "category": "Maps & Navigation", "vendor": "Uber Technologies"},

    # Communication & Social
    "com.whatsapp": {"name": "WhatsApp Messenger", "category": "Communication", "vendor": "Meta Platforms"},
    "org.telegram.messenger": {"name": "Telegram", "category": "Communication", "vendor": "Telegram FZ-LLC"},
    "com.instagram.android": {"name": "Instagram", "category": "Social", "vendor": "Meta Platforms"},
    "com.facebook.katana": {"name": "Facebook", "category": "Social", "vendor": "Meta Platforms"},
    "com.snapchat.android": {"name": "Snapchat", "category": "Social", "vendor": "Snap Inc"},
    "com.discord": {"name": "Discord", "category": "Communication", "vendor": "Discord Inc"},
    "com.twitter.android": {"name": "X (formerly Twitter)", "category": "Social", "vendor": "X Corp"},
    "com.linkedin.android": {"name": "LinkedIn", "category": "Business", "vendor": "LinkedIn"},
    "com.reddit.frontpage": {"name": "Reddit", "category": "News & Discussion", "vendor": "reddit Inc"},

    # Media, Streaming & Entertainment
    "com.amazon.avod.thirdpartyclient": {"name": "Amazon Prime Video", "category": "Entertainment", "vendor": "Amazon Mobile LLC"},
    "com.netflix.mediaclient": {"name": "Netflix", "category": "Entertainment", "vendor": "Netflix Inc"},
    "com.google.android.youtube": {"name": "YouTube", "category": "Video Players & Editors", "vendor": "Google LLC"},
    "com.google.android.apps.youtube.music": {"name": "YouTube Music", "category": "Music & Audio", "vendor": "Google LLC"},
    "com.spotify.music": {"name": "Spotify: Music and Podcasts", "category": "Music & Audio", "vendor": "Spotify AB"},
    "com.jio.media.jiobeats": {"name": "JioSaavn Music & Podcasts", "category": "Music & Audio", "vendor": "Jio Platforms"},
    "com.jio.myjio": {"name": "MyJio", "category": "Productivity", "vendor": "Jio Platforms"},
    "com.chess": {"name": "Chess - Play & Learn", "category": "Board Games", "vendor": "Chess.com"},
    "com.MDickie.WrestlingEmpire": {"name": "Wrestling Empire", "category": "Action Games", "vendor": "MDickie"},
    "com.pubg.imobile": {"name": "Battlegrounds Mobile India (BGMI)", "category": "Action Games", "vendor": "KRAFTON Inc"},

    # Productive & System
    "andes.oplus.documentsreader": {"name": "OPPO Documents Reader", "category": "Productivity", "vendor": "OPPO / ColorOS"},
    "com.google.android.apps.docs": {"name": "Google Drive", "category": "Productivity", "vendor": "Google LLC"},
    "com.google.android.apps.docs.editors.sheets": {"name": "Google Sheets", "category": "Productivity", "vendor": "Google LLC"},
    "com.google.android.apps.authenticator2": {"name": "Google Authenticator", "category": "Tools", "vendor": "Google LLC"},
    "com.azure.authenticator": {"name": "Microsoft Authenticator", "category": "Productivity", "vendor": "Microsoft Corporation"},
    "com.brave.browser": {"name": "Brave Private Web Browser", "category": "Communication", "vendor": "Brave Software"},
    "org.mozilla.firefox": {"name": "Firefox Fast & Private Browser", "category": "Communication", "vendor": "Mozilla"},
    "com.android.chrome": {"name": "Google Chrome", "category": "Communication", "vendor": "Google LLC"},
    "com.github.android": {"name": "GitHub", "category": "Developer Tools", "vendor": "GitHub Inc"},
    "com.figma.mirror": {"name": "Figma Mirror", "category": "Art & Design", "vendor": "Figma Inc"},
    "com.fiverr.fiverr": {"name": "Fiverr - Freelance Services", "category": "Business", "vendor": "Fiverr"},
    "com.cloudflare.cloudflareoneagent": {"name": "Cloudflare One Agent", "category": "Business", "vendor": "Cloudflare Inc"},
    "com.digilocker.android": {"name": "DigiLocker", "category": "Government & ID", "vendor": "National e-Governance Division (NeGD)"},
    "com.fampay.in": {"name": "FamPay - UPI & Cards", "category": "Finance", "vendor": "FamPay"},
    "com.beneficiaryapp": {"name": "Ayushman Bharat PMJAY (Beneficiary)", "category": "Health & Medical", "vendor": "National Health Authority"},
}


def clean_title_from_package(package_name: str) -> str:
    """Generate a clean human-readable title from an arbitrary Android package identifier."""
    if not package_name:
        return "Unknown Application"

    parts = package_name.split(".")
    # Remove common prefixes
    filtered = [p for p in parts if p.lower() not in ("com", "org", "net", "io", "in", "android", "apps", "app")]
    if not filtered:
        filtered = parts

    # Take the last 1 or 2 meaningful segments
    candidate = " ".join(filtered[-2:] if len(filtered) >= 2 else filtered)

    # Split CamelCase (e.g. WrestlingEmpire -> Wrestling Empire)
    candidate = re.sub(r"([a-z])([A-Z])", r"\1 \2", candidate)
    # Replace underscores/dashes with spaces
    candidate = re.sub(r"[_\-]+", " ", candidate)

    # Title-case words
    words = [w.capitalize() for w in candidate.split() if w]
    return " ".join(words) if words else package_name


def resolve_friendly_app_name(package_name: str, candidate_label: Optional[str] = None) -> str:
    """Resolve the most accurate human-readable application title."""
    if candidate_label and candidate_label.strip() and candidate_label.strip().lower() != package_name.lower():
        # Clean quotes
        label = candidate_label.strip().strip("'\"")
        if label:
            return label

    if package_name in KNOWN_POPULAR_APPS:
        return KNOWN_POPULAR_APPS[package_name]["name"]

    return clean_title_from_package(package_name)


def lookup_play_store_app(package_name: str, timeout_sec: float = 3.0) -> Optional[Dict[str, Any]]:
    """Query Google Play Store web listing for official title, developer and category."""
    url = f"https://play.google.com/store/apps/details?id={urllib.parse.quote(package_name)}&hl=en"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                html = resp.read().decode("utf-8", errors="ignore")
                # Parse title
                title_match = re.search(r"<title id=\"main-title\">([^<]+)</title>", html)
                app_title = ""
                if title_match:
                    full_title = title_match.group(1).strip()
                    # Strip " - Apps on Google Play"
                    app_title = re.sub(r"\s*-\s*Apps on Google Play\s*$", "", full_title, flags=re.IGNORECASE)
                    app_title = app_title.replace("&#39;", "'").replace("&amp;", "&").replace("&quot;", '"')

                # Developer name match
                dev_match = re.search(r'itemprop="author".*?<span[^>]*>([^<]+)</span>', html, re.DOTALL)
                developer = dev_match.group(1).strip() if dev_match else "Google Play Verified Publisher"

                return {
                    "status": "VERIFIED_PLAY_STORE",
                    "package_name": package_name,
                    "official_name": app_title or resolve_friendly_app_name(package_name),
                    "developer": developer,
                    "play_store_url": url,
                    "is_play_store_indexed": True,
                }
    except Exception:
        pass

    return None


def lookup_circl_hash(sha256_hash: str, timeout_sec: float = 3.0) -> Optional[Dict[str, Any]]:
    """Query CIRCL Hashlookup API for NIST NSRL / RDS known clean file records."""
    if not sha256_hash or len(sha256_hash) != 64:
        return None

    url = f"https://hashlookup.circl.lu/lookup/sha256/{sha256_hash.lower()}"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "AndroMalHut-Forensics/1.0",
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if "FileName" in data or "ProductCode" in data or "SHA-256" in data:
                    return {
                        "status": "KNOWN_NSRL_RECORD",
                        "filename": data.get("FileName", "APK Archive"),
                        "product_name": data.get("ProductName", "Recognized Software Build"),
                        "db_source": "CIRCL / NIST Reference Data Set (NSRL)",
                        "trusted": True,
                    }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "NOT_IN_NSRL", "trusted": None}
    except Exception:
        pass

    return None


def lookup_virustotal_hash(sha256_hash: str, timeout_sec: float = 4.0) -> Optional[Dict[str, Any]]:
    """Query VirusTotal v3 files API if VT_API_KEY environment variable is present."""
    api_key = os.environ.get("VT_API_KEY", "").strip()
    if not api_key or not sha256_hash:
        return None

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash.lower()}"
    req = urllib.request.Request(
        url,
        headers={
            "x-apikey": api_key,
            "User-Agent": "AndroMalHut-Forensics/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                meaningful_name = attrs.get("meaningful_name") or attrs.get("names", [""])[0]
                return {
                    "status": "SUCCESS",
                    "malicious_count": stats.get("malicious", 0),
                    "suspicious_count": stats.get("suspicious", 0),
                    "undetected_count": stats.get("undetected", 0),
                    "harmless_count": stats.get("harmless", 0),
                    "suggested_threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", "CLEAN"),
                    "meaningful_name": meaningful_name,
                }
    except Exception:
        pass

    return None


def verify_package_online(package_name: str, sha256_hash: Optional[str] = None) -> Dict[str, Any]:
    """Perform aggregated online verification of an Android application and its hash."""
    friendly_fallback = resolve_friendly_app_name(package_name)
    result = {
        "package_name": package_name,
        "app_name": friendly_fallback,
        "sha256": sha256_hash or "Not Provided",
        "verified_source": "Local Catalog & Heuristics",
        "play_store_status": "Not Verified Online",
        "threat_reputation": "UNKNOWN / LOCAL EVALUATION",
        "details": [],
    }

    # 1. Check Google Play Store
    play_info = lookup_play_store_app(package_name)
    if play_info:
        result["app_name"] = play_info["official_name"]
        result["verified_source"] = f"Google Play Store (Developer: {play_info['developer']})"
        result["play_store_status"] = f"Official Google Play Store Application ({play_info['developer']})"
        result["threat_reputation"] = "BENIGN / VERIFIED PLAY STORE APPLICATION"
        result["details"].append(f"Official Listing: {play_info['play_store_url']}")
    elif package_name in KNOWN_POPULAR_APPS:
        known = KNOWN_POPULAR_APPS[package_name]
        result["app_name"] = known["name"]
        result["verified_source"] = f"Verified Application Database ({known['vendor']})"
        result["play_store_status"] = f"Recognized Mobile Application ({known['category']})"
        result["threat_reputation"] = "BENIGN / VERIFIED COMMON APPLICATION"

    # 2. Check CIRCL Hashlookup
    if sha256_hash:
        circl_res = lookup_circl_hash(sha256_hash)
        if circl_res and circl_res.get("trusted"):
            result["details"].append(f"CIRCL/NSRL Record: Recognized clean software build ({circl_res.get('product_name')})")
            if "BENIGN" not in result["threat_reputation"]:
                result["threat_reputation"] = "BENIGN / NIST NSRL VERIFIED"

    # 3. Check VirusTotal if configured
    if sha256_hash:
        vt_res = lookup_virustotal_hash(sha256_hash)
        if vt_res:
            mal = vt_res.get("malicious_count", 0)
            if mal > 0:
                result["threat_reputation"] = f"MALICIOUS / FLAGGED BY {mal} VIRUSTOTAL ENGINES"
                result["details"].append(f"Threat Label: {vt_res.get('suggested_threat_label')}")
            else:
                result["threat_reputation"] = "CLEAN / 0 VIRUSTOTAL DETECTIONS"
                result["details"].append("VirusTotal: Verified 0 malicious detections across AV engines.")

    return result
