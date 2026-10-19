"""
DroidSleuth Timeline Correlation Module
Consolidates chronological incident timeline from APK metadata, installation times,
device logs, SMS records, network captures, and evidence acquisition logs.
"""

import os
import csv
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import log_case_action


def normalize_iso_timestamp(ts_str: str) -> Tuple[str, str]:
    """Attempt to parse and normalize arbitrary timestamp into UTC ISO format.
    
    Returns (normalized_iso_utc, limitations_note).
    """
    if not ts_str or ts_str in ("Unknown", "Unavailable", "0"):
        return ("0000-00-00T00:00:00Z", "Timestamp missing or unavailable from source artifact")

    ts_clean = ts_str.strip()

    # Try ISO formats
    iso_formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d",
    ]

    for fmt in iso_formats:
        try:
            dt = datetime.strptime(ts_clean, fmt)
            if dt.tzinfo is None:
                # Naive assumed UTC or local clock
                return (dt.replace(tzinfo=timezone.utc).isoformat(), "Local device clock; UTC assumed without offset")
            return (dt.astimezone(timezone.utc).isoformat(), "Exact timestamp with timezone offset")
        except Exception:
            continue

    # Try numeric epoch ms or sec
    if ts_clean.isdigit():
        try:
            val = int(ts_clean)
            if val > 1e11:  # ms
                dt = datetime.fromtimestamp(val / 1000.0, tz=timezone.utc)
            else:  # sec
                dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return (dt.isoformat(), "Unix epoch converted to UTC")
        except Exception:
            pass

    return (ts_clean, "Unparsed raw timestamp string; sorting order may be approximate")


def build_incident_timeline(case_dir: Path, operator: Optional[str] = None) -> List[Dict[str, Any]]:
    """Aggregate forensic events across all case artifacts into a sorted chronological timeline."""
    events: List[Dict[str, Any]] = []

    # 1. Evidence Acquisition events from case.json history and evidence_hashes.json
    hashes_file = case_dir / "hashes" / "evidence_hashes.json"
    if hashes_file.exists():
        try:
            records = json.loads(hashes_file.read_text(encoding="utf-8"))
            for r in records:
                ts_utc, note = normalize_iso_timestamp(r.get("collected_at_utc", ""))
                events.append({
                    "timestamp_utc": ts_utc,
                    "original_timestamp": r.get("collected_at_utc", ""),
                    "timezone": "UTC",
                    "event_type": "EVIDENCE_COLLECTION",
                    "source": f"Hash Manifest / {r.get('filename')}",
                    "description": f"Evidence acquired: {r.get('description')} ({r.get('size_bytes')} bytes, SHA256: {r.get('sha256')[:16]}...)",
                    "confidence": "HIGH",
                    "limitations": note,
                })
        except Exception:
            pass

    # 2. Case history actions
    case_json = case_dir / "case.json"
    if case_json.exists():
        try:
            meta = json.loads(case_json.read_text(encoding="utf-8"))
            for h in meta.get("history", []):
                ts_utc, note = normalize_iso_timestamp(h.get("timestamp_utc", ""))
                events.append({
                    "timestamp_utc": ts_utc,
                    "original_timestamp": h.get("timestamp_utc", ""),
                    "timezone": "UTC",
                    "event_type": f"CASE_{h.get('action')}",
                    "source": f"Audit Log ({h.get('operator')})",
                    "description": h.get("details", ""),
                    "confidence": "HIGH",
                    "limitations": note,
                })
        except Exception:
            pass

    # 3. APK Analysis timestamps
    apk_analysis_dir = case_dir / "analysis" / "apk_analysis"
    if apk_analysis_dir.exists():
        for f in apk_analysis_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                manifest = data.get("manifest", {})
                pkg = manifest.get("package_name", "Unknown")

                analyzed_at = data.get("analyzed_at_utc")
                if analyzed_at:
                    ts_utc, note = normalize_iso_timestamp(analyzed_at)
                    events.append({
                        "timestamp_utc": ts_utc,
                        "original_timestamp": analyzed_at,
                        "timezone": "UTC",
                        "event_type": "STATIC_ANALYSIS",
                        "source": f"APK Analysis ({f.name})",
                        "description": f"APK Static Analysis completed for {pkg} (Threat severity: {data.get('permissions_analysis', {}).get('overall_severity', 'Unknown')})",
                        "confidence": "HIGH",
                        "limitations": note,
                    })
            except Exception:
                pass

    # 4. Device inventory installation timestamps
    inv_dir = case_dir / "evidence" / "device_inventory"
    if inv_dir.exists():
        for f in inv_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                inv_time = data.get("inventory_time_utc")
                if inv_time:
                    ts_utc, note = normalize_iso_timestamp(inv_time)
                    events.append({
                        "timestamp_utc": ts_utc,
                        "original_timestamp": inv_time,
                        "timezone": "UTC",
                        "event_type": "DEVICE_INVENTORY",
                        "source": f"Device Inventory ({data.get('device_serial', 'device')})",
                        "description": f"Device inventory snapshot recorded: {data.get('total_apps', 0)} total applications ({data.get('user_apps_count', 0)} 3rd-party)",
                        "confidence": "HIGH",
                        "limitations": note,
                    })
            except Exception:
                pass

    # 5. SMS Events
    sms_analysis_dir = case_dir / "analysis" / "sms_analysis"
    if sms_analysis_dir.exists():
        for f in sms_analysis_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for msg in data.get("flagged_messages", []):
                    raw_ts = msg.get("timestamp_utc", "")
                    ts_utc, note = normalize_iso_timestamp(raw_ts)
                    events.append({
                        "timestamp_utc": ts_utc,
                        "original_timestamp": raw_ts,
                        "timezone": "Device Local / UTC",
                        "event_type": "SUSPICIOUS_SMS",
                        "source": f"SMS Message ({msg.get('sender_recipient')})",
                        "description": f"Direction: {msg.get('direction')} - Flagged for: {'; '.join(msg.get('reasons', []))} | Content: {msg.get('body', '')[:120]}",
                        "confidence": "HIGH",
                        "limitations": f"{note} (Phone SMS timestamp may be subject to carrier or device clock settings)",
                    })
            except Exception:
                pass

    # 6. Network Analysis Events
    net_analysis_dir = case_dir / "analysis" / "network_analysis"
    if net_analysis_dir.exists():
        for f in net_analysis_dir.glob("*.json"):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                for ind in data.get("indicators", []):
                    ts = ind.get("first_seen")
                    if ts and ts != "Unknown":
                        ts_utc, note = normalize_iso_timestamp(ts)
                        events.append({
                            "timestamp_utc": ts_utc,
                            "original_timestamp": ts,
                            "timezone": "UTC",
                            "event_type": "NETWORK_OBSERVATION",
                            "source": f"Network Capture ({ind.get('source_file')})",
                            "description": f"Observed communication to {ind.get('indicator_type')} {ind.get('indicator')} ({ind.get('reason')})",
                            "confidence": ind.get("confidence", "MEDIUM"),
                            "limitations": note,
                        })
            except Exception:
                pass

    # Sort strictly chronologically
    events.sort(key=lambda x: x["timestamp_utc"])

    # Export to analysis/timelines/
    out_dir = case_dir / "analysis" / "timelines"
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    json_path = out_dir / f"timeline_{timestamp}.json"
    csv_path = out_dir / f"timeline_{timestamp}.csv"

    json_path.write_text(json.dumps(events, indent=2), encoding="utf-8")

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp (UTC)", "Original Timestamp", "Timezone", "Event Type", "Source", "Description", "Confidence", "Limitations"])
        for ev in events:
            writer.writerow([
                ev.get("timestamp_utc"),
                ev.get("original_timestamp"),
                ev.get("timezone"),
                ev.get("event_type"),
                ev.get("source"),
                ev.get("description"),
                ev.get("confidence"),
                ev.get("limitations"),
            ])

    log_case_action(
        case_dir,
        "TIMELINE_CORRELATED",
        f"Correlated {len(events)} events across case evidence into {json_path.name}",
        operator,
    )

    return events
