"""
DroidSleuth Network Analysis & C2 Indicator Module
Analyzes PCAP/PCAPNG captures (using tshark), DNS logs, Zeek logs, and text logs.
Extracts normalized indicators of compromise (IOCs), scores confidence, and correlates C2 activity.
"""

import os
import re
import csv
import json
import shutil
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple

from modules.case_manager import log_case_action


def is_tshark_installed() -> bool:
    """Check if tshark executable is available in PATH."""
    return shutil.which("tshark") is not None


# Known benign or infrastructure domains to filter/categorize
BENIGN_OR_TELEMETRY_DOMAINS = {
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "android.com", "googleadservices.com", "googlesyndication.com",
    "gvt1.com", "gvt2.com", "play.googleapis.com", "connectivitycheck.gstatic.com",
    "clients.l.google.com", "time.android.com", "w3.org", "apache.org",
}

PRIVATE_IP_REGEX = re.compile(
    r"^(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"0\.0\.0\.0|255\.255\.255\.255)$"
)


def is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is in private, loopback, or broadcast ranges."""
    return bool(PRIVATE_IP_REGEX.match(ip_str))


def parse_pcap_with_tshark(pcap_path: Path) -> List[Dict[str, Any]]:
    """Extract packet records from PCAP/PCAPNG capture using tshark."""
    if not is_tshark_installed():
        raise RuntimeError("tshark is not installed. PCAP/PCAPNG dissection requires tshark: sudo apt install tshark")

    fields = [
        "-e", "frame.time_utc",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "ip.proto",
        "-e", "tcp.dstport",
        "-e", "udp.dstport",
        "-e", "dns.qry.name",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "tls.handshake.extensions_server_name",
    ]

    cmd = [
        "tshark", "-r", str(pcap_path),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
    ] + fields

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("tshark extraction timed out on capture file.")

    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed with code {proc.returncode}: {proc.stderr.strip()}")

    records = []
    lines = proc.stdout.splitlines()

    for line in lines:
        parts = line.split("\t")
        if len(parts) < 12:
            parts.extend([""] * (12 - len(parts)))

        time_utc = parts[0]
        ip_src = parts[1] or parts[3]
        ip_dst = parts[2] or parts[4]
        proto = parts[5]
        dst_port = parts[6] or parts[7]
        dns_query = parts[8]
        http_host = parts[9]
        http_uri = parts[10]
        tls_sni = parts[11]

        records.append({
            "timestamp": time_utc,
            "ip_src": ip_src,
            "ip_dst": ip_dst,
            "proto": proto,
            "dst_port": dst_port,
            "dns_query": dns_query.lower() if dns_query else "",
            "http_host": http_host.lower() if http_host else "",
            "http_uri": http_uri,
            "tls_sni": tls_sni.lower() if tls_sni else "",
        })

    return records


def parse_text_network_log(log_path: Path) -> List[Dict[str, Any]]:
    """Fallback parser for text-based network/DNS logs, Zeek TSVs, or syslog."""
    records = []
    ipv4_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}\b")
    url_pattern = re.compile(r"https?://[a-zA-Z0-9_\-\.\:]+(?:/[a-zA-Z0-9_\-\.\?\=\&\%\#]*)?")

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            extracted_ips = ipv4_pattern.findall(line_str)
            extracted_urls = url_pattern.findall(line_str)
            extracted_domains = domain_pattern.findall(line_str)

            # Heuristic extraction
            ip_dst = extracted_ips[0] if extracted_ips else ""
            url = extracted_urls[0] if extracted_urls else ""
            domain = extracted_domains[0] if extracted_domains else ""

            records.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "line_number": line_no,
                "raw_line": line_str,
                "ip_dst": ip_dst,
                "url": url,
                "domain": domain,
            })

    return records


def parse_indicator_feed_file(feed_path: Path) -> List[Dict[str, Any]]:
    """Parse manually supplied indicator files (.txt, .csv, .json)."""
    indicators = []
    if not feed_path.exists():
        return indicators

    ext = feed_path.suffix.lower()

    if ext == ".json":
        try:
            data = json.loads(feed_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "indicator" in item:
                        indicators.append(item)
                    elif isinstance(item, str):
                        indicators.append({
                            "indicator": item.strip(),
                            "source_file": feed_path.name,
                            "type": "UNKNOWN",
                            "confidence": "HIGH",
                            "reason": "Imported manual indicator feed",
                        })
        except Exception:
            pass
    elif ext == ".csv":
        try:
            with open(feed_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ind = row.get("indicator") or row.get("ioc") or row.get("value")
                    if ind:
                        indicators.append({
                            "indicator": ind.strip(),
                            "type": row.get("indicator_type", row.get("type", "UNKNOWN")),
                            "source_file": feed_path.name,
                            "confidence": row.get("confidence", "HIGH"),
                            "reason": row.get("reason", "Imported manual indicator CSV"),
                        })
        except Exception:
            pass
    else:
        # Plain text line by line
        with open(feed_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line_str = line.strip()
                if not line_str or line_str.startswith("#"):
                    continue
                indicators.append({
                    "indicator": line_str,
                    "type": "UNKNOWN",
                    "source_file": feed_path.name,
                    "confidence": "HIGH",
                    "reason": "Imported manual indicator text file",
                })

    return indicators


def analyze_network_evidence(
    evidence_path: Path,
    case_dir: Optional[Path] = None,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Perform comprehensive network and C2 indicator analysis on capture or log file."""
    if not evidence_path.exists():
        raise FileNotFoundError(f"Network evidence file not found: {evidence_path}")

    ext = evidence_path.suffix.lower()
    is_pcap = ext in (".pcap", ".pcapng", ".cap")

    indicators_map: Dict[str, Dict[str, Any]] = {}

    def add_indicator(
        val: str,
        itype: str,
        source_loc: str,
        reason: str,
        confidence: str = "MEDIUM",
        timestamp: Optional[str] = None,
    ):
        if not val or val in indicators_map:
            if val in indicators_map:
                indicators_map[val]["occurrence_count"] += 1
                if timestamp:
                    if not indicators_map[val]["first_seen"]:
                        indicators_map[val]["first_seen"] = timestamp
                    indicators_map[val]["last_seen"] = timestamp
            return

        indicators_map[val] = {
            "indicator": val,
            "indicator_type": itype,
            "source_file": evidence_path.name,
            "source_location": source_loc,
            "first_seen": timestamp or "Unknown",
            "last_seen": timestamp or "Unknown",
            "occurrence_count": 1,
            "confidence": confidence,
            "reason": reason,
        }

    summary = {
        "source_file": evidence_path.name,
        "is_binary_capture": is_pcap,
        "tshark_used": False,
        "total_packets_or_lines": 0,
        "dns_queries_extracted": 0,
        "http_requests_extracted": 0,
        "tls_sni_extracted": 0,
        "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    if is_pcap:
        if not is_tshark_installed():
            return {
                "status": "ERROR",
                "error": "Binary PCAP file detected, but 'tshark' is not installed. Install tshark with: sudo apt install tshark",
            }
        records = parse_pcap_with_tshark(evidence_path)
        summary["tshark_used"] = True
        summary["total_packets_or_lines"] = len(records)

        for rec in records:
            ts = rec.get("timestamp")
            dst_ip = rec.get("ip_dst")
            if dst_ip and not is_private_ip(dst_ip):
                add_indicator(
                    dst_ip,
                    "IPv4",
                    f"Port {rec.get('dst_port')}",
                    "External destination IP observed in network capture",
                    confidence="MEDIUM",
                    timestamp=ts,
                )

            dns = rec.get("dns_query")
            if dns:
                summary["dns_queries_extracted"] += 1
                conf = "INFORMATIONAL" if any(b in dns for b in BENIGN_OR_TELEMETRY_DOMAINS) else "HIGH"
                reason = "Benign telemetry / Android system domain" if conf == "INFORMATIONAL" else "DNS query resolved by host"
                add_indicator(dns, "DNS_QUERY", f"Port {rec.get('dst_port')}", reason, confidence=conf, timestamp=ts)

            sni = rec.get("tls_sni")
            if sni:
                summary["tls_sni_extracted"] += 1
                conf = "INFORMATIONAL" if any(b in sni for b in BENIGN_OR_TELEMETRY_DOMAINS) else "HIGH"
                reason = "TLS Server Name Indication (SNI) contacted"
                add_indicator(sni, "TLS_SNI", f"Port {rec.get('dst_port')}", reason, confidence=conf, timestamp=ts)

            http_host = rec.get("http_host")
            http_uri = rec.get("http_uri")
            if http_host:
                summary["http_requests_extracted"] += 1
                full_url = f"http://{http_host}{http_uri}" if http_uri else f"http://{http_host}/"
                add_indicator(full_url, "HTTP_URL", f"Port {rec.get('dst_port')}", "Cleartext HTTP request transmitted", confidence="HIGH", timestamp=ts)
    else:
        # Text log / Zeek / CSV / plain text
        records = parse_text_network_log(evidence_path)
        summary["total_packets_or_lines"] = len(records)
        for rec in records:
            ts = rec.get("timestamp")
            line_no = rec.get("line_number", 0)
            if rec.get("ip_dst") and not is_private_ip(rec["ip_dst"]):
                add_indicator(rec["ip_dst"], "IPv4", f"Line {line_no}", "Public IP parsed from network log", confidence="MEDIUM", timestamp=ts)
            if rec.get("url"):
                add_indicator(rec["url"], "URL", f"Line {line_no}", "URL parsed from network log", confidence="HIGH", timestamp=ts)
            if rec.get("domain") and not any(b in rec["domain"] for b in BENIGN_OR_TELEMETRY_DOMAINS):
                add_indicator(rec["domain"], "DOMAIN", f"Line {line_no}", "Domain parsed from network log", confidence="MEDIUM", timestamp=ts)

    indicator_table = list(indicators_map.values())
    indicator_table.sort(key=lambda x: (x["confidence"] != "HIGH", x["confidence"] != "MEDIUM", -x["occurrence_count"]))

    results = {
        "status": "SUCCESS",
        "summary": summary,
        "indicators_count": len(indicator_table),
        "indicators": indicator_table,
    }

    # Save to analysis/network_analysis/ if case_dir given
    if case_dir:
        out_dir = case_dir / "analysis" / "network_analysis"
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        stem = evidence_path.stem

        json_out = out_dir / f"network_analysis_{stem}_{timestamp}.json"
        json_out.write_text(json.dumps(results, indent=2), encoding="utf-8")

        csv_out = out_dir / f"network_indicators_{stem}_{timestamp}.csv"
        with open(csv_out, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["indicator", "indicator_type", "source_file", "source_location", "first_seen", "last_seen", "occurrence_count", "confidence", "reason"])
            for ind in indicator_table:
                writer.writerow([
                    ind.get("indicator"),
                    ind.get("indicator_type"),
                    ind.get("source_file"),
                    ind.get("source_location"),
                    ind.get("first_seen"),
                    ind.get("last_seen"),
                    ind.get("occurrence_count"),
                    ind.get("confidence"),
                    ind.get("reason"),
                ])

        log_case_action(
            case_dir,
            "NETWORK_ANALYSIS_COMPLETED",
            f"Analyzed {evidence_path.name}: identified {len(indicator_table)} indicators. Output: {json_out.name}",
            operator,
        )

    return results
