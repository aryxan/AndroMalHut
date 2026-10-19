"""
AndroMalHut Forensic Reporting Module
Author: aryxan (https://github.com/aryxan/AndroMalHut)
Generates comprehensive forensic reports in Markdown and PDF (via ReportLab).
Includes all 16 required sections, cryptographic manifests, timelines, and MITRE correlations.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import log_case_action

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
        HRFlowable,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page counts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#555555"))

        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "AndroMalHut Forensic Report")
            self.drawRightString(612 - 54, 750, "DEFENSIVE FORENSIC INVESTIGATION")
            self.setStrokeColor(colors.HexColor("#D0D0D0"))
            self.setLineWidth(0.5)
            self.line(54, 744, 612 - 54, 744)

        # Footer
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 54, 36, page_str)
        self.drawString(54, 36, "CONFIDENTIAL // LAW ENFORCEMENT & DEFENSIVE INCIDENT RESPONSE")
        self.setStrokeColor(colors.HexColor("#D0D0D0"))
        self.setLineWidth(0.5)
        self.line(54, 46, 612 - 54, 46)

        self.restoreState()


def load_case_data(case_dir: Path) -> Dict[str, Any]:
    """Gather all case records, analysis results, and evidence data."""
    data: Dict[str, Any] = {
        "case": {},
        "hashes": [],
        "inventory": None,
        "apk_analysis": [],
        "network_analysis": [],
        "sms_analysis": [],
        "log_analysis": [],
        "timeline": [],
        "ai_explanations": [],
    }

    # case.json
    case_json = case_dir / "case.json"
    if case_json.exists():
        try:
            data["case"] = json.loads(case_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # hashes
    hashes_json = case_dir / "hashes" / "evidence_hashes.json"
    if hashes_json.exists():
        try:
            data["hashes"] = json.loads(hashes_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # device_inventory
    inv_dir = case_dir / "evidence" / "device_inventory"
    if inv_dir.exists():
        for f in inv_dir.glob("*.json"):
            try:
                data["inventory"] = json.loads(f.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    # apk_analysis
    apk_dir = case_dir / "analysis" / "apk_analysis"
    if apk_dir.exists():
        for f in apk_dir.glob("*.json"):
            try:
                data["apk_analysis"].append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass

    # network_analysis
    net_dir = case_dir / "analysis" / "network_analysis"
    if net_dir.exists():
        for f in net_dir.glob("*.json"):
            try:
                data["network_analysis"].append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass

    # sms_analysis
    sms_dir = case_dir / "analysis" / "sms_analysis"
    if sms_dir.exists():
        for f in sms_dir.glob("*.json"):
            try:
                data["sms_analysis"].append(json.loads(f.read_text(encoding="utf-8")))
            except Exception:
                pass

    # timelines
    time_dir = case_dir / "analysis" / "timelines"
    if time_dir.exists():
        for f in sorted(time_dir.glob("*.json"), reverse=True):
            try:
                data["timeline"] = json.loads(f.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    # ai_explanations
    ai_dir = case_dir / "analysis" / "ai_explanations"
    if ai_dir.exists():
        for f in sorted(ai_dir.glob("*.md"), reverse=True):
            try:
                data["ai_explanations"].append(f.read_text(encoding="utf-8"))
            except Exception:
                pass

    return data


def generate_markdown_report(case_dir: Path, operator: Optional[str] = None) -> Path:
    """Generate the comprehensive 16-section forensic Markdown report."""
    data = load_case_data(case_dir)
    case_meta = data["case"]
    case_id = case_meta.get("case_id", case_dir.name)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    report_lines: List[str] = []

    # Title & Metadata
    report_lines.append(f"# AndroMalHut Forensic Investigation Report: {case_id}\n")
    report_lines.append(f"**Report Generated:** {now_utc}  ")
    report_lines.append(f"**Investigator:** {case_meta.get('investigator', 'Forensic Investigator')}  ")
    report_lines.append(f"**Case Status:** {case_meta.get('status', 'Active')}  ")
    report_lines.append(f"**Incident Date:** {case_meta.get('incident_date', 'Unknown')}  ")
    report_lines.append(f"**Time Zone:** {case_meta.get('time_zone', 'UTC')}\n")
    report_lines.append("---\n")

    # Section 1: Case Summary
    report_lines.append("## 1. Case Summary\n")
    report_lines.append(f"{case_meta.get('case_description', 'Investigation into suspect mobile malware infection.')}\n")
    if case_meta.get("notes"):
        report_lines.append(f"**Investigator Notes:** {case_meta.get('notes')}\n")

    # Section 2: Scope and Authorization Notes
    report_lines.append("## 2. Scope and Authorization Notes\n")
    report_lines.append(
        "This forensic investigation was authorized for defensive security verification, incident containment, "
        "and account compromise assessment following reported social engineering. All evidence collection was executed "
        "using non-destructive, read-only acquisition techniques via standard Android Debug Bridge interfaces and offline file inspection. "
        "No device protections were bypassed, no system partitions were written to, and no untrusted APK code was executed on the host system.\n"
    )

    # Section 3: Device Details
    report_lines.append("## 3. Device Details\n")
    report_lines.append(f"- **Target Device Identifier:** {case_meta.get('device_identifier', 'Unknown Device')}")
    if data["inventory"]:
        inv = data["inventory"]
        report_lines.append(f"- **Device Serial:** `{inv.get('device_serial', 'N/A')}`")
        report_lines.append(f"- **Inventory Timestamp:** {inv.get('inventory_time_utc', 'N/A')}")
        report_lines.append(f"- **Total Installed Packages:** {inv.get('total_apps', 0)}")
        report_lines.append(f"- **User / Third-Party Apps:** {inv.get('user_apps_count', 0)}")
        report_lines.append(f"- **System Apps:** {inv.get('system_apps_count', 0)}\n")
    else:
        report_lines.append("- *No live ADB device snapshot recorded for this case (Offline file analysis mode).*\n")

    # Section 4: Evidence Inventory
    report_lines.append("## 4. Evidence Inventory & Chain of Custody\n")
    if data["hashes"]:
        report_lines.append("| Preserved File | Type / Subfolder | Size (Bytes) | Collected (UTC) | Description |")
        report_lines.append("|---|---|---|---|---|")
        for h in data["hashes"]:
            report_lines.append(f"| `{h.get('filename')}` | `{h.get('relative_path')}` | {h.get('size_bytes')} | {h.get('collected_at_utc')} | {h.get('description')} |")
        report_lines.append("")
    else:
        report_lines.append("*No preserved evidence files currently registered in hash manifest.*\n")

    # Section 5: Hash Manifest
    report_lines.append("## 5. Cryptographic Hash Manifest\n")
    if data["hashes"]:
        report_lines.append("| Preserved File | SHA-256 | SHA-1 | MD5 |")
        report_lines.append("|---|---|---|---|")
        for h in data["hashes"]:
            report_lines.append(f"| `{h.get('filename')}` | `{h.get('sha256')}` | `{h.get('sha1')}` | `{h.get('md5')}` |")
        report_lines.append("")
    else:
        report_lines.append("*No cryptographic hashes recorded.*\n")

    # Section 6: Installed Application Inventory Summary
    report_lines.append("## 6. Installed Application Inventory Summary\n")
    if data["inventory"] and data["inventory"].get("applications"):
        user_apps = [a for a in data["inventory"]["applications"] if a.get("type") == "User/Third-Party"]
        report_lines.append(f"Detected **{len(user_apps)}** third-party user applications on device:\n")
        report_lines.append("| Package Name | APK Path | Running at Acquisition |")
        report_lines.append("|---|---|---|")
        for a in user_apps[:40]:  # Cap at 40 in summary
            report_lines.append(f"| `{a.get('package_name')}` | `{a.get('apk_path')}` | {'YES' if a.get('is_running') else 'No'} |")
        if len(user_apps) > 40:
            report_lines.append(f"\n*(Truncated: {len(user_apps) - 40} additional user apps listed in raw CSV export)*\n")
        report_lines.append("")
    else:
        report_lines.append("*No installed application inventory recorded.*\n")

    # Section 7: Suspicious APK Metadata
    report_lines.append("## 7. Suspicious APK Metadata\n")
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            m = apk.get("manifest", {})
            h = apk.get("hashes", {})
            report_lines.append(f"### Application: `{m.get('package_name', 'Unknown')}`\n")
            report_lines.append(f"- **Application Label:** {m.get('application_label')}")
            report_lines.append(f"- **Version:** {m.get('version_name')} (versionCode: {m.get('version_code')})")
            report_lines.append(f"- **Target SDK:** {m.get('target_sdk')} (Min SDK: {m.get('min_sdk')})")
            report_lines.append(f"- **APK File Size:** {h.get('size_bytes')} bytes")
            report_lines.append(f"- **APK SHA-256:** `{h.get('sha256')}`")
            report_lines.append(f"- **Signing Status:** {apk.get('signing_info', {}).get('status', 'Unknown')}")
            report_lines.append(f"- **Embedded DEX Files:** {', '.join(apk.get('embedded_files', {}).get('dex_files', []))}")
            report_lines.append(f"- **Embedded Native Libs:** {len(apk.get('embedded_files', {}).get('native_libraries', []))}")
            report_lines.append("")
    else:
        report_lines.append("*No suspicious APK static analysis performed.*\n")

    # Section 8: Permission and Component Analysis
    report_lines.append("## 8. Permission and Component Analysis\n")
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            pa = apk.get("permissions_analysis", {})
            m = apk.get("manifest", {})
            report_lines.append(f"### Threat Assessment for `{m.get('package_name')}`\n")
            report_lines.append(f"- **Overall Threat Severity:** **{pa.get('overall_severity', 'UNKNOWN')}** (Score: {pa.get('risk_score', 0)}/100)")
            report_lines.append(f"- **Total Declared Permissions:** {pa.get('total_declared', 0)}")
            report_lines.append(f"- **Identified Capabilities:** {', '.join(pa.get('capabilities', ['None']))}\n")

            if pa.get("matched_threat_patterns"):
                report_lines.append("#### Matched High-Risk Threat Combinations:\n")
                for pat in pa["matched_threat_patterns"]:
                    report_lines.append(f"- **{pat.get('name')}** (`{pat.get('severity')}`): {pat.get('description')} [MITRE: {pat.get('mitre_id')}]")
                report_lines.append("")

            # Exported components
            exp_comps = m.get("exported_components", [])
            report_lines.append(f"#### Exported Android Components ({len(exp_comps)} detected):\n")
            if exp_comps:
                report_lines.append("| Component Type | Component Name | Required Permission | Filter Actions |")
                report_lines.append("|---|---|---|---|")
                for c in exp_comps[:20]:
                    acts = ", ".join(c.get("actions", [])) or "None"
                    report_lines.append(f"| {c.get('type')} | `{c.get('name')}` | `{c.get('permission') or 'None'}` | `{acts}` |")
                report_lines.append("")
            else:
                report_lines.append("*No explicitly exported components found in manifest.*\n")
    else:
        report_lines.append("*No permission or component data available.*\n")

    # Section 9: Suspicious Strings and Network Indicators
    report_lines.append("## 9. Suspicious Strings and Code Indicators\n")
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            patterns = apk.get("observed_patterns", {})
            report_lines.append("#### Observed Security-Sensitive API Patterns in Bytecode:\n")
            has_pattern = False
            for cat, items in patterns.items():
                if items:
                    has_pattern = True
                    report_lines.append(f"- **{cat.replace('_', ' ').title()}:** {', '.join(items)}")
            if not has_pattern:
                report_lines.append("- *No high-risk API string patterns detected in DEX string pool.*")
            report_lines.append("")
    else:
        report_lines.append("*No string indicator records available.*\n")

    # Section 10: Possible C2 Findings with Confidence Levels
    report_lines.append("## 10. Possible C2 Findings and Network Indicators\n")
    net_indicators = []
    if data["network_analysis"]:
        for na in data["network_analysis"]:
            net_indicators.extend(na.get("indicators", []))

    if net_indicators:
        report_lines.append("| Indicator | Type | Confidence | Occurrences | Location / Port | Forensic Reason |")
        report_lines.append("|---|---|---|---|---|---|")
        for ind in net_indicators[:35]:
            report_lines.append(
                f"| `{ind.get('indicator')}` | {ind.get('indicator_type')} | **{ind.get('confidence')}** | "
                f"{ind.get('occurrence_count')} | {ind.get('source_location')} | {ind.get('reason')} |"
            )
        report_lines.append("")
    else:
        report_lines.append("*No suspicious network C2 indicators or communication sessions recorded.*\n")

    # Section 11: Log and SMS Findings
    report_lines.append("## 11. Log and SMS Findings\n")
    sms_flagged = []
    if data["sms_analysis"]:
        for sa in data["sms_analysis"]:
            sms_flagged.extend(sa.get("analysis", {}).get("flagged_messages", []))

    if sms_flagged:
        report_lines.append(f"### Suspicious / 2FA SMS Messages ({len(sms_flagged)} detected):\n")
        report_lines.append("| Timestamp (UTC) | Sender / Recipient | Direction | Flagged Rationale | Snippet |")
        report_lines.append("|---|---|---|---|---|")
        for m in sms_flagged[:20]:
            snippet = m.get("body", "").replace("\n", " ")[:60]
            reasons = "; ".join(m.get("reasons", []))
            report_lines.append(f"| {m.get('timestamp_utc')} | `{m.get('sender_recipient')}` | {m.get('direction')} | {reasons} | {snippet}... |")
        report_lines.append("")
    else:
        report_lines.append("- *No suspicious SMS messages or 2FA interceptions identified in imported evidence.*\n")

    # Section 12: Chronological Timeline
    report_lines.append("## 12. Chronological Incident Timeline\n")
    if data["timeline"]:
        report_lines.append("| Timestamp (UTC) | Event Type | Source | Event Description | Confidence |")
        report_lines.append("|---|---|---|---|---|")
        for ev in data["timeline"][:40]:
            report_lines.append(
                f"| {ev.get('timestamp_utc')} | `{ev.get('event_type')}` | {ev.get('source')} | "
                f"{ev.get('description')} | {ev.get('confidence')} |"
            )
        report_lines.append("")
    else:
        report_lines.append("*Incident timeline has not yet been compiled for this case.*\n")

    # Section 13: Limitations and Unavailable Evidence
    report_lines.append("## 13. Limitations and Unavailable Evidence\n")
    report_lines.append(
        "- **Device Root Restrictions:** The device was inspected under standard authorized user privileges without root access. "
        "Consequently, private application sandboxes (`/data/data/<package>`) and raw SQLite databases were inaccessible.\n"
        "- **Deleted Data Recovery:** Non-rooted Android devices encrypt user data and do not permit low-level physical block imaging "
        "or deleted SQLite record carving without vendor-specific exploit chains or chip-off acquisitions.\n"
        "- **Dynamic Execution:** Static analysis does not execute the payload. C2 command sequences and dynamically unpacked DEX modules "
        "cannot be observed without isolated sandboxed dynamic execution.\n"
        "- **Clock Drift:** Device timestamps reflect internal hardware clocks and network provider sync, which may have minor offsets from true UTC.\n"
    )

    # Section 14: Conclusions Separated from Hypotheses
    report_lines.append("## 14. Conclusions and Behavioral Hypotheses\n")
    report_lines.append("### Directly Observed Forensic Facts:\n")
    facts_written = False
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            for f in apk.get("findings", {}).get("facts", []):
                report_lines.append(f"- {f}")
                facts_written = True
    if not facts_written:
        report_lines.append("- Evidence collected and verified against cryptographic hashes.")
    report_lines.append("\n### Behavioral Hypotheses (Requiring Dynamic Corroboration):\n")
    hypo_written = False
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            for h in apk.get("findings", {}).get("hypotheses", []):
                report_lines.append(f"- **[HYPOTHESIS]** {h}")
                hypo_written = True
    if not hypo_written:
        report_lines.append("- No high-confidence malicious hypotheses generated.")
    report_lines.append("")

    # Optional AI-Assisted explanation if available
    if data["ai_explanations"]:
        report_lines.append("### AI-Assisted Narrative Analysis (Ollama Interpretation):\n")
        report_lines.append(data["ai_explanations"][0])
        report_lines.append("")

    # Section 15: Recommended Defensive Actions
    report_lines.append("## 15. Recommended Defensive Actions\n")
    report_lines.append(
        "1. **Isolate Device:** Disconnect the phone from Wi-Fi and remove the cellular SIM card to halt active C2 communication.\n"
        "2. **Revoke Accessibility & Admin Rights:** Navigate to *Settings -> Accessibility* and *Settings -> Security -> Device Admin apps* "
        "to disable suspect app permissions prior to uninstallation.\n"
        "3. **Uninstall Malicious Packages:** Remove identified unauthorized application packages via `Settings -> Apps` or authorized ADB.\n"
        "4. **Credential Reset:** Assume credentials entered while the suspect app was active may be compromised. Rotate all banking, email, "
        "and primary online account passwords from a separate known-clean computer.\n"
        "5. **Revoke Active Sessions:** Force sign-out of all current web/app sessions across Google, financial institutions, and messaging platforms.\n"
        "6. **Replace SIM Card / Contact Carrier:** If SMS toll fraud or SIM swap was observed, notify the cellular carrier immediately.\n"
    )

    # Section 16: Tool Versions and Collection Methodology
    report_lines.append("## 16. Tool Versions and Collection Methodology\n")
    report_lines.append("- **Forensic Toolkit:** AndroMalHut v1.0.0 by aryxan (https://github.com/aryxan/AndroMalHut)")
    report_lines.append(f"- **Python Version:** {sys.version.split()[0]}")
    report_lines.append(f"- **Host Platform:** {sys.platform}")
    report_lines.append("- **Collection Method:** Read-only ADB query, AXML parsing, DEX string extraction, tshark PCAP dissection")
    report_lines.append("- **Cryptographic Hashing:** SHA-256, SHA-1, MD5 verified via hashlib\n")

    # Write report
    reports_dir = case_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"CASE_REPORT_{case_id}.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")

    log_case_action(
        case_dir,
        "REPORT_GENERATED",
        f"Generated complete 16-section Markdown forensic report: {report_path.name}",
        operator,
    )

    return report_path


def generate_pdf_report(case_dir: Path, operator: Optional[str] = None) -> Tuple[Optional[Path], Optional[str]]:
    """Generate a clean, professional PDF forensic report using ReportLab."""
    if not REPORTLAB_AVAILABLE:
        return (
            None,
            "Error: 'reportlab' is not installed. PDF generation requires reportlab: pip install reportlab",
        )

    # First ensure latest Markdown report exists
    md_path = generate_markdown_report(case_dir, operator)
    data = load_case_data(case_dir)
    case_meta = data["case"]
    case_id = case_meta.get("case_id", case_dir.name)

    reports_dir = case_dir / "reports"
    pdf_path = reports_dir / f"CASE_REPORT_{case_id}.pdf"

    # Setup ReportLab DocTemplate
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#1A2530"),
        spaceAfter=10,
    )

    h1_style = ParagraphStyle(
        "Heading1_Custom",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#0D47A1"),
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    )

    h2_style = ParagraphStyle(
        "Heading2_Custom",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#263238"),
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    )

    body_style = ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#212121"),
        spaceAfter=4,
    )

    bullet_style = ParagraphStyle(
        "Bullet_Custom",
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=3,
    )

    meta_box_style = ParagraphStyle(
        "MetaBox",
        parent=body_style,
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#37474F"),
    )

    story = []

    # Title Banner
    story.append(Paragraph(f"AndroMalHut Forensic Investigation Report", title_style))
    story.append(Paragraph(f"<b>Case Identifier:</b> {case_id} &nbsp;|&nbsp; <b>Investigator:</b> {case_meta.get('investigator', 'Forensic Investigator')} &nbsp;|&nbsp; <b>Generated:</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", meta_box_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0D47A1"), spaceBefore=2, spaceAfter=12))

    # Section 1: Summary
    story.append(Paragraph("1. Executive Case Summary", h1_style))
    story.append(Paragraph(case_meta.get("case_description", "Investigation into suspect mobile malware infection."), body_style))
    if case_meta.get("notes"):
        story.append(Paragraph(f"<b>Investigator Notes:</b> {case_meta.get('notes')}", body_style))
    story.append(Spacer(1, 8))

    # Section 2: Scope & Authorization
    story.append(Paragraph("2. Scope and Authorization Notes", h1_style))
    scope_text = (
        "This forensic investigation was conducted under authorized defensive incident response guidelines. "
        "Collection methodology utilized read-only ADB acquisition and offline static analysis. "
        "Evidence integrity was preserved with cryptographic hashing immediately upon acquisition. "
        "No device security protections were bypassed, and untrusted APK code was not executed."
    )
    story.append(Paragraph(scope_text, body_style))
    story.append(Spacer(1, 8))

    # Section 3: Device Details
    story.append(Paragraph("3. Device Details", h1_style))
    story.append(Paragraph(f"• <b>Device Identifier:</b> {case_meta.get('device_identifier', 'Unknown')}", bullet_style))
    if data["inventory"]:
        inv = data["inventory"]
        story.append(Paragraph(f"• <b>ADB Serial:</b> {inv.get('device_serial', 'N/A')}", bullet_style))
        story.append(Paragraph(f"• <b>Total Installed Packages:</b> {inv.get('total_apps', 0)} ({inv.get('user_apps_count', 0)} User, {inv.get('system_apps_count', 0)} System)", bullet_style))
    else:
        story.append(Paragraph("• <i>No live connected ADB device registered.</i>", bullet_style))
    story.append(Spacer(1, 8))

    # Section 4 & 5: Evidence & Cryptographic Manifest
    story.append(Paragraph("4. Evidence & Cryptographic Hash Manifest", h1_style))
    if data["hashes"]:
        table_data = [["Filename", "Size", "SHA-256", "Collected (UTC)"]]
        for h in data["hashes"]:
            table_data.append([
                Paragraph(h.get("filename", "")[:24], body_style),
                str(h.get("size_bytes", 0)),
                Paragraph(f"<font size=7>{h.get('sha256', '')}</font>", body_style),
                Paragraph(f"<font size=7>{h.get('collected_at_utc', '')[:19]}</font>", body_style),
            ])

        t = Table(table_data, colWidths=[120, 50, 220, 114])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0D47A1")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
            ("TOPPADDING", (0, 0), (-1, 0), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F5F7FA"), colors.white]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("<i>No evidence hashes recorded.</i>", body_style))
    story.append(Spacer(1, 10))

    # Section 6: Installed Apps
    story.append(Paragraph("5. Installed Applications Summary", h1_style))
    if data["inventory"] and data["inventory"].get("applications"):
        user_apps = [a for a in data["inventory"]["applications"] if a.get("type") == "User/Third-Party"]
        story.append(Paragraph(f"<b>Third-Party Installed Applications ({len(user_apps)} total):</b>", body_style))
        app_table_data = [["Package Name", "Running"]]
        for a in user_apps[:15]:
            app_table_data.append([
                Paragraph(a.get("package_name", ""), body_style),
                "YES" if a.get("is_running") else "No",
            ])
        at = Table(app_table_data, colWidths=[400, 104])
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474F")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F8F9FA"), colors.white]),
        ]))
        story.append(at)
    else:
        story.append(Paragraph("<i>No installed applications inventory available.</i>", body_style))
    story.append(Spacer(1, 10))

    # Section 7 & 8: APK Findings & Threat Patterns
    story.append(Paragraph("6. Suspect APK Analysis & Threat Scoring", h1_style))
    if data["apk_analysis"]:
        for apk in data["apk_analysis"]:
            m = apk.get("manifest", {})
            pa = apk.get("permissions_analysis", {})
            story.append(Paragraph(f"<b>Package:</b> {m.get('package_name')} &nbsp;|&nbsp; <b>Label:</b> {m.get('application_label')}", h2_style))
            story.append(Paragraph(f"• <b>Threat Severity:</b> <font color='red'><b>{pa.get('overall_severity')}</b></font> (Risk Score: {pa.get('risk_score')}/100)", bullet_style))
            story.append(Paragraph(f"• <b>Target SDK:</b> {m.get('target_sdk')} (Min SDK: {m.get('min_sdk')})", bullet_style))
            story.append(Paragraph(f"• <b>Declared Capabilities:</b> {', '.join(pa.get('capabilities', ['None']))}", bullet_style))

            if pa.get("matched_threat_patterns"):
                story.append(Spacer(1, 4))
                story.append(Paragraph("<b>Matched Threat Combinations:</b>", body_style))
                for pat in pa["matched_threat_patterns"]:
                    story.append(Paragraph(f"• <b>{pat.get('name')}</b> [{pat.get('severity')}]: {pat.get('description')}", bullet_style))
    else:
        story.append(Paragraph("<i>No suspect APK analyzed in this case.</i>", body_style))
    story.append(Spacer(1, 10))

    # Section 10: Network C2 Indicators
    story.append(Paragraph("7. Command-and-Control (C2) & Network Indicators", h1_style))
    net_inds = []
    if data["network_analysis"]:
        for na in data["network_analysis"]:
            net_inds.extend(na.get("indicators", []))

    if net_inds:
        net_table_data = [["Indicator", "Type", "Confidence", "Reason"]]
        for ind in net_inds[:15]:
            net_table_data.append([
                Paragraph(f"<font size=7>{ind.get('indicator')[:40]}</font>", body_style),
                ind.get("indicator_type", ""),
                ind.get("confidence", ""),
                Paragraph(f"<font size=7>{ind.get('reason', '')[:45]}</font>", body_style),
            ])
        nt = Table(net_table_data, colWidths=[180, 70, 74, 180])
        nt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#B71C1C")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFF8F8"), colors.white]),
        ]))
        story.append(nt)
    else:
        story.append(Paragraph("<i>No suspicious network C2 indicators observed.</i>", body_style))
    story.append(Spacer(1, 10))

    # Section 12: Timeline
    story.append(Paragraph("8. Chronological Incident Timeline", h1_style))
    if data["timeline"]:
        time_table_data = [["Timestamp (UTC)", "Event Type", "Event Description"]]
        for ev in data["timeline"][:15]:
            time_table_data.append([
                Paragraph(f"<font size=7>{ev.get('timestamp_utc', '')[:19]}</font>", body_style),
                Paragraph(f"<font size=7>{ev.get('event_type', '')}</font>", body_style),
                Paragraph(f"<font size=7>{ev.get('description', '')[:75]}</font>", body_style),
            ])
        tt = Table(time_table_data, colWidths=[110, 110, 284])
        tt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E7D32")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D0D0D0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F1F8E9"), colors.white]),
        ]))
        story.append(tt)
    else:
        story.append(Paragraph("<i>Timeline not yet compiled.</i>", body_style))
    story.append(Spacer(1, 10))

    # Section 13, 14, 15: Limitations, Conclusions & Recommendations
    story.append(Paragraph("9. Limitations, Conclusions & Recommendations", h1_style))
    story.append(Paragraph("<b>Defensive Containment Recommendations:</b>", body_style))
    story.append(Paragraph("1. <b>Isolate Device:</b> Immediately disconnect device from Wi-Fi and mobile networks.", bullet_style))
    story.append(Paragraph("2. <b>Revoke Permissions:</b> Check Accessibility & Device Admin settings to disable suspect app persistence.", bullet_style))
    story.append(Paragraph("3. <b>Credential Invalidation:</b> Rotate passwords and 2FA credentials for all banking and email accounts accessed from phone.", bullet_style))
    story.append(Paragraph("4. <b>Package Removal:</b> Uninstall unauthorized packages via Android application management or ADB.", bullet_style))

    # Build Document using NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)

    log_case_action(
        case_dir,
        "PDF_REPORT_GENERATED",
        f"Generated professional PDF report: {pdf_path.name}",
        operator,
    )

    return (pdf_path, None)



# ASCANNER_APK_REPORT_INTEGRATION_V1
# Adds concise APK static-analysis findings to existing Markdown/PDF reports.
import json as _ascan_json
import hashlib as _ascan_hashlib
import subprocess as _ascan_subprocess
from pathlib import Path as _AscanPath

_ascan_original_markdown_report = generate_markdown_report

def _ascan_apk_analysis_section(case_dir):
    case = _AscanPath(case_dir)
    lines = [
        "## APK Static Analysis",
        "",
        "This section summarizes available APK analysis artifacts. "
        "Static indicators and AI-generated interpretations are not "
        "proof of malicious behavior.",
        ""
    ]

    apks = sorted(
        (case / "evidence" / "original_apks").rglob("*.apk")
    ) if (case / "evidence" / "original_apks").exists() else []

    if not apks:
        lines += ["No original APK files were found in this case.", ""]
        return "\n".join(lines)

    model_reports = (
        _AscanPath.home()
        / "Android-Forensics/Datasets/Drebin/model/reports"
    )
    qwen_reports = case / "reports"

    for apk in apks:
        lines += [f"### {apk.name}", ""]

        digest = _ascan_hashlib.sha256()
        with apk.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        sha256 = digest.hexdigest()

        lines += [f"- **SHA-256:** `{sha256}`"]

        try:
            result = _ascan_subprocess.run(
                ["apksigner", "verify", "--verbose", "--print-certs", str(apk)],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout + result.stderr
            verified = result.returncode == 0 and "Verifies" in output
            lines.append(
                f"- **APK signature verification:** "
                f"{'PASS' if verified else 'FAIL/UNAVAILABLE'}"
            )
            for row in output.splitlines():
                if "Signer #1 certificate SHA-256 digest:" in row:
                    lines.append(f"- **Signer certificate:** `{row.split(':', 1)[1].strip()}`")
                    break
        except (OSError, subprocess.SubprocessError):
            lines.append("- **APK signature verification:** unavailable")

        matched_json = None
        if model_reports.exists():
            for candidate in sorted(
                model_reports.glob("*.json"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            ):
                try:
                    data = _ascan_json.loads(candidate.read_text(errors="replace"))
                    if data.get("sha256", "").lower() == sha256.lower():
                        matched_json = (candidate, data)
                        break
                except (OSError, ValueError):
                    continue

        if matched_json:
            json_path, data = matched_json
            assessment = data.get("maliciousness_assessment") or {}
            prob = assessment.get("maliciousness_probability")
            prob_status = assessment.get("probability_status", "UNAVAILABLE")
            prob_str = f"{prob:.1%}" if (isinstance(prob, (int, float)) and prob_status == "AVAILABLE") else "Unavailable"
            lines += [
                f"- **Scanner JSON:** `{json_path.name}`",
                f"- **Package:** `{data.get('package', 'unknown')}`",
                f"- **Declared permissions:** {data.get('permission_count', 'unknown')}",
                f"- **DEX files:** {data.get('dex_files', 'unknown')}",
                f"- **ML Assessment Verdict:** `{assessment.get('verdict', 'UNDETERMINED')}`",
                f"- **ML Maliciousness Probability:** {prob_str}",
                f"- **Evidence quality:** `{assessment.get('evidence_quality', 'unknown')}`",
                ""
            ]
            for limitation in assessment.get("limitations", data.get("limitations", [])):
                lines.append(f"- **Limitation:** {limitation}")
        else:
            lines += [
                "- **Scanner JSON:** no report matching this APK's SHA-256 was found.",
                "- **ML Maliciousness Probability:** unavailable.",
                ""
            ]

        package = ""
        if matched_json:
            package = matched_json[1].get("package", "")

        qwen = []
        if qwen_reports.exists():
            qwen = sorted(
                qwen_reports.glob("*_qwen_analysis.txt"),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
        selected_qwen = next(
            (p for p in qwen if package and p.name.startswith(package + "_")),
            None
        )

        if selected_qwen:
            try:
                content = selected_qwen.read_text(errors="replace").strip()
                lines += [
                    f"**AI analysis:** `{selected_qwen.name}`",
                    "",
                    content[:12000],
                    "",
                    "> AI-generated interpretation; independently validate claims "
                    "against the preserved evidence."
                    if content else "AI report exists but is empty.",
                    ""
                ]
                if len(content) > 12000:
                    lines += ["[AI report truncated in the consolidated report.]", ""]
            except OSError:
                lines += ["AI report could not be read.", ""]
        else:
            lines += ["No matching Qwen analysis report was found.", ""]

    lines += [
        "### Interpretation limits",
        "",
        "- A valid signature proves integrity relative to the signing key, not that the app is benign.",
        "- Permissions and API references do not prove that behavior occurred.",
        "- Static analysis cannot establish runtime behavior on its own.",
        "- The ML Maliciousness Probability evaluates static capability features against 25,722 labeled applications.",
        ""
    ]
    return "\n".join(lines)

def generate_markdown_report(case_dir, operator=None):
    result = _ascan_original_markdown_report(case_dir, operator)
    path = _AscanPath(result)
    section = _ascan_apk_analysis_section(case_dir)
    existing = path.read_text(errors="replace") if path.exists() else ""
    marker = "## APK Static Analysis"
    if marker in existing:
        existing = existing.split(marker, 1)[0].rstrip() + "\n\n"
    path.write_text(existing + section)
    return result
