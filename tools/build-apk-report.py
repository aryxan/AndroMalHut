#!/usr/bin/env python3
import sys, json, hashlib, subprocess
from pathlib import Path
from datetime import datetime, timezone

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
except ImportError:
    raise SystemExit("Missing ReportLab. Install with: sudo apt install python3-reportlab")

if len(sys.argv) != 2:
    raise SystemExit("Usage: build-apk-report.py APK_PATH")

apk = Path(sys.argv[1]).expanduser().resolve()
if not apk.is_file():
    raise SystemExit(f"APK not found: {apk}")

h = hashlib.sha256(apk.read_bytes()).hexdigest()
json_dir = Path.home() / "Android-Forensics/Datasets/Drebin/model/reports"
matched = None
for p in sorted(json_dir.glob("*.json"), key=lambda x:x.stat().st_mtime, reverse=True):
    try:
        d = json.loads(p.read_text(errors="replace"))
        if str(d.get("sha256", "")).lower() == h.lower():
            matched = (p, d)
            break
    except (OSError, ValueError):
        continue

if matched is None:
    raise SystemExit("No scanner JSON matches this APK SHA-256. Run the scanner first.")

json_path, d = matched
assessment = d.get("maliciousness_assessment") or {}
package = d.get("package") or apk.stem
case = None
try:
    scanner_root = Path(__file__).resolve().parent.parent
    if str(scanner_root) not in sys.path:
        sys.path.insert(0, str(scanner_root))
    from modules.case_manager import get_active_case
    case = get_active_case()
except Exception:
    pass

if not case or not case.exists():
    if "evidence" in apk.parts:
        idx = apk.parts.index("evidence")
        case = Path(*apk.parts[:idx])
    elif (apk.parent.parent.parent / "case.json").exists():
        case = apk.parent.parent.parent
    else:
        case = apk.parent

reports = case / "reports"
reports.mkdir(parents=True, exist_ok=True)
out = reports / f"{package}_{datetime.now():%Y%m%d_%H%M%S}_scan_report.pdf"

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="Brand", parent=styles["Title"],
    textColor=colors.HexColor("#12304A"), fontSize=23, leading=28))
styles.add(ParagraphStyle(name="SectionBlue", parent=styles["Heading2"],
    textColor=colors.HexColor("#146C94"), spaceBefore=12))
styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"],
    fontSize=8, leading=10, wordWrap="CJK"))

def safe(x):
    s = str(x)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")

story = [
    Paragraph("ANDROMALHUT", styles["Brand"]),
    Paragraph("Android APK Static Analysis Report", styles["Heading2"]),
    Spacer(1, 5*mm),
    Paragraph("Verdict: " + safe(assessment.get("verdict", "UNDETERMINED")),
              styles["Heading2"]),
    Paragraph("Indicator-based assessment only; this is not a confirmed malware verdict.",
              styles["BodyText"]),
    Paragraph("Application Overview", styles["SectionBlue"])
]
rows = [["Field", "Value"]]
for key, value in [
    ("App name", d.get("app_name", "Unknown")),
    ("Package", package),
    ("Version", d.get("version_name", "Unknown")),
    ("Version code", d.get("version_code", "Unknown")),
    ("APK SHA-256", h),
    ("Analysis mode", d.get("analysis_mode", "Static")),
    ("Permissions", d.get("permission_count", "Unknown")),
    ("DEX files", d.get("dex_files", "Unknown")),
    ("Evidence quality", assessment.get("evidence_quality", "Unknown")),
    ("ML Maliciousness Prob", (f"{assessment['maliciousness_probability']:.1%}" if isinstance(assessment.get("maliciousness_probability"), (int, float)) and assessment.get("probability_status") == "AVAILABLE" else "Unavailable")),
    ("Classification", d.get("classification") or assessment.get("verdict", "Unknown")),
    ("Scanner JSON", json_path.name),
]:
    rows.append([Paragraph(safe(key), styles["Small"]),
                 Paragraph(safe(value), styles["Small"])])
t = Table(rows, colWidths=[43*mm, 135*mm], repeatRows=1)
t.setStyle(TableStyle([
    ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#12304A")),
    ("TEXTCOLOR", (0,0), (-1,0), colors.white),
    ("BACKGROUND", (0,1), (0,-1), colors.HexColor("#EAF1F7")),
    ("GRID", (0,0), (-1,-1), .4, colors.HexColor("#CBD5E1")),
    ("VALIGN", (0,0), (-1,-1), "TOP"),
    ("LEFTPADDING", (0,0), (-1,-1), 6),
    ("RIGHTPADDING", (0,0), (-1,-1), 6),
    ("TOPPADDING", (0,0), (-1,-1), 5),
    ("BOTTOMPADDING", (0,0), (-1,-1), 5),
]))
story += [t, Paragraph("Feature Indicators", styles["SectionBlue"])]
features = d.get("feature_presence_preview") or {}
if features:
    frows = [["Indicator", "Observed"]]
    frows += [[Paragraph(safe(k), styles["Small"]), Paragraph(safe(v), styles["Small"])]
              for k, v in list(features.items())[:100]]
    ft = Table(frows, colWidths=[145*mm, 33*mm], repeatRows=1)
    ft.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#146C94")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#CBD5E1")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#F4F7FA")]),
    ]))
    story.append(ft)
    if len(features) > 100:
        story.append(Paragraph(f"First 100 of {len(features)} indicators shown.", styles["Small"]))
else:
    story.append(Paragraph("No feature preview supplied.", styles["BodyText"]))

story.append(Paragraph("Declared Permissions", styles["SectionBlue"]))
story.append(Paragraph(safe(", ".join(d.get("permissions") or ["Not supplied"])), styles["Small"]))
story.append(Paragraph("Limitations", styles["SectionBlue"]))
limitations = list(assessment.get("limitations") or d.get("limitations") or [])
limitations += [
    "Static indicators do not prove runtime behavior or malicious intent.",
    "A valid APK signature does not prove the app is benign.",
    "Model assesses static capability features trained across 25,722 applications."
]
for item in dict.fromkeys(limitations):
    story.append(Paragraph("• " + safe(item), styles["BodyText"]))
    story.append(Spacer(1, 2*mm))
story += [
    Spacer(1, 4*mm),
    Paragraph("Evidence provenance", styles["SectionBlue"]),
    Paragraph("APK: " + safe(apk), styles["Small"]),
    Paragraph("Generated: " + datetime.now(timezone.utc).isoformat(), styles["Small"]),
]
def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748B"))
    canvas.drawString(16*mm, 9*mm, "ANDROMALHUT | Static analysis")
    canvas.drawRightString(194*mm, 9*mm, f"Page {doc.page}")
    canvas.restoreState()

doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=16*mm,
    rightMargin=16*mm, topMargin=16*mm, bottomMargin=17*mm,
    title=f"AndroMalHut Report - {package}", author="AndroMalHut")
doc.build(story, onFirstPage=footer, onLaterPages=footer)
print("PDF_REPORT=" + str(out))
print("APK_SHA256=" + h)
print("VERDICT=" + str(assessment.get("verdict", "UNDETERMINED")))
