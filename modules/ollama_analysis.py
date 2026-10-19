"""
DroidSleuth Optional Ollama Integration Module
Provides local LLM-assisted explanation of forensic findings using Ollama.
Treats model output as unverified analysis, labels hypotheses, and maintains raw evidence integrity.
"""

import os
import json
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from modules.case_manager import log_case_action

OLLAMA_BASE_URL = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")


def check_ollama_status() -> Tuple[bool, List[str], str]:
    """Check if Ollama local server is running and list available models.
    
    Returns (is_available, model_names, status_message).
    """
    url = f"{OLLAMA_BASE_URL}/api/tags"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "DroidSleuth-Forensics/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                models = [m.get("name") for m in data.get("models", []) if m.get("name")]
                if models:
                    return (True, models, f"Ollama is running with {len(models)} model(s) available.")
                else:
                    return (True, [], "Ollama is running, but no local models are installed. (Run: ollama pull <model>)")
            return (False, [], f"Ollama returned HTTP status {resp.status}")
    except urllib.error.URLError:
        return (False, [], "Ollama daemon is not reachable at http://127.0.0.1:11434. (Start with: ollama serve)")
    except Exception as e:
        return (False, [], f"Ollama connection error: {e}")


def generate_ollama_explanation(
    prompt_context: str,
    model_name: str,
    system_prompt: Optional[str] = None,
) -> Dict[str, Any]:
    """Query a locally installed Ollama model to generate a structured forensic interpretation."""
    url = f"{OLLAMA_BASE_URL}/api/generate"

    default_system = (
        "You are an expert digital forensics investigator and Android security researcher assisting an authorized defensive investigation. "
        "Analyze the provided factual findings, suspicious indicators, and permissions. "
        "Strictly adhere to forensic standards: clearly separate observed facts from behavioral hypotheses. "
        "Explain the risks in clear, professional technical language. Highlight what actions the suspect app is capable of doing. "
        "Do not invent facts not present in the evidence."
    )

    payload = {
        "model": model_name,
        "prompt": prompt_context,
        "system": system_prompt or default_system,
        "stream": False,
        "options": {
            "temperature": 0.2,
        },
    }

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json", "User-Agent": "DroidSleuth-Forensics/1.0"},
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            if resp.status == 200:
                resp_data = json.loads(resp.read().decode("utf-8"))
                response_text = resp_data.get("response", "").strip()

                disclaimer = (
                    "> [!IMPORTANT]\n"
                    "> **FORENSIC NOTICE: AI-ASSISTED HYPOTHESIS GENERATION**\n"
                    "> The following explanation was generated locally by an artificial intelligence model "
                    f"(`{model_name}`). This output constitutes an unverified behavioral hypothesis and interpretation. "
                    "Raw evidence files and cryptographic manifests remain the definitive forensic source of truth.\n\n"
                )

                labeled_output = disclaimer + response_text

                return {
                    "status": "SUCCESS",
                    "model_used": model_name,
                    "explanation_markdown": labeled_output,
                    "raw_response": response_text,
                    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                }
            return {
                "status": "ERROR",
                "error": f"Ollama API returned HTTP {resp.status}",
            }
    except Exception as e:
        return {
            "status": "ERROR",
            "error": f"Failed to communicate with Ollama: {e}",
        }


def run_case_ollama_explanation(
    case_dir: Path,
    model_name: str,
    operator: Optional[str] = None,
) -> Dict[str, Any]:
    """Compile case findings and generate an Ollama explanation saved to the case analysis folder."""
    # Gather case summary facts
    case_json = case_dir / "case.json"
    case_meta = {}
    if case_json.exists():
        try:
            case_meta = json.loads(case_json.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Gather latest APK analysis
    apk_findings_summary = []
    apk_dir = case_dir / "analysis" / "apk_analysis"
    if apk_dir.exists():
        for f in apk_dir.glob("*.json"):
            try:
                adata = json.loads(f.read_text(encoding="utf-8"))
                manifest = adata.get("manifest", {})
                perm_report = adata.get("permissions_analysis", {})
                apk_findings_summary.append(
                    f"App Package: {manifest.get('package_name')}\n"
                    f"Threat Severity: {perm_report.get('overall_severity')} (Risk Score: {perm_report.get('risk_score')}/100)\n"
                    f"Dangerous Capabilities: {', '.join(perm_report.get('capabilities', []))}\n"
                    f"Threat Patterns Matched: {[p.get('name') for p in perm_report.get('matched_threat_patterns', [])]}\n"
                    f"Exported Components: {len(manifest.get('exported_components', []))}\n"
                    f"Observed Code Patterns: {list(adata.get('observed_patterns', {}).keys())}\n"
                )
            except Exception:
                pass

    # Gather Network indicators
    net_indicators = []
    net_dir = case_dir / "analysis" / "network_analysis"
    if net_dir.exists():
        for f in net_dir.glob("*.json"):
            try:
                ndata = json.loads(f.read_text(encoding="utf-8"))
                for ind in ndata.get("indicators", [])[:10]:
                    net_indicators.append(f"{ind.get('indicator_type')}: {ind.get('indicator')} ({ind.get('reason')})")
            except Exception:
                pass

    prompt_context = (
        f"Case ID: {case_meta.get('case_id')}\n"
        f"Case Description: {case_meta.get('case_description')}\n"
        f"Device: {case_meta.get('device_identifier')}\n\n"
        f"=== APK FINDINGS ===\n"
        f"{''.join(apk_findings_summary) if apk_findings_summary else 'No APK analysis recorded yet.'}\n\n"
        f"=== NETWORK & C2 INDICATORS ===\n"
        f"{chr(10).join(net_indicators) if net_indicators else 'No network indicators recorded yet.'}\n\n"
        "Provide a clear, structured forensic briefing explaining what this APK is capable of doing, "
        "how the evidence indicates suspicious persistence, overlay phishing, or credential exfiltration, "
        "and recommended defensive containment steps."
    )

    res = generate_ollama_explanation(prompt_context, model_name=model_name)
    if res.get("status") == "SUCCESS":
        # Save output to case analysis
        out_dir = case_dir / "analysis" / "ai_explanations"
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_file = out_dir / f"ollama_briefing_{ts}.md"
        out_file.write_text(res["explanation_markdown"], encoding="utf-8")

        log_case_action(
            case_dir,
            "AI_EXPLANATION_GENERATED",
            f"Generated local Ollama forensic explanation using model {model_name} -> {out_file.name}",
            operator,
        )
        res["saved_file"] = str(out_file)

    return res
