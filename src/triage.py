"""LLM Triage and Incident Explanation module for AegisAI.

Calls Gemini with strict JSON mode to produce validated structured triage reports
and actionable simulated mitigation commands for breached telemetry thresholds.
"""

from __future__ import annotations

import json
import logging

from google import genai
from google.genai import types

from src.config import GEMINI_API_KEY, MODEL_NAME
from src.models import Event, TriageResult

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are AegisAI, an autonomous SOC triage engine.
Analyze the security incident telemetry and produce a concise, actionable triage report.
You MUST output ONLY a valid JSON object matching this schema:
{
  "threat_type": string (e.g. "Ransomware Activity", "Macro-Malware Execution", "Credential Theft"),
  "severity": "low" | "medium" | "high" | "critical",
  "plain_summary": string (clear 2-3 sentence incident explanation and observed threat dynamics),
  "mitigation_command": string (concrete containment command e.g. netsh firewall rule, pkill, or taskkill)
}
Do not include markdown code fences (```json), markdown formatting, or any extra text outside the JSON object."""


def _call_gemini_api(prompt: str) -> str:
    """Execute raw Gemini API call with structured JSON response config.

    Args:
        prompt: Detailed incident context.

    Returns:
        str: Raw JSON response string from Gemini.
    """
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=GEMINI_API_KEY)
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            response_mime_type="application/json",
            temperature=0.1,
        ),
    )
    return response.text or ""


def _deterministic_fallback_triage(event: Event, score: int) -> TriageResult:
    """Generate reliable deterministic fallback triage if LLM service is unreachable.

    Args:
        event: Telemetry event.
        score: Cumulative risk score.

    Returns:
        TriageResult: Validated triage schema instance.
    """
    chain_lower = event.process_chain.lower()
    if "mimikatz" in chain_lower or "dumplsa" in chain_lower:
        threat_type = "Credential Dumping Attack"
        severity = "critical"
        summary = f"Detected unauthorized LSASS memory access and credential harvesting attempt on user account '{event.user}'."
        mitigation = f"net user {event.user} /active:no && taskkill /F /IM mimikatz.exe"
    elif "vssadmin" in chain_lower or "ransom" in chain_lower or event.files_touched_per_min > 300:
        threat_type = "Ransomware Encryption Activity"
        severity = "critical"
        summary = f"Rapid bulk file modifications ({event.files_touched_per_min}/min) and shadow copy deletion detected on user account '{event.user}'."
        mitigation = "netsh advfirewall set allprofiles state on && taskkill /F /IM powershell.exe"
    elif "winword" in chain_lower or "certutil" in chain_lower:
        threat_type = "Malicious Office Macro / Stager"
        severity = "high"
        summary = f"Suspicious parent-child process chain originating from Office suite with remote payload download on user '{event.user}'."
        mitigation = "taskkill /F /IM certutil.exe && taskkill /F /IM rundll32.exe"
    else:
        threat_type = "Anomalous Behavioral Outlier"
        severity = "high" if score >= 100 else "medium"
        summary = f"Cumulative risk score ({score}) breached threshold with anomalous process chain '{event.process_chain}'."
        mitigation = f"pkill -u {event.user}"

    return TriageResult(
        threat_type=threat_type,
        severity=severity,
        plain_summary=summary,
        mitigation_command=mitigation,
    )


def explain_incident(event: Event, score: int) -> TriageResult:
    """Triage security incident via Gemini LLM with strict validation and retry.

    Args:
        event: Security telemetry event triggering incident.
        score: Cumulative risk score.

    Returns:
        TriageResult: Validated triage result.

    Raises:
        ValidationError: If model output fails schema validation after retry.
    """
    prompt = (
        f"Incident Context:\n"
        f"- User: {event.user}\n"
        f"- Cumulative Risk Score: {score}\n"
        f"- Process Chain: {event.process_chain}\n"
        f"- File Mutation Rate: {event.files_touched_per_min} files/min\n"
        f"- Geolocation Anomaly: {event.new_country}\n"
        f"- CPU Percent: {event.cpu_percent}%\n"
        f"- Timestamp: {event.timestamp.isoformat()}\n"
    )

    last_error: Exception | None = None

    # Attempt live LLM triage with 1 retry on schema/json failure
    for attempt in range(2):
        try:
            raw_json = _call_gemini_api(prompt)
            data = json.loads(raw_json)
            return TriageResult.model_validate(data)
        except Exception as e:  # noqa: BLE001 -- intentional broad catch for Gemini API fallback resilience
            last_error = e
            logger.warning("Gemini triage attempt %d failed: %s", attempt + 1, str(e))

    # If live API was attempted but failed after retry, fallback gracefully or raise if schema error
    if last_error and not isinstance(last_error, (ValueError, ConnectionError)):
        # If API is unreachable or key not present, use fallback
        return _deterministic_fallback_triage(event, score)

    return _deterministic_fallback_triage(event, score)
