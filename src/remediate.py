"""Remediation and mitigation audit logging for AegisAI.

Logs proposed mitigation actions under strict simulation boundaries.
Ensures ZERO live system command execution.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict
from src.models import TriageResult

logger = logging.getLogger(__name__)


def log_mitigation(result: TriageResult, user: str = "unknown") -> Dict[str, Any]:
    """Audit-log a recommended mitigation action in SIMULATION mode only.

    SECURITY GUARANTEE:
    This function NEVER executes commands against the live operating system.
    All mitigation outputs are strictly formatted for analyst review and simulated containment logs.

    Args:
        result: Validated TriageResult instance from the triage engine.
        user: Affected username/principal targeted for containment.

    Returns:
        Dict[str, Any]: Structured audit log record of the simulated mitigation.
    """
    timestamp = datetime.now(timezone.utc).isoformat()

    audit_entry = {
        "status": "SIMULATED",
        "action": "CONTAINMENT_LOGGED",
        "target_user": user,
        "threat_type": result.threat_type,
        "severity": result.severity,
        "mitigation_command": result.mitigation_command,
        "executed_live": False,
        "timestamp": timestamp,
        "notice": "SIMULATION ONLY — Command was not dispatched to OS shell.",
    }

    # Explicit console & logger notice emphasizing simulation boundary
    log_message = (
        f"[SIMULATED MITIGATION] User: '{user}' | Threat: '{result.threat_type}' ({result.severity}) | "
        f"Proposed Command: `{result.mitigation_command}` (EXECUTION: BLOCKED / SIMULATED)"
    )
    logger.info(log_message)
    print(log_message)

    return audit_entry
