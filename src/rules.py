"""Rules engine for AegisAI.

Evaluates security telemetry events against deterministic point-based heuristic rules
for known-bad activity patterns (rapid file operations, suspicious parent-child
process chains, credential dumping, and geo-anomalies).
"""

from __future__ import annotations

import re

from src.models import Event

# Heuristic rule patterns and assigned risk points
SUSPICIOUS_PATTERNS: list[tuple[str, int, str]] = [
    (r"mimikatz|sekurlsa|DumpLsa|procdump", 50, "Credential dumping signature detected"),
    (r"vssadmin.*delete\s+shadows|ransom|locker", 45, "Shadow copy deletion / ransomware signature"),
    (r"(winword|excel|powerpnt|outlook)\.exe.*(->|>)\s*(cmd|powershell|cscript|wscript|mshta)\.exe", 35, "Office app spawned command interpreter"),
    (r"powershell.*(-enc|-executionpolicy\s+bypass|downloadstring|iex)", 35, "Obfuscated / policy-bypass PowerShell invocation"),
    (r"certutil.*-urlcache|bitsadmin.*\/transfer", 30, "Living-off-the-land download utility invoked"),
    (r"rundll32\.exe\s+.*\.bin|regsvr32\.exe\s+\/s", 30, "Unsigned/raw binary execution via system utility"),
]


def rule_score(event: Event) -> int:
    """Evaluate deterministic security rules against an incoming telemetry event.

    Args:
        event: Validated telemetry Event instance.

    Returns:
        int: Cumulative point-based risk score from triggered rules.
    """
    score: int = 0
    chain_lower = event.process_chain.lower()

    # 1. Process chain signature checks
    for pattern, points, _ in SUSPICIOUS_PATTERNS:
        if re.search(pattern, chain_lower, re.IGNORECASE):
            score += points

    # 2. File activity rate thresholds
    if event.files_touched_per_min >= 300:
        score += 40
    elif event.files_touched_per_min >= 100:
        score += 20
    elif event.files_touched_per_min >= 50:
        score += 10

    # 3. Geolocation anomaly
    if event.new_country:
        score += 35

    # 4. CPU consumption spikes
    if event.cpu_percent >= 85.0:
        score += 15
    elif event.cpu_percent >= 60.0:
        score += 5

    return score
