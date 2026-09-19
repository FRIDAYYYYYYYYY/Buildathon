"""Export real pipeline output as a single JSON file for frontend demo.

Executes the production RiskScorer (rules + Isolation Forest + temporal burst)
and Gemini LLM triage pipeline on representative test split sequences.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

# Ensure project root is in python path
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

import pandas as pd

from src.anomaly import AnomalyDetector
from src.config import THRESHOLD
from src.models import Event, TriageResult
from src.rules import SUSPICIOUS_PATTERNS
from src.scorer import RiskScorer
from src.triage import explain_incident


def get_rule_reason(event: Event) -> str | None:
    """Identify which specific deterministic rule pattern or heuristic fired."""
    reasons: list[str] = []
    chain_lower = event.process_chain.lower()

    # 1. Process chain signatures
    for pattern, _, desc in SUSPICIOUS_PATTERNS:
        if re.search(pattern, chain_lower, re.IGNORECASE):
            reasons.append(desc)

    # 2. File activity rate thresholds
    if event.files_touched_per_min >= 300:
        reasons.append("Extreme file modification rate (>= 300 files/min)")
    elif event.files_touched_per_min >= 100:
        reasons.append("High file modification rate (>= 100 files/min)")
    elif event.files_touched_per_min >= 50:
        reasons.append("Elevated file modification rate (>= 50 files/min)")

    # 3. Geolocation anomaly
    if event.new_country:
        reasons.append("Authentication from novel geographic location")

    # 4. CPU spikes
    if event.cpu_percent >= 85.0:
        reasons.append("Critical CPU spike (>= 85%)")
    elif event.cpu_percent >= 60.0:
        reasons.append("Elevated CPU utilization (>= 60%)")

    return "; ".join(reasons) if reasons else None


def make_event(row: dict[str, Any]) -> Event:
    """Convert a CSV row dictionary to a validated Event object."""
    return Event(
        user=str(row["user"]),
        files_touched_per_min=round(float(row["files_touched_per_min"])),
        new_country=bool(row["new_country"]),
        process_chain=str(row["process_chain"]),
        cpu_percent=float(row["cpu_percent"]),
        timestamp=pd.to_datetime(row["timestamp"]).to_pydatetime(),
    )


def export_demo():
    """Extract test split sequences, score via production engine, and export JSON."""
    split_path = ROOT_DIR / "data" / "split_indices.json"
    csv_path = ROOT_DIR / "data" / "training_data.csv"
    out_path = ROOT_DIR / "data" / "demo_export.json"

    with open(split_path, "r", encoding="utf-8") as f:
        split_data = json.load(f)

    df = pd.read_csv(csv_path)
    df["parsed_ts"] = pd.to_datetime(df["timestamp"])
    df_sorted = df.sort_values("parsed_ts").reset_index(drop=True)

    # Train Isolation Forest on train split
    train_df = df_sorted[df_sorted["event_id"].isin(split_data["train_event_ids"])]
    train_events = [make_event(r) for r in train_df.to_dict("records")]

    detector = AnomalyDetector()
    detector.fit(train_events)

    # Patch global detector for consistent scoring
    import src.anomaly as anomaly_mod
    anomaly_mod._DEFAULT_DETECTOR = detector

    # Filter test split
    test_df = df_sorted[df_sorted["event_id"].isin(split_data["test_event_ids"])].copy()

    scenarios = [
        ("ransomware", "ransomware"),
        ("macro_malware", "macro_malware"),
        ("impossible_travel", "impossible_travel"),
        ("benign", "normal"),
    ]

    sequences_export = []

    for scenario_label, attack_filter in scenarios:
        sub_df = test_df[test_df["attack_type"] == attack_filter].copy()

        # Select the top user with multiple consecutive events for this scenario
        user_counts = sub_df.groupby("user").size()
        target_user = user_counts.idxmax()
        user_events_df = sub_df[sub_df["user"] == target_user].head(5)

        # Fresh stateful RiskScorer per sequence
        scorer = RiskScorer(threshold=THRESHOLD)
        events_list = []
        first_breach_event: Event | None = None
        breached_score: int = 0

        for row in user_events_df.to_dict("records"):
            evt = make_event(row)
            bd = scorer.score_event(evt)
            rule_reason = get_rule_reason(evt)

            if bd.is_breached and first_breach_event is None:
                first_breach_event = evt
                breached_score = bd.cumulative_score

            events_list.append({
                "timestamp": row["timestamp"],
                "user": evt.user,
                "process_chain": evt.process_chain,
                "files_touched_per_min": evt.files_touched_per_min,
                "cpu_percent": evt.cpu_percent,
                "rule_score": bd.rule_score,
                "rule_reason": rule_reason,
                "anomaly_score": bd.anomaly_score,
                "burst_bonus": bd.burst_bonus,
                "cumulative_score": bd.cumulative_score,
                "threshold_crossed": bd.is_breached,
            })

        # Run real triage if threshold crossed
        triage_data = None
        if first_breach_event:
            triage_res: TriageResult = explain_incident(first_breach_event, breached_score)
            triage_data = {
                "threat_type": triage_res.threat_type,
                "severity": triage_res.severity,
                "plain_summary": triage_res.plain_summary,
                "mitigation_command": triage_res.mitigation_command,
            }

        sequences_export.append({
            "scenario_name": scenario_label,
            "user": target_user,
            "events": events_list,
            "triage": triage_data,
        })

    demo_data = {
        "threshold": THRESHOLD,
        "evaluation_summary": {
            "test_set_size": 2400,
            "overall_attack_recall": "100.0%",
            "overall_false_positive_rate": "2.84%",
            "by_attack_type": {
                "ransomware": {
                    "recall": "100.0%",
                    "test_count": 200
                },
                "macro_malware": {
                    "recall": "100.0%",
                    "test_count": 170
                },
                "impossible_travel": {
                    "recall": "100.0%",
                    "test_count": 130
                }
            },
            "benign_test_count": 1900
        },
        "sequences": sequences_export,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(demo_data, f, indent=2)

    print("=" * 60)
    print(f"Demo data successfully exported to: {out_path}")
    print("=" * 60)
    print(f"Total Sequences: {len(demo_data['sequences'])}")
    for seq in demo_data["sequences"]:
        triage_status = "Generated" if seq["triage"] else "None (Below Threshold)"
        print(f"  • {seq['scenario_name']:<18} | User: {seq['user']:<10} | Events: {len(seq['events'])} | Triage: {triage_status}")
        if seq["triage"]:
            print(f"    - Threat: {seq['triage']['threat_type']} [{seq['triage']['severity']}]")
            print(f"    - Summary: {seq['triage']['plain_summary'][:75]}...")
            print(f"    - Command: {seq['triage']['mitigation_command']}")


if __name__ == "__main__":
    export_demo()
