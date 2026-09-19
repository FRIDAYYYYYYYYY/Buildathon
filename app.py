"""AegisAI - Autonomous Cybersecurity Detection & Triage Dashboard.

Thin interactive Streamlit interface for visualizing the hybrid detection pipeline,
risk score accumulation, LLM incident triage, and simulated mitigation logging.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from src.config import MODEL_NAME, THRESHOLD, validate_gemini_config
from src.data_generator import (
    generate_attack_scenario,
    generate_baseline_events,
)
from src.remediate import log_mitigation
from src.scorer import RiskScorer
from src.triage import explain_incident

# Page configuration
st.set_page_config(
    page_title="AegisAI — Autonomous Cyber Defense",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ AegisAI — Autonomous Security Engine")
st.caption(
    "Hybrid Detection (Heuristic Rules + Isolation Forest) • LLM Incident Triage • Simulated Containment"
)

# Sidebar settings & scenario control
st.sidebar.header("🕹️ Simulation Control")
scenario = st.sidebar.selectbox(
    "Select Telemetry Stream Scenario:",
    options=["Benign Baseline", "ransomware", "macro_malware", "impossible_travel"],
    format_func=lambda s: s.replace("_", " ").title(),
)

threshold_val = st.sidebar.slider("Incident Risk Threshold", min_value=30, max_value=150, value=THRESHOLD)
gemini_status = "🟢 Active" if validate_gemini_config() else "🟠 Fallback Mode (No API Key)"
st.sidebar.markdown(f"**LLM Backend:** {gemini_status}")
st.sidebar.markdown(f"**Model:** `{MODEL_NAME}`")
st.sidebar.markdown("---")
st.sidebar.info(
    "🔒 **Security Guarantee:** All mitigation containment actions are simulated. Zero live commands are dispatched to host shells."
)

# Initialize state
if "scorer" not in st.session_state or st.session_state.get("current_scenario") != scenario:
    st.session_state.scorer = RiskScorer(threshold=threshold_val)
    st.session_state.current_scenario = scenario
    st.session_state.audit_logs = []

scorer: RiskScorer = st.session_state.scorer
scorer.threshold = threshold_val

# Generate events based on scenario
if scenario == "Benign Baseline":
    events = generate_baseline_events(count=6, seed=42)
    user_name = "alice.ops"
else:
    events = generate_attack_scenario(scenario, user=f"victim_{scenario}")
    user_name = f"victim_{scenario}"

st.subheader(f"📊 Active Event Stream: `{scenario.replace('_', ' ').title()}`")

# Metrics display columns
col1, col2, col3, col4 = st.columns(4)
col1.metric("Target Entity", user_name)
col2.metric("Configured Threshold", f"{threshold_val} pts")

events_data = []
incident_triggered = False
triggered_event = None
breached_score = 0

for e in events:
    bd = scorer.score_event(e)
    events_data.append({
        "Timestamp": e.timestamp.strftime("%H:%M:%S"),
        "Process Chain": e.process_chain,
        "Files/min": e.files_touched_per_min,
        "CPU %": f"{e.cpu_percent}%",
        "Geo Anomaly": "⚠️ Yes" if e.new_country else "No",
        "Rule Score": bd.rule_score,
        "Anomaly Score": bd.anomaly_score,
        "Burst Bonus": f"⚡ +{bd.burst_bonus}" if bd.burst_bonus > 0 else "-",
        "Cumulative Risk": bd.cumulative_score,
        "Breached": "🚨 BREACH" if bd.is_breached else "Normal",
    })
    if bd.is_breached and not incident_triggered:
        incident_triggered = True
        triggered_event = e
        breached_score = bd.cumulative_score

curr_score = scorer.get_user_score(user_name)
col3.metric("Cumulative Risk Score", f"{curr_score} pts", delta=f"{curr_score - threshold_val} pts vs threshold")
col4.metric("Incident Status", "🚨 TRIGGERED" if incident_triggered else "🟢 MONITORING")

# Event Table
df = pd.DataFrame(events_data)
st.dataframe(df, use_container_width=True, hide_index=True)

# Incident Triage & Mitigation Card
if incident_triggered and triggered_event:
    st.markdown("---")
    st.subheader("🚨 Autonomous Incident Triage & Containment")
    
    with st.spinner("Triaging incident via Gemini LLM..."):
        triage_result = explain_incident(triggered_event, breached_score)
        audit_log = log_mitigation(triage_result, user=user_name)
        if audit_log not in st.session_state.audit_logs:
            st.session_state.audit_logs.append(audit_log)

    t_col1, t_col2 = st.columns([1, 1])

    with t_col1:
        st.markdown(f"### Threat: **{triage_result.threat_type}**")
        sev_color = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "blue"
        }.get(triage_result.severity, "gray")
        st.markdown(f"**Severity:** :{sev_color}[{triage_result.severity.upper()}]")
        st.write(f"**Summary:** {triage_result.plain_summary}")

    with t_col2:
        st.markdown("### 🛡️ Recommended Containment (Simulated)")
        st.code(triage_result.mitigation_command, language="bash")
        st.success("✅ Logged to audit trail (SIMULATED ONLY — Execution blocked)")

# Audit Log Section
if st.session_state.audit_logs:
    st.markdown("---")
    st.subheader("📋 Mitigation Audit Ledger")
    audit_df = pd.DataFrame(st.session_state.audit_logs)
    st.dataframe(
        audit_df[["timestamp", "status", "target_user", "threat_type", "severity", "mitigation_command", "notice"]],
        use_container_width=True,
        hide_index=True,
    )
