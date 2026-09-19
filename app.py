"""AegisAI premium Streamlit dashboard.

The detection, scoring, triage, and remediation pipeline remains unchanged;
this module provides the visual presentation layer for the existing pipeline.
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

# ─────────────────────────────────────────────────────────────────────────────
# Premium visual system
# ─────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AegisAI | Autonomous Security",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');

    :root {
        --ink: #e9f1ff;
        --muted: #8fa5c4;
        --line: rgba(137, 169, 217, 0.17);
        --panel: rgba(15, 27, 50, 0.78);
        --panel-strong: #0d1a31;
        --cyan: #55d8ff;
        --green: #42e6a4;
        --amber: #ffc76b;
        --red: #ff6d8e;
    }

    html, body, [class*="css"] {
        font-family: 'Manrope', sans-serif;
    }
    .stApp {
        background:
            radial-gradient(circle at 82% 0%, rgba(22, 113, 179, .22), transparent 29rem),
            radial-gradient(circle at 0% 20%, rgba(33, 69, 146, .18), transparent 27rem),
            #071225;
        color: var(--ink);
    }
    [data-testid="stHeader"] { background: transparent; }
    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #0b1931 0%, #081326 100%);
        border-right: 1px solid var(--line);
    }
    [data-testid="stSidebar"] > div:first-child { padding-top: 2rem; }
    [data-testid="stSidebar"] label, [data-testid="stSidebar"] p { color: var(--muted); }
    [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 { color: var(--ink); }
    .block-container { max-width: 1500px; padding: 2.5rem 3.5rem 4rem; }
    h1, h2, h3 { letter-spacing: -0.035em; color: var(--ink); }
    h1 { font-weight: 800; font-size: clamp(2rem, 4vw, 3.2rem); margin-bottom: .2rem; }
    h2 { font-size: 1.3rem; margin-top: .2rem; }
    h3 { font-size: 1rem; }
    .eyebrow {
        color: var(--cyan); font-family: 'DM Mono', monospace; font-size: .72rem;
        letter-spacing: .16em; text-transform: uppercase; margin-bottom: .8rem;
    }
    .hero-subtitle { color: var(--muted); font-size: .98rem; margin: 0 0 1.6rem; }
    .hero-badge {
        display: inline-flex; align-items: center; gap: .5rem; padding: .4rem .75rem;
        border: 1px solid rgba(66,230,164,.28); border-radius: 999px;
        background: rgba(66,230,164,.08); color: var(--green); font-size: .72rem;
        font-family: 'DM Mono', monospace; letter-spacing: .05em;
    }
    .panel {
        background: var(--panel); border: 1px solid var(--line); border-radius: 18px;
        padding: 1.15rem 1.25rem; box-shadow: 0 14px 40px rgba(0,0,0,.15);
    }
    .panel-title { color: var(--muted); font-size: .72rem; text-transform: uppercase; letter-spacing: .13em; margin-bottom: .45rem; }
    .panel-value { color: var(--ink); font-size: 1.4rem; font-weight: 800; }
    .panel-caption { color: var(--muted); font-size: .76rem; margin-top: .3rem; }
    .status-pill { display: inline-flex; align-items: center; gap: .42rem; padding: .36rem .68rem; border-radius: 999px; font-size: .72rem; font-weight: 700; }
    .status-good { color: var(--green); background: rgba(66,230,164,.1); border: 1px solid rgba(66,230,164,.24); }
    .status-alert { color: var(--red); background: rgba(255,109,142,.1); border: 1px solid rgba(255,109,142,.28); }
    .status-neutral { color: var(--cyan); background: rgba(85,216,255,.1); border: 1px solid rgba(85,216,255,.22); }
    .section-label { display: flex; align-items: center; gap: .65rem; color: var(--ink); font-weight: 700; font-size: 1.02rem; margin: 1.55rem 0 .8rem; }
    .section-label span { color: var(--cyan); font-family: 'DM Mono', monospace; font-size: .7rem; }
    .threat-card { border: 1px solid rgba(255,109,142,.32); background: linear-gradient(135deg, rgba(115,24,58,.32), rgba(15,27,50,.9)); border-radius: 18px; padding: 1.2rem 1.3rem; }
    .contain-card { border: 1px solid rgba(85,216,255,.25); background: linear-gradient(135deg, rgba(14,64,91,.32), rgba(15,27,50,.9)); border-radius: 18px; padding: 1.2rem 1.3rem; }
    .notice { color: var(--green); font-family: 'DM Mono', monospace; font-size: .72rem; letter-spacing: .02em; }
    div[data-testid="stMetric"] { background: var(--panel); border: 1px solid var(--line); padding: 1rem 1.1rem; border-radius: 16px; }
    div[data-testid="stMetricLabel"] { color: var(--muted); }
    div[data-testid="stMetricValue"] { color: var(--ink); font-weight: 800; }
    div[data-testid="stDataFrame"] { border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
    .stCodeBlock { border: 1px solid rgba(85,216,255,.2); border-radius: 12px; }
    hr { border-color: var(--line); margin: 1.8rem 0; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ─────────────────────────────────────────────────────────────────────────────
# Header and controls
# ─────────────────────────────────────────────────────────────────────────────
st.markdown('<div class="eyebrow">AEGISAI / SECURITY OPERATIONS CENTER</div>', unsafe_allow_html=True)
header_left, header_right = st.columns([3.4, 1], vertical_alignment="center")
with header_left:
    st.title("Autonomous security, made visible.")
    st.markdown(
        '<p class="hero-subtitle">A hybrid detection engine for behavioral signals, incident triage, and safe response orchestration.</p>',
        unsafe_allow_html=True,
    )
with header_right:
    st.markdown('<div class="hero-badge">● SYSTEM ONLINE</div>', unsafe_allow_html=True)

with st.sidebar:
    st.markdown('<div class="eyebrow">CONTROL PLANE</div>', unsafe_allow_html=True)
    st.markdown("## Simulation controls")
    scenario = st.selectbox(
        "Telemetry stream",
        options=["Benign Baseline", "ransomware", "macro_malware", "impossible_travel"],
        format_func=lambda s: s.replace("_", " ").title(),
    )
    threshold_val = st.slider(
        "Incident risk threshold",
        min_value=30,
        max_value=150,
        value=THRESHOLD,
        help="Cumulative score required to open an incident.",
    )
    st.markdown("---")
    gemini_status = "Active" if validate_gemini_config() else "Fallback mode"
    status_class = "status-good" if validate_gemini_config() else "status-neutral"
    st.markdown(f'<span class="status-pill {status_class}">● LLM {gemini_status}</span>', unsafe_allow_html=True)
    st.caption(f"Model · `{MODEL_NAME}`")
    st.markdown("---")
    st.markdown(
        '<div class="notice">🔒 SIMULATION BOUNDARY<br><span style="color:#8fa5c4">Containment commands are logged for review and never dispatched to the host.</span></div>',
        unsafe_allow_html=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Existing pipeline state and scoring logic
# ─────────────────────────────────────────────────────────────────────────────
if "scorer" not in st.session_state or st.session_state.get("current_scenario") != scenario:
    st.session_state.scorer = RiskScorer(threshold=threshold_val)
    st.session_state.current_scenario = scenario
    st.session_state.audit_logs = []

scorer: RiskScorer = st.session_state.scorer
scorer.threshold = threshold_val

if scenario == "Benign Baseline":
    events = generate_baseline_events(count=6, seed=42)
    user_name = "alice.ops"
else:
    events = generate_attack_scenario(scenario, user=f"victim_{scenario}")
    user_name = f"victim_{scenario}"

st.markdown(
    f'<div class="section-label"><span>01</span> LIVE TELEMETRY / {scenario.replace("_", " ").upper()}</div>',
    unsafe_allow_html=True,
)

# Score events exactly as before; only the presentation has changed.
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

metric_cols = st.columns(4)
metric_cols[0].metric("Target entity", user_name)
metric_cols[1].metric("Risk threshold", f"{threshold_val} pts")
metric_cols[2].metric("Cumulative risk", f"{curr_score} pts", delta=f"{curr_score - threshold_val} vs threshold")
metric_cols[3].metric("Incident status", "TRIGGERED" if incident_triggered else "MONITORING")

with st.expander("View scoring signal legend", expanded=False):
    st.markdown(
        "**Rule score** identifies known signatures. **Anomaly score** measures deviation from baseline. "
        "**Burst bonus** correlates multiple suspicious events in a short window. The cumulative score opens an incident at the configured threshold."
    )

st.dataframe(
    pd.DataFrame(events_data),
    use_container_width=True,
    hide_index=True,
    height=280,
    column_config={
        "Timestamp": st.column_config.TextColumn("Time", width="small"),
        "Process Chain": st.column_config.TextColumn("Process chain", width="large"),
        "Cumulative Risk": st.column_config.NumberColumn("Cumulative risk", format="%d pts"),
    },
)


# ─────────────────────────────────────────────────────────────────────────────
# Existing triage and audit presentation
# ─────────────────────────────────────────────────────────────────────────────
if incident_triggered and triggered_event:
    st.markdown('<div class="section-label"><span>02</span> INCIDENT RESPONSE / AUTONOMOUS TRIAGE</div>', unsafe_allow_html=True)

    with st.spinner("Generating structured incident triage..."):
        triage_result = explain_incident(triggered_event, breached_score)
        audit_log = log_mitigation(triage_result, user=user_name)
        if audit_log not in st.session_state.audit_logs:
            st.session_state.audit_logs.append(audit_log)

    t_col1, t_col2 = st.columns([1, 1], gap="large")
    with t_col1:
        st.markdown('<div class="threat-card">', unsafe_allow_html=True)
        st.markdown('<div class="panel-title">Threat assessment</div>', unsafe_allow_html=True)
        st.markdown(f"### {triage_result.threat_type}")
        severity = triage_result.severity.upper()
        st.markdown(f'<span class="status-pill status-alert">● {severity} SEVERITY</span>', unsafe_allow_html=True)
        st.markdown(f"\n**Analyst summary**\n\n{triage_result.plain_summary}")
        st.markdown('</div>', unsafe_allow_html=True)

    with t_col2:
        st.markdown('<div class="contain-card">', unsafe_allow_html=True)
        st.markdown('<div class="panel-title">Recommended containment</div>', unsafe_allow_html=True)
        st.markdown("### Simulated action")
        st.code(triage_result.mitigation_command, language="bash")
        st.markdown('<div class="notice">✓ AUDIT LOGGED · SIMULATION ONLY · EXECUTION BLOCKED</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

if st.session_state.audit_logs:
    st.markdown('<div class="section-label"><span>03</span> AUDIT TRAIL / MITIGATION LEDGER</div>', unsafe_allow_html=True)
    audit_df = pd.DataFrame(st.session_state.audit_logs)
    st.dataframe(
        audit_df[["timestamp", "status", "target_user", "threat_type", "severity", "mitigation_command", "notice"]],
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn("Recorded at", width="medium"),
            "status": st.column_config.TextColumn("Status", width="small"),
            "mitigation_command": st.column_config.TextColumn("Proposed command", width="large"),
            "notice": st.column_config.TextColumn("Safety notice", width="large"),
        },
    )
else:
    st.markdown('<div class="section-label"><span>03</span> AUDIT TRAIL / MITIGATION LEDGER</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="panel"><div class="panel-title">No containment actions recorded</div><div class="panel-caption">Run an attack scenario to generate a simulation-only audit entry.</div></div>',
        unsafe_allow_html=True,
    )

st.markdown(
    '<div style="color:#58708f;font-family:DM Mono,monospace;font-size:.68rem;text-align:center;margin-top:2.5rem;letter-spacing:.08em;">AEGISAI // DEFENSE-IN-DEPTH // HUMAN-REVIEWABLE // SAFE BY DEFAULT</div>',
    unsafe_allow_html=True,
)
