# Implementation Plan — By Phase

### Phase 0 — Foundation (20 min)
- Repo skeleton: `src/{rules,anomaly,scorer,triage,remediate,config}.py`
- `.env` file + `python-dotenv`, Gemini key loaded via `config.py`
- Test call to Gemini API — confirm key works before building anything else
- **Grader signal:** Security (no hardcoded secrets)

### Phase 1 — Data Contracts (20 min)
- Pydantic models: `Event` (`user`, `files_touched_per_min`, `new_country`, `process_chain`, `cpu_percent`, `timestamp`)
- Pydantic model: `TriageResult` (`threat_type`, `severity`, `plain_summary`, `mitigation_command`)
- **Grader signal:** Code quality

### Phase 2 — Mock Data (25 min)
- Scripted event generator: normal baseline + 3 attack scenarios (rapid file access, macro-malware process chain, impossible-travel login)
- No grading signal directly, but blocks everything downstream

### Phase 3 — Rules Engine (30 min)
- `rules.py` → `rule_score(event: Event) -> int`
- Point-based checks against known-bad patterns
- Console-tested against mock data before moving on
- **Grader signal:** Architecture

### Phase 4 — Anomaly Detection (40 min)
- `anomaly.py` → `IsolationForest` trained on normal baseline
- `anomaly_score(event: Event) -> int`, console-tested
- **Grader signal:** Innovation

### Phase 5 — Combined Scoring (25 min)
- `scorer.py` → per-user running total, threshold gate (constant, documented as tunable)
- **Grader signal:** Architecture

### Phase 6 — LLM Triage (50 min)
- `triage.py` → Gemini call, strict JSON output
- Parse into `TriageResult`, validate, retry once on schema failure
- **Grader signal:** Innovation, Security

### Phase 7 — Mitigation Output (20 min)
- `remediate.py` → logs `mitigation_command` as simulated action
- Explicit label: simulated, not executed
- **Grader signal:** Innovation, Security

### Phase 8 — UI (30 min)
- Thin Streamlit wiring — not graded, keep minimal
- First thing to cut if time runs short

### Phase 9 — Docs & Ship (40 min)
- `SECURITY.md`: input validation, no secrets, simulated-only execution
- README: architecture diagram, scope-cut items as "future work"
- Final commit
- **Grader signal:** Security, Architecture

---

## Strategy & Cut Order
**Cut order if behind schedule:** Phase 8 first, then trim Phase 2's attack scenarios to 2 instead of 3.  
**Never cut:** Phase 1 (Data Contracts), Phase 6 (Validation), or Phase 9 (`SECURITY.md`) — highest ROI and cheapest points on the board.
