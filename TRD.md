# TRD — AI-Powered Autonomous Cybersecurity

## Context
Reviewed only by an AI code evaluator (code quality, architecture, security, innovation). No runtime demo needed — every decision below optimizes for what's verifiable by reading the repo.

---

## Tech Stack

| Layer | Tool |
| :--- | :--- |
| **Rules engine** | Plain Python, dict/if-else logic |
| **ML anomaly detection** | `scikit-learn` — `IsolationForest` |
| **Explanation + mitigation** | Gemini API (`google-genai` / `google-generativeai`), JSON mode |
| **Schema validation** | `Pydantic` |
| **Secrets** | `python-dotenv` + `.env` (never hardcoded) |
| **Dashboard** | Streamlit (thin — not graded, keep minimal) |
| **Data** | Synthetic scripted event sequences (JSON) |

---

## Data Models (Pydantic)

```python
from datetime import datetime
from typing import Literal
from pydantic import BaseModel

class Event(BaseModel):
    user: str
    files_touched_per_min: int
    new_country: bool
    process_chain: str
    cpu_percent: float
    timestamp: datetime

class TriageResult(BaseModel):
    threat_type: str
    severity: Literal["low", "medium", "high", "critical"]
    plain_summary: str
    mitigation_command: str
```

> **Security Signal**: Validate every event on ingestion and every Gemini response before use.

---

## Module Breakdown

- **`rules.py`** — `rule_score(event: Event) -> int`  
  Point-based checks on known-bad patterns (rapid file access, unusual location, malicious process chain).

- **`anomaly.py`** — `anomaly_score(event: Event) -> int`  
  `IsolationForest`, trained on normal baseline, returns 0–100 scaled score.

- **`scorer.py`** — `process_event(event: Event) -> int`  
  Combines rule + anomaly score into per-user running total. Threshold constant documented as tunable, not derived.

- **`triage.py`** — `explain_incident(event: Event, score: int) -> TriageResult`  
  Gemini call, strict JSON, parsed into `TriageResult`. Retry once on schema failure, raise on second failure — don't silently swallow bad output.

- **`remediate.py`** — `log_mitigation(result: TriageResult) -> None`  
  Logs the mitigation command as simulated. No real system calls. Explicit comment + log line stating this.

- **`config.py`** — loads `.env`, exposes `GEMINI_API_KEY`, `THRESHOLD` as named constants.

---

## Security Requirements (Explicit, Gradable)
1. **No secrets in source** — `.env` + `.gitignore` includes it.
2. **Input validation** via Pydantic on every event before scoring.
3. **Output validation** via Pydantic on every Gemini response before use.
4. **No `eval` or dynamic command execution** — `mitigation_command` is a string for display/logging only.
5. **`SECURITY.md`** stating: simulated response only, no destructive actions taken.

---

## Non-Functional Requirements
- **Every function**: Type-hinted, docstrings, single responsibility.
- **File size**: No file exceeds ~100 lines — if it does, split it (grader-readability signal).
- **Documentation**: `README.md` documents architecture diagram + explicitly lists scope-cut items as "future work".
