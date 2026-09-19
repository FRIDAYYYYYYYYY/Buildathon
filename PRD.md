# PRD — AI-Powered Autonomous Cybersecurity

## Evaluation Context
Submission is graded by an AI code evaluator only — no live demo audience. Every design choice below is optimized for what a code-reading grader can verify directly in the repo, scored on code quality, architecture, security, innovation.

## Problem
Endpoint threats (rapid file access, malicious process chains, impossible-travel logins) go undetected by static rules and get lost in noise. Static thresholds miss novel attack patterns; pure ML alone isn't explainable.

## Solution
Hybrid detection — rules engine + Isolation Forest score every event, combine into a per-user/host running total. Cross a threshold → Gemini writes a plain-English incident report and a concrete `mitigation_command`. Response is logged as simulated, never executed against a real system.

## Scoring-Axis Alignment

| Axis | How the repo proves it |
| :--- | :--- |
| **Code quality** | Type hints, docstrings, Pydantic models for event + response schemas, no hardcoded values buried in logic |
| **Architecture** | Cleanly separated modules — rules / anomaly / scoring / triage — never collapsed into one script |
| **Security** | No hardcoded secrets (`.env` + `python-dotenv`), input validation before scoring, JSON schema validation on all LLM output, explicit `SECURITY.md` stating simulated-only execution |
| **Innovation** | Hybrid rules+ML scoring (not single-method), closes the loop with a real mitigation output — not just a passive report |

## Scope (5hr build)
Correlation graphs, GNN detection, real response automation, model retraining — stated as future work in README, not built.

## Non-negotiables
- **No stubs** — every function has real logic a grader can trace end-to-end
- **No API keys in source**
- **`mitigation_command` must render as actual output**, not just be mentioned in docs
- **Every simulated action explicitly labeled simulated**, in code and docs
