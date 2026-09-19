# Workflow & Architecture

```mermaid
flowchart TD
    A["<b>New event</b><br>Validated via Pydantic"] --> B["<b>Rules engine</b><br>Known-bad patterns"]
    A --> C["<b>Isolation forest</b><br>Deviation from normal"]
    
    B --> D["<b>Combined score</b><br>Per user/host total"]
    C --> D
    
    D --> E{"<b>Threshold check</b><br>Score vs threshold"}
    
    E -- "Below" --> F["<b>Keep watching</b>"]
    E -- "Crossed" --> G["<b>Incident opened</b><br>Escalated for triage"]
    
    G --> H["<b>Gemini triage</b><br>Strict JSON output"]
    H --> I["<b>Mitigation logged</b><br>Simulated action"]

    style A fill:#3c3f41,stroke:#666,color:#fff
    style B fill:#1e4f8a,stroke:#3b82f6,color:#fff
    style C fill:#8a531e,stroke:#f59e0b,color:#fff
    style D fill:#7c2d12,stroke:#ea580c,color:#fff
    style E fill:#374151,stroke:#6b7280,color:#fff
    style F fill:#374151,stroke:#6b7280,color:#fff
    style G fill:#7f1d1d,stroke:#ef4444,color:#fff
    style H fill:#4338ca,stroke:#6366f1,color:#fff
    style I fill:#064e3b,stroke:#10b981,color:#fff
```

```
                    New Event
              (validated via Pydantic)
                        │
          ┌─────────────┴─────────────┐
          ▼                           ▼
    Rules Engine                Isolation Forest
  (known-bad patterns,        (deviation from
   point-based)                learned normal)
          │                           │
          └─────────────┬─────────────┘
                        ▼
                 Combined Score
          (added to user/host running total)
                        ▼
                 Threshold Check
          ┌─────────────┴─────────────┐
          ▼                           ▼
      Below threshold            Crossed threshold
      → keep watching            → Incident Opened
      → no alert                         │
                                         ▼
                                  Gemini Triage
                        (strict JSON → validated
                           into TriageResult)
                                         ▼
                                Mitigation Logged
                        (simulated action, explicitly
                              labeled as simulated)
```

> **Core Architectural Rule**: Rules + isolation forest scores combine first; Gemini only explains and proposes — never executes.

---

# Implementation Plan — Phased (5hr, code-quality-first)

| Phase | Task | Time | Grader signal it targets |
|---|---|---|---|
| **0** | `.env` setup, Gemini key test call, repo skeleton | 20 min | Security (no hardcoded secrets) |
| **1** | Pydantic models (`Event`, `TriageResult`) | 20 min | Code quality |
| **2** | Mock event generator — scripted normal + 3 attack scenarios | 25 min | — |
| **3** | `rules.py`, console-tested against mock data | 30 min | Architecture |
| **4** | `anomaly.py` (IsolationForest), console-tested | 40 min | Innovation |
| **5** | `scorer.py` — combined score + threshold | 25 min | Architecture |
| **6** | `triage.py` — Gemini call, validated JSON, retry-once logic | 50 min | Innovation, Security |
| **7** | `remediate.py` — simulated mitigation logging | 20 min | Innovation, Security |
| **8** | Thin Streamlit wiring (minimal — not graded) | 30 min | — |
| **9** | `SECURITY.md`, README (architecture + scope-cut future work), commit | 40 min | Security, Architecture |

---

## Contingency & Priority Order
**If time runs out:**
- Cut Phase 8 (dashboard) before anything else — it's not graded.
- **Never cut**: Pydantic validation, docstrings, or `SECURITY.md` — those are pure grader-facing wins for near-zero time cost.
