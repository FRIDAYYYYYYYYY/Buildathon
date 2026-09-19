"""
Step 1 - Tabular source dataset for the hybrid detector (Isolation Forest + toy GNN).

Generates data/training_data.csv. This CSV is the ONLY source of truth: the graph
in Step 2 is derived from it, never generated separately.

Run:  python generate_training_data.py
Deterministic: every random draw comes from one numpy Generator seeded with SEED.
"""
import hashlib
import sys
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, ValidationError

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------
SEED = 42
N_ROWS = 10_000
N_ANOMALIES = 500                      # exactly 5%
ATTACK_SPLIT = {                       # must sum to N_ANOMALIES
    "ransomware": 200,
    "macro_malware": 170,
    "impossible_travel": 130,
}
N_USERS = 60
N_WORKSTATIONS = 30
N_SERVERS = 10                         # 40 hosts total
START = datetime(2026, 8, 1)
DAYS = 30
OUT_PATH = Path(__file__).parent / "data" / "training_data.csv"

assert sum(ATTACK_SPLIT.values()) == N_ANOMALIES


# ----------------------------------------------------------------------------
# Event model (MIRROR of anomaly.py's Event, reconstructed from the field list.
# Swap for `from anomaly import Event` once you confirm it matches.)
# ----------------------------------------------------------------------------
class Event(BaseModel):
    user: str
    files_touched_per_min: float = Field(ge=0)
    new_country: bool
    process_chain: list[str] = Field(min_length=1)
    cpu_percent: float = Field(ge=0, le=100)
    timestamp: datetime


# ----------------------------------------------------------------------------
# Derived features (ASSUMED definitions - reconcile with anomaly.py)
# Kept in one function so they are trivial to swap.
# ----------------------------------------------------------------------------
def derive_features(chain: list[str], ts: datetime) -> dict:
    return {
        "process_chain_length": len(chain),        # number of processes
        "process_chain_depth": len(chain) - 1,     # parent->child hops
        "hour_of_day": ts.hour,
        "is_off_hours": int(ts.hour < 7 or ts.hour >= 20 or ts.weekday() >= 5),
    }


# ----------------------------------------------------------------------------
# Process chain templates
# ----------------------------------------------------------------------------
NORMAL_CHAINS = [
    (["explorer.exe", "chrome.exe"], 0.24),
    (["explorer.exe", "winword.exe"], 0.14),
    (["explorer.exe", "excel.exe"], 0.12),
    (["explorer.exe", "outlook.exe"], 0.10),
    (["explorer.exe", "teams.exe"], 0.08),
    (["explorer.exe", "code.exe", "python.exe"], 0.10),
    (["explorer.exe", "code.exe", "node.exe"], 0.05),
    (["services.exe", "svchost.exe"], 0.07),
    (["explorer.exe", "cmd.exe", "python.exe"], 0.04),
    (["explorer.exe", "code.exe", "git.exe", "ssh.exe"], 0.03),
    (["explorer.exe", "cmd.exe", "powershell.exe"], 0.03),   # admin hard-negative
]
MACRO_HEADS = [["explorer.exe", "winword.exe"], ["explorer.exe", "excel.exe"],
               ["explorer.exe", "outlook.exe", "winword.exe"]]
MACRO_MIDS = ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"]
MACRO_TAILS = ["certutil.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "payload.exe"]
RANSOM_CHAINS = [
    ["explorer.exe", "invoice.exe"],
    ["explorer.exe", "updater.exe"],
    ["explorer.exe", "cmd.exe", "locker.exe"],
    ["services.exe", "svchost.exe", "enc.exe"],
]


def pick_weighted(rng, items):
    chains, w = zip(*items)
    w = np.array(w) / np.sum(w)
    return list(chains[rng.choice(len(chains), p=w)])


def macro_chain(rng):
    chain = list(MACRO_HEADS[rng.integers(len(MACRO_HEADS))])
    chain.append(str(rng.choice(MACRO_MIDS)))
    if rng.random() < 0.6:
        chain.append("powershell.exe" if chain[-1] != "powershell.exe" else "cmd.exe")
    chain.append(str(rng.choice(MACRO_TAILS)))
    return chain


# ----------------------------------------------------------------------------
# Users / hosts
# ----------------------------------------------------------------------------
def build_entities(rng):
    users = [f"user_{i:03d}" for i in range(1, N_USERS + 1)]
    ws = [f"ws-{i:02d}" for i in range(1, N_WORKSTATIONS + 1)]
    srv = [f"srv-{i:02d}" for i in range(1, N_SERVERS + 1)]
    # each user has a home workstation (some share one) and a favourite server
    home_ws = {u: ws[i % N_WORKSTATIONS] for i, u in enumerate(users)}
    fav_srv = {u: srv[rng.integers(N_SERVERS)] for u in users}
    # per-user behavioural baselines
    base_files = {u: float(rng.uniform(3, 25)) for u in users}
    base_cpu = {u: float(rng.uniform(12, 32)) for u in users}
    # normal activity weight (heavy vs light users)
    act_w = rng.dirichlet(np.full(N_USERS, 2.0))
    return users, ws, srv, home_ws, fav_srv, base_files, base_cpu, act_w


def pick_host(rng, u, home_ws, fav_srv, ws):
    r = rng.random()
    if r < 0.80:
        return home_ws[u]
    if r < 0.92:
        return fav_srv[u]
    return str(rng.choice(ws))


# ----------------------------------------------------------------------------
# Timestamps
# ----------------------------------------------------------------------------
def business_ts(rng):
    day = int(rng.integers(DAYS))
    while (START + timedelta(days=day)).weekday() >= 5 and rng.random() < 0.9:
        day = int(rng.integers(DAYS))            # weekends are rare
    hour = int(np.clip(rng.normal(13, 3.2), 0, 23))
    return START + timedelta(days=day, hours=hour,
                             minutes=int(rng.integers(60)), seconds=int(rng.integers(60)))


def offhours_ts(rng):
    day = int(rng.integers(DAYS))
    hour = int(rng.choice([0, 1, 2, 3, 4, 5, 22, 23]))
    return START + timedelta(days=day, hours=hour,
                             minutes=int(rng.integers(60)), seconds=int(rng.integers(60)))


def any_ts(rng):
    return START + timedelta(days=int(rng.integers(DAYS)), hours=int(rng.integers(24)),
                             minutes=int(rng.integers(60)), seconds=int(rng.integers(60)))


# ----------------------------------------------------------------------------
# Generation
# ----------------------------------------------------------------------------
def generate() -> pd.DataFrame:
    rng = np.random.default_rng(SEED)
    users, ws, srv, home_ws, fav_srv, base_files, base_cpu, act_w = build_entities(rng)
    rows = []

    # ---- normal events ----
    n_normal = N_ROWS - N_ANOMALIES
    for _ in range(n_normal):
        u = users[rng.choice(N_USERS, p=act_w)]
        files = rng.poisson(base_files[u])
        cpu = float(np.clip(rng.normal(base_cpu[u], 7), 1, 70))
        new_country = False
        chain = pick_weighted(rng, NORMAL_CHAINS)
        ts = business_ts(rng) if rng.random() < 0.93 else offhours_ts(rng)
        # hard negatives so the classes overlap (not trivially separable)
        r = rng.random()
        if r < 0.02:                                   # backup / bulk copy burst
            files = int(rng.integers(120, 400))
            cpu = float(rng.uniform(35, 70))
        elif r < 0.035:                                # legit travel
            new_country = True
        rows.append(dict(user=u, files_touched_per_min=float(files), new_country=new_country,
                         process_chain=chain, cpu_percent=round(cpu, 2), timestamp=ts,
                         label=0, attack_type="normal"))

    # ---- injected anomalies ----
    # skewed victim selection: some accounts get hit repeatedly (realistic, graph-relevant)
    victim_w = rng.dirichlet(np.full(N_USERS, 0.6))
    for attack, count in ATTACK_SPLIT.items():
        for _ in range(count):
            u = users[rng.choice(N_USERS, p=victim_w)]
            if attack == "ransomware":
                files = float(rng.integers(250, 3000))
                cpu = float(rng.uniform(55, 100))
                new_country = False
                chain = list(RANSOM_CHAINS[rng.integers(len(RANSOM_CHAINS))])
                ts = offhours_ts(rng) if rng.random() < 0.55 else business_ts(rng)
            elif attack == "macro_malware":
                files = float(rng.poisson(base_files[u] * rng.uniform(1, 3)))
                cpu = float(rng.uniform(30, 85))
                new_country = False
                chain = macro_chain(rng)
                ts = business_ts(rng)
            else:  # impossible_travel
                files = float(rng.poisson(base_files[u]))
                cpu = float(np.clip(rng.normal(base_cpu[u], 7), 1, 70))
                new_country = True
                chain = pick_weighted(rng, NORMAL_CHAINS)
                ts = offhours_ts(rng) if rng.random() < 0.6 else any_ts(rng)
            rows.append(dict(user=u, files_touched_per_min=files, new_country=new_country,
                             process_chain=chain, cpu_percent=round(min(cpu, 100.0), 2),
                             timestamp=ts, label=1, attack_type=attack))

    df = pd.DataFrame(rows)

    # hosts: assigned after the fact using the same rng stream (deterministic)
    df["host"] = [pick_host(rng, u, home_ws, fav_srv, ws) for u in df["user"]]

    # sort by time, then assign a stable event_id (this is the row key Step 2 will use)
    df = df.sort_values("timestamp", kind="mergesort").reset_index(drop=True)
    df.insert(0, "event_id", [f"evt_{i:05d}" for i in range(len(df))])

    # derived features
    derived = pd.DataFrame([derive_features(c, t) for c, t in zip(df["process_chain"], df["timestamp"])])
    df = pd.concat([df, derived], axis=1)

    # serialise for CSV
    df["process_chain"] = df["process_chain"].apply(lambda c: ">".join(c))
    df["new_country"] = df["new_country"].astype(int)
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%dT%H:%M:%S")

    cols = ["event_id", "timestamp", "user", "host", "files_touched_per_min", "new_country",
            "process_chain", "cpu_percent", "process_chain_length", "process_chain_depth",
            "hour_of_day", "is_off_hours", "label", "attack_type"]
    return df[cols]


# ----------------------------------------------------------------------------
# Sanity checks
# ----------------------------------------------------------------------------
def validate(df: pd.DataFrame) -> None:
    print("\n=== SANITY CHECKS ===")
    print(f"Row count            : {len(df):,}")
    assert len(df) == N_ROWS

    vc = df["label"].value_counts().sort_index()
    print(f"Normal               : {vc[0]:,} ({vc[0] / len(df):.2%})")
    print(f"Anomaly              : {vc[1]:,} ({vc[1] / len(df):.2%})")
    print("Anomaly breakdown    :")
    for k, v in df[df.label == 1]["attack_type"].value_counts().items():
        print(f"    {k:<18}{v:>5}")

    nulls = int(df.isna().sum().sum())
    print(f"Null cells           : {nulls}")
    assert nulls == 0
    assert df["event_id"].is_unique

    bad = 0
    for rec in df.to_dict("records"):
        try:
            Event(user=rec["user"], files_touched_per_min=rec["files_touched_per_min"],
                  new_country=bool(rec["new_country"]),
                  process_chain=rec["process_chain"].split(">"),
                  cpu_percent=rec["cpu_percent"], timestamp=rec["timestamp"])
        except ValidationError:
            bad += 1
    print(f"Pydantic Event valid : {len(df) - bad:,}/{len(df):,}  (invalid: {bad})")
    assert bad == 0

    per_user = df.groupby("user").size()
    print(f"Unique users         : {df['user'].nunique()}")
    print(f"Unique hosts         : {df['host'].nunique()}")
    print(f"Unique process chains: {df['process_chain'].nunique()}")
    print(f"Unique processes     : {len({p for c in df['process_chain'] for p in c.split('>')})}")
    print(f"Events/user          : min {per_user.min()}, median {int(per_user.median())}, max {per_user.max()}")
    print(f"Users with >=1 anomaly: {df[df.label == 1]['user'].nunique()}/{df['user'].nunique()}")
    print(f"Time range           : {df['timestamp'].min()} -> {df['timestamp'].max()}")


def main():
    df = generate()
    validate(df)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)
    digest = hashlib.sha256(OUT_PATH.read_bytes()).hexdigest()

    print("\n=== OUTPUT ===")
    print(f"Saved                : {OUT_PATH}")
    print(f"Random seed          : {SEED}")
    print(f"SHA-256              : {digest}")
    return digest


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
