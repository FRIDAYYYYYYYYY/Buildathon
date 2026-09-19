import json
import re
import pandas as pd
from src.models import Event
from src.anomaly import AnomalyDetector
from src.scorer import RiskScorer

splits = json.load(open('data/split_indices.json'))
df = pd.read_csv('data/training_data.csv')
df['parsed_ts'] = pd.to_datetime(df['timestamp'])
df = df.sort_values('parsed_ts').reset_index(drop=True)

train_df = df[df['event_id'].isin(splits['train_event_ids'])]
test_df = df[df['event_id'].isin(splits['test_event_ids'])].copy()

def make_event(row):
    return Event(
        user=row['user'],
        files_touched_per_min=int(round(row['files_touched_per_min'])),
        new_country=bool(row['new_country']),
        process_chain=row['process_chain'],
        cpu_percent=float(row['cpu_percent']),
        timestamp=row['parsed_ts'].to_pydatetime(),
    )

train_events = [make_event(r) for r in train_df.to_dict('records')]
detector = AnomalyDetector()
detector.fit(train_events)

# Test updated pattern
SUSPICIOUS_PATTERNS_NEW = [
    (r"mimikatz|sekurlsa|DumpLsa|procdump", 50, "Credential dumping signature detected"),
    (r"vssadmin.*delete\s+shadows|ransom|locker", 45, "Shadow copy deletion / ransomware signature"),
    (r"(winword|excel|powerpnt|outlook)\.exe.*(->|>)\s*(cmd|powershell|cscript|wscript|mshta)\.exe", 35, "Office app spawned command interpreter"),
    (r"powershell.*(-enc|-executionpolicy\s+bypass|downloadstring|iex)", 35, "Obfuscated / policy-bypass PowerShell invocation"),
    (r"certutil.*-urlcache|bitsadmin.*\/transfer", 30, "Living-off-the-land download utility invoked"),
    (r"rundll32\.exe\s+.*\.bin|regsvr32\.exe\s+\/s", 30, "Unsigned/raw binary execution via system utility"),
]

def custom_rule_score(event: Event) -> int:
    score = 0
    chain_lower = event.process_chain.lower()
    for pattern, points, _ in SUSPICIOUS_PATTERNS_NEW:
        if re.search(pattern, chain_lower, re.IGNORECASE):
            score += points
    if event.files_touched_per_min >= 300:
        score += 40
    elif event.files_touched_per_min >= 100:
        score += 20
    elif event.files_touched_per_min >= 50:
        score += 10
    if event.new_country:
        score += 35
    if event.cpu_percent >= 85.0:
        score += 15
    elif event.cpu_percent >= 60.0:
        score += 5
    return score

# Evaluation on all 2400 test events
records = test_df.to_dict('records')
results = []
user_scores = {}
user_burst = {}

for r in records:
    evt = make_event(r)
    r_sc = custom_rule_score(evt)
    a_sc = detector.anomaly_score(evt)
    raw = 0 if (r_sc == 0 and a_sc < 30) else (r_sc + a_sc)
    
    # burst
    bonus = 0
    if (r_sc + a_sc) > 30:
        if evt.user not in user_burst:
            user_burst[evt.user] = []
        user_burst[evt.user].append(evt.timestamp)
        cutoff = evt.timestamp - pd.Timedelta(seconds=300)
        user_burst[evt.user] = [t for t in user_burst[evt.user] if t >= cutoff]
        if len(user_burst[evt.user]) >= 3:
            bonus = 20
            
    risk = raw + bonus
    cum = user_scores.get(evt.user, 0) + risk
    user_scores[evt.user] = cum
    results.append({
        'event_id': r['event_id'],
        'label': r['label'],
        'attack_type': r['attack_type'],
        'rule_score': r_sc,
        'anomaly_score': a_sc,
        'cumulative_score': cum,
        'is_breached': cum >= 75
    })

res_df = pd.DataFrame(results)
benign = res_df[res_df['label'] == 0]
attacks = res_df[res_df['label'] == 1]

print("=== RESULTS WITH REFINED REGEX ===")
print(f"Benign False Positives: {benign['is_breached'].sum()} / {len(benign)}")
print(f"Overall Attack Detection: {attacks['is_breached'].sum()} / {len(attacks)} ({attacks['is_breached'].mean():.2%})")
for att, g in attacks.groupby('attack_type'):
    print(f"  - {att:<18}: {g['is_breached'].sum()} / {len(g)} ({g['is_breached'].mean():.2%})")

