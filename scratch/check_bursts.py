import json
import pandas as pd
from src.models import Event
from src.rules import rule_score
from src.anomaly import AnomalyDetector

splits = json.load(open('data/split_indices.json'))
df = pd.read_csv('data/training_data.csv')
df['parsed_ts'] = pd.to_datetime(df['timestamp'])
df = df.sort_values('parsed_ts').reset_index(drop=True)

train_df = df[df['event_id'].isin(splits['train_event_ids'])]
test_df = df[df['event_id'].isin(splits['test_event_ids'])].copy()

# Fit detector on train split
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

# Compute raw scores for test events
test_records = test_df.to_dict('records')
test_events = [make_event(r) for r in test_records]
test_df['rule_score'] = [rule_score(e) for e in test_events]
test_df['anomaly_score'] = [detector.anomaly_score(e) for e in test_events]
test_df['raw_combined'] = test_df['rule_score'] + test_df['anomaly_score']

print("Raw scores summary:")
for att in ['normal', 'ransomware', 'macro_malware', 'impossible_travel']:
    sub = test_df[test_df['attack_type'] == att]
    print(f"\n--- {att} (N={len(sub)}) ---")
    print(f"Rule score: min={sub['rule_score'].min()}, mean={sub['rule_score'].mean():.1f}, max={sub['rule_score'].max()}")
    print(f"Anomaly score: min={sub['anomaly_score'].min()}, mean={sub['anomaly_score'].mean():.1f}, max={sub['anomaly_score'].max()}")
    print(f"Raw combined: min={sub['raw_combined'].min()}, mean={sub['raw_combined'].mean():.1f}, max={sub['raw_combined'].max()}")
    print(f"Events with raw_combined >= 30: {(sub['raw_combined'] >= 30).sum()} / {len(sub)} ({(sub['raw_combined'] >= 30).mean():.1%})")
    print(f"Events with raw_combined > 30: {(sub['raw_combined'] > 30).sum()} / {len(sub)} ({(sub['raw_combined'] > 30).mean():.1%})")

