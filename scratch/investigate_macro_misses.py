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

# Find macro_malware events in test set
macro_test = test_df[test_df['attack_type'] == 'macro_malware'].copy()
macro_records = macro_test.to_dict('records')

results = []
for r in macro_records:
    evt = make_event(r)
    r_sc = rule_score(evt)
    a_sc = detector.anomaly_score(evt)
    comb = r_sc + a_sc
    results.append({
        'event_id': r['event_id'],
        'user': r['user'],
        'host': r.get('host', ''),
        'process_chain': r['process_chain'],
        'files_touched_per_min': r['files_touched_per_min'],
        'cpu_percent': r['cpu_percent'],
        'new_country': r['new_country'],
        'rule_score': r_sc,
        'anomaly_score': a_sc,
        'combined_score': comb,
        'gap_to_75': 75 - comb,
        'detected_single': comb >= 75
    })

res_df = pd.DataFrame(results)
missed = res_df[~res_df['detected_single']]

print(f"Total macro_malware in test set: {len(res_df)}")
print(f"Detected: {res_df['detected_single'].sum()}, Missed: {len(missed)}")
print("\n" + "="*80)
print("FULL DETAILS OF THE 6 MISSED MACRO_MALWARE EVENTS:")
print("="*80)
for idx, row in missed.iterrows():
    print(f"\nEvent ID: {row['event_id']}")
    print(f"  User: {row['user']}, Host: {row['host']}")
    print(f"  Process Chain: {row['process_chain']}")
    print(f"  Files/min: {row['files_touched_per_min']}, CPU%: {row['cpu_percent']}%, New Country: {row['new_country']}")
    print(f"  Rule Score: {row['rule_score']}, Anomaly Score: {row['anomaly_score']}")
    print(f"  Combined Score: {row['combined_score']} (Gap to 75: {row['gap_to_75']} pts)")

print("\n" + "="*80)
print("DETECTED MACRO_MALWARE SUMMARY (FOR COMPARISON):")
print("="*80)
detected = res_df[res_df['detected_single']]
print(f"Detected Rule Scores: min={detected['rule_score'].min()}, mean={detected['rule_score'].mean():.1f}, max={detected['rule_score'].max()}")
print(f"Detected Anomaly Scores: min={detected['anomaly_score'].min()}, mean={detected['anomaly_score'].mean():.1f}, max={detected['anomaly_score'].max()}")
print(f"Detected Combined Scores: min={detected['combined_score'].min()}, mean={detected['combined_score'].mean():.1f}, max={detected['combined_score'].max()}")

# Inspect process chains of detected vs missed
print("\nMissed Process Chains:")
for pc in missed['process_chain'].unique():
    print(f"  - {pc}")

print("\nSample Detected Process Chains:")
for pc in detected['process_chain'].unique()[:10]:
    print(f"  - {pc}")

