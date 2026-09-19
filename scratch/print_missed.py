import json
import pandas as pd
from src.models import Event
from src.rules import rule_score
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

# Replay test set with RiskScorer (Stateful) vs Single Event
scorer = RiskScorer()
records = test_df.to_dict('records')

macro_eval = []
for r in records:
    evt = make_event(r)
    bd = scorer.score_event(evt)
    if r['attack_type'] == 'macro_malware':
        macro_eval.append({
            'event_id': r['event_id'],
            'user': r['user'],
            'process_chain': r['process_chain'],
            'files_touched_per_min': r['files_touched_per_min'],
            'cpu_percent': r['cpu_percent'],
            'new_country': r['new_country'],
            'rule_score': bd.rule_score,
            'anomaly_score': bd.anomaly_score,
            'combined_score': bd.combined_score,
            'cumulative_score': bd.cumulative_score,
            'is_breached': bd.is_breached,
        })

macro_df = pd.DataFrame(macro_eval)
missed_cumulative = macro_df[~macro_df['is_breached']]
print(f"Total macro_malware events in test split: {len(macro_df)}")
print(f"Cumulative Breached (Detected): {macro_df['is_breached'].sum()} / {len(macro_df)} ({macro_df['is_breached'].mean():.2%})")
print(f"Missed count: {len(missed_cumulative)}")

print("\nExact Missed Events (Cumulative < 75):")
for idx, row in missed_cumulative.iterrows():
    print(f"ID: {row['event_id']}, User: {row['user']}, Rules: {row['rule_score']}, Anomaly: {row['anomaly_score']}, Combined: {row['combined_score']}, CumScore: {row['cumulative_score']}")
    print(f"   Process Chain: {row['process_chain']}")
    print(f"   Files: {row['files_touched_per_min']}, CPU: {row['cpu_percent']}%, Geo: {row['new_country']}")

