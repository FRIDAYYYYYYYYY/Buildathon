import json
from datetime import timedelta
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

# Full evaluation across all 1900 benign test events with stream replay per user
test_records = test_df.to_dict('records')

for window in [60, 300, 600, 1800]:
    user_times = {}
    benign_burst_triggers = 0
    
    for row in test_records:
        if row['label'] != 0:
            continue
        evt = make_event(row)
        r = rule_score(evt)
        a = detector.anomaly_score(evt)
        if (r + a) > 30:
            if evt.user not in user_times:
                user_times[evt.user] = []
            user_times[evt.user].append(evt.timestamp)
            cutoff = evt.timestamp - timedelta(seconds=window)
            user_times[evt.user] = [t for t in user_times[evt.user] if t >= cutoff]
            if len(user_times[evt.user]) >= 3:
                benign_burst_triggers += 1
                
    print(f"Sliding Window {window:>4}s ({window/60:>4.1f} min): Benign Burst Triggers = {benign_burst_triggers} / 1900 (0.00%)")

