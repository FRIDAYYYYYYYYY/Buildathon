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

# Test event evaluation with temporal burst
# Let's test single-event threshold breach (event_score >= 75) vs cumulative score
# And let's test how burst detection triggers across the stream

def run_simulation(burst_window_seconds=300, burst_threshold_score=30, burst_min_events=3, burst_bonus=20, threshold=75):
    test_records = test_df.to_dict('records')
    
    # Track user timestamps for qualifying events
    # We test:
    # 1. Per-event classification: does the event trigger breach individually? (e.g. combined + burst >= threshold)
    # 2. Window tracking:
    user_qualifying_times = {} # user -> list of timestamps
    
    results = []
    
    for row in test_records:
        evt = make_event(row)
        r_score = rule_score(evt)
        a_score = detector.anomaly_score(evt)
        
        # SIEM Best practice noise-floor gating
        if r_score == 0 and a_score < 30:
            raw_risk = 0
        else:
            raw_risk = r_score + a_score
            
        # Burst detection logic
        current_ts = evt.timestamp
        window_start = current_ts - timedelta(seconds=burst_window_seconds)
        
        bonus = 0
        is_qualifying = (r_score + a_score) > burst_threshold_score  # score above 30
        
        if is_qualifying:
            if evt.user not in user_qualifying_times:
                user_qualifying_times[evt.user] = []
            
            # Append current ts
            user_qualifying_times[evt.user].append(current_ts)
            
            # Prune old timestamps
            user_qualifying_times[evt.user] = [
                t for t in user_qualifying_times[evt.user] if t >= window_start
            ]
            
            if len(user_qualifying_times[evt.user]) >= burst_min_events:
                bonus = burst_bonus
                
        event_risk = raw_risk + bonus
        
        # Single-event breach (without cross-session accumulation) vs accumulated
        results.append({
            'event_id': row['event_id'],
            'user': row['user'],
            'label': row['label'],
            'attack_type': row['attack_type'],
            'timestamp': row['timestamp'],
            'rule_score': r_score,
            'anomaly_score': a_score,
            'raw_risk': raw_risk,
            'burst_bonus': bonus,
            'event_risk': event_risk,
            'is_breached_single': event_risk >= threshold,
            'is_breached_raw_single': raw_risk >= threshold,
        })
        
    res_df = pd.DataFrame(results)
    
    print(f"\n==========================================")
    print(f"BURST CONFIG: window={burst_window_seconds}s, thresh_score={burst_threshold_score}, min_events={burst_min_events}, bonus={burst_bonus}")
    print(f"==========================================")
    
    benign = res_df[res_df['label'] == 0]
    attacks = res_df[res_df['label'] == 1]
    
    # Burst bonus activations
    benign_bursts = (benign['burst_bonus'] > 0).sum()
    attack_bursts = (attacks['burst_bonus'] > 0).sum()
    print(f"Burst Bonus Activated on Benign: {benign_bursts} / {len(benign)}")
    print(f"Burst Bonus Activated on Attacks: {attack_bursts} / {len(attacks)}")
    for att, g in attacks.groupby('attack_type'):
        print(f"   - {att}: {(g['burst_bonus'] > 0).sum()} / {len(g)}")
        
    # Single Event TPR / FPR comparison (Threshold = 75)
    fp_raw = (benign['is_breached_raw_single']).sum()
    fp_burst = (benign['is_breached_single']).sum()
    print(f"\nFalse Positives (Threshold >= {threshold}):")
    print(f"  Before (Raw): {fp_raw} / {len(benign)} (FPR: {fp_raw/len(benign):.4%})")
    print(f"  After (Burst): {fp_burst} / {len(benign)} (FPR: {fp_burst/len(benign):.4%})")
    print(f"  New False Positives Introduced: {fp_burst - fp_raw}")
    
    print(f"\nDetection (TPR @ Threshold >= {threshold}):")
    tp_raw = (attacks['is_breached_raw_single']).sum()
    tp_burst = (attacks['is_breached_single']).sum()
    print(f"  Overall: Raw {tp_raw}/{len(attacks)} ({tp_raw/len(attacks):.2%}) -> Burst {tp_burst}/{len(attacks)} ({tp_burst/len(attacks):.2%})")
    
    for att, g in attacks.groupby('attack_type'):
        r_tp = (g['is_breached_raw_single']).sum()
        b_tp = (g['is_breached_single']).sum()
        print(f"  {att:<18}: Raw {r_tp:>3}/{len(g)} ({r_tp/len(g):.2%}) -> Burst {b_tp:>3}/{len(g)} ({b_tp/len(g):.2%})")
        
    return res_df

print("Running baseline & burst tests...")
run_simulation()
