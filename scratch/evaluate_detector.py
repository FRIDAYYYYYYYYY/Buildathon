import json
import pandas as pd
from datetime import datetime
from src.models import Event
from src.scorer import RiskScorer
from src.anomaly import AnomalyDetector
from src.rules import rule_score

def load_data():
    split_data = json.load(open('data/split_indices.json'))
    df = pd.read_csv('data/training_data.csv')
    df['parsed_ts'] = pd.to_datetime(df['timestamp'])
    return split_data, df

def make_event(row):
    return Event(
        user=row['user'],
        files_touched_per_min=int(round(row['files_touched_per_min'])),
        new_country=bool(row['new_country']),
        process_chain=row['process_chain'],
        cpu_percent=float(row['cpu_percent']),
        timestamp=pd.to_datetime(row['timestamp']).to_pydatetime(),
    )

def evaluate(scorer_factory=None):
    split_data, df = load_data()
    train_ids = set(split_data['train_event_ids'])
    test_ids = set(split_data['test_event_ids'])
    
    # Sort entire dataset chronologically
    df_sorted = df.sort_values('parsed_ts').reset_index(drop=True)
    
    # Train anomaly detector on train split
    train_df = df_sorted[df_sorted['event_id'].isin(train_ids)]
    train_events = [make_event(r) for r in train_df.to_dict('records')]
    
    detector = AnomalyDetector()
    detector.fit(train_events)
    
    # Patch default detector or use custom scorer
    import src.scorer as scorer_mod
    import src.anomaly as anomaly_mod
    anomaly_mod._DEFAULT_DETECTOR = detector
    
    if scorer_factory:
        scorer = scorer_factory()
    else:
        scorer = RiskScorer()
        
    # Replay all test events in chronological order (or whole stream)
    # Let's see: in a real SIEM stream, events arrive chronologically per user.
    # Let's track stats per event in the test set.
    
    # Let's track:
    # 1. Single event-level breach (combined_score >= threshold or rule/anomaly)
    # 2. Cumulative score breach
    results = []
    
    # Test set rows
    test_df = df_sorted[df_sorted['event_id'].isin(test_ids)]
    
    for row in test_df.to_dict('records'):
        evt = make_event(row)
        bd = scorer.score_event(evt)
        results.append({
            'event_id': row['event_id'],
            'user': row['user'],
            'label': row['label'],
            'attack_type': row['attack_type'],
            'timestamp': row['timestamp'],
            'rule_score': bd.rule_score,
            'anomaly_score': bd.anomaly_score,
            'combined_score': bd.combined_score,
            'cumulative_score': bd.cumulative_score,
            'is_breached': bd.is_breached,
            'burst_bonus': getattr(bd, 'burst_bonus', 0)
        })
        
    res_df = pd.DataFrame(results)
    
    print("=== EVALUATION RESULTS ===")
    print(f"Total test events: {len(res_df)}")
    
    # True positives, false positives, TPR, FPR by attack type and overall
    # An event is flagged if is_breached is True (or cumulative_score >= threshold)
    benign = res_df[res_df['label'] == 0]
    attacks = res_df[res_df['label'] == 1]
    
    fp_count = (benign['is_breached']).sum()
    fpr = fp_count / len(benign) if len(benign) > 0 else 0
    
    print(f"Benign test events: {len(benign)}")
    print(f"False Positives: {fp_count} (FPR: {fpr:.4%})")
    
    attack_stats = []
    for att_type, group in attacks.groupby('attack_type'):
        tp_count = (group['is_breached']).sum()
        tpr = tp_count / len(group)
        attack_stats.append({
            'Attack Type': att_type,
            'Total': len(group),
            'Detected (TP)': tp_count,
            'TPR': f"{tpr:.2%}",
            'Mean Cumulative Score': group['cumulative_score'].mean(),
            'Mean Rule Score': group['rule_score'].mean(),
            'Mean Anomaly Score': group['anomaly_score'].mean(),
        })
        
    overall_tp = (attacks['is_breached']).sum()
    overall_tpr = overall_tp / len(attacks)
    print(f"\nOverall Attack Detection: {overall_tp}/{len(attacks)} (TPR: {overall_tpr:.2%})")
    print(pd.DataFrame(attack_stats).to_string(index=False))
    
    return res_df

if __name__ == '__main__':
    evaluate()
