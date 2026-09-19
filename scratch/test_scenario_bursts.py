import json
from datetime import datetime, timedelta, timezone
import pandas as pd
from src.models import Event
from src.rules import rule_score
from src.anomaly import AnomalyDetector
from src.data_generator import generate_baseline_events, generate_attack_scenario

# 1. Load test data and train detector
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

# Test attack scenarios from data_generator
print("=== TESTING SCRIPTED MULTI-STAGE SCENARIOS (data_generator.py) ===")
for scenario_name in ['ransomware', 'macro_malware', 'impossible_travel']:
    events = generate_attack_scenario(scenario_name, user=f"victim_{scenario_name}", seed=101)
    
    # Baseline scorer (without burst)
    class StandardScorer:
        def __init__(self, threshold=75):
            self.threshold = threshold
            self.cum_score = 0
        def score_event(self, e):
            r = rule_score(e)
            a = detector.anomaly_score(e)
            risk = 0 if (r == 0 and a < 30) else (r + a)
            self.cum_score += risk
            return r, a, risk, self.cum_score, self.cum_score >= self.threshold

    # Burst scorer
    class BurstScorer:
        def __init__(self, threshold=75, window_sec=300, min_events=3, bonus=20, thresh_score=30):
            self.threshold = threshold
            self.window_sec = window_sec
            self.min_events = min_events
            self.bonus = bonus
            self.thresh_score = thresh_score
            self.user_history = {}
            self.cum_score = 0
            
        def score_event(self, e):
            r = rule_score(e)
            a = detector.anomaly_score(e)
            raw_risk = 0 if (r == 0 and a < 30) else (r + a)
            
            # burst tracking
            b_bonus = 0
            if (r + a) > self.thresh_score:
                if e.user not in self.user_history:
                    self.user_history[e.user] = []
                self.user_history[e.user].append(e.timestamp)
                cutoff = e.timestamp - timedelta(seconds=self.window_sec)
                self.user_history[e.user] = [t for t in self.user_history[e.user] if t >= cutoff]
                if len(self.user_history[e.user]) >= self.min_events:
                    b_bonus = self.bonus
                    
            event_risk = raw_risk + b_bonus
            self.cum_score += event_risk
            return r, a, raw_risk, b_bonus, event_risk, self.cum_score, self.cum_score >= self.threshold

    s_std = StandardScorer()
    s_bst = BurstScorer()
    
    print(f"\n--- Scenario: {scenario_name} (3 sequential events, 45s apart) ---")
    for idx, e in enumerate(events):
        r1, a1, risk1, cum1, br1 = s_std.score_event(e)
        r2, a2, raw2, bon2, risk2, cum2, br2 = s_bst.score_event(e)
        print(f"Event {idx+1}: Process='{e.process_chain}'")
        print(f"   Rules={r1:2d}, Anomaly={a1:2d} | Standard: EventRisk={risk1:3d}, CumScore={cum1:3d} (Breach={br1})")
        print(f"   Burst Bonus=+{bon2:2d}     | Burst:    EventRisk={risk2:3d}, CumScore={cum2:3d} (Breach={br2})")

