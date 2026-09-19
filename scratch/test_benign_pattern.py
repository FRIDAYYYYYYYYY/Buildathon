import json
import re
import pandas as pd
from src.models import Event
from src.anomaly import AnomalyDetector

splits = json.load(open('data/split_indices.json'))
df = pd.read_csv('data/training_data.csv')
test_df = df[df['event_id'].isin(splits['test_event_ids'])].copy()

pattern_orig = r"(winword|excel|powerpnt|outlook)\.exe\s*->\s*(cmd|powershell|cscript|wscript)\.exe"
pattern_new = r"(winword|excel|powerpnt|outlook)\.exe.*(->|>)\s*(cmd|powershell|cscript|wscript|mshta)\.exe"

benign_test = test_df[test_df['label'] == 0]
match_orig = benign_test[benign_test['process_chain'].str.contains(pattern_orig, case=False, regex=True)]
match_new = benign_test[benign_test['process_chain'].str.contains(pattern_new, case=False, regex=True)]

print(f"Benign test matches with original pattern: {len(match_orig)}")
print(f"Benign test matches with new pattern: {len(match_new)}")

