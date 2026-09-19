import pandas as pd
import re

df = pd.read_csv('data/training_data.csv')
benign_df = df[df['label'] == 0]

pattern = r"(winword|excel|powerpnt|outlook)\.exe\s*(->|>)\s*(cmd|powershell|cscript|wscript|mshta)\.exe"

matches = benign_df[benign_df['process_chain'].str.contains(pattern, case=False, regex=True)]
print(f"Benign events matching pattern in whole dataset (N={len(benign_df)}): {len(matches)}")
for pc in matches['process_chain'].unique():
    print(f"  - {pc}")

