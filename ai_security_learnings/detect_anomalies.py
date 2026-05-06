#!/usr/bin/env python3
import os
import pandas as pd
import numpy as np
from pathlib import Path
from joblib import load

def shannon_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy -= p_x * np.log2(p_x)
    return entropy

# Define focused scan targets
root_dirs = ['/opt/robbco', '/tmp', '/dev/shm', '/usr/local/bin']
all_rows = []

print("[*] Scanning paths:")
for root_dir in root_dirs:
    print(f"    - {root_dir}")
    for path in Path(root_dir).rglob("*"):
        if path.is_file():
            try:
                with open(path, 'rb') as f:
                    content = f.read(1024)
                    entropy = shannon_entropy(content.decode(errors='ignore'))
            except:
                entropy = 0
            try:
                all_rows.append({
                    'path': str(path),
                    'size': os.path.getsize(path),
                    'ext': path.suffix.lower(),
                    'entropy': entropy,
                    'is_hidden': path.name.startswith('.'),
                    'is_executable': os.access(path, os.X_OK)
                })
            except:
                continue

# Convert to DataFrame
df = pd.DataFrame(all_rows)

# Drop path for prediction, encode features
features = df.drop(columns=['path'])
features_encoded = pd.get_dummies(features)

# Load trained model
model = load('/opt/dfir-lab/file_model.joblib')

# Align columns if needed
model_features = model.feature_names_in_
missing_cols = [col for col in model_features if col not in features_encoded.columns]
for col in missing_cols:
    features_encoded[col] = 0
features_encoded = features_encoded[model_features]  # re-order to match

# Predict suspiciousness
df['prediction'] = model.predict(features_encoded)
suspicious = df[df['prediction'] == 1]

# Output results
print("\n[!] Supervised AI-flagged suspicious files:")
print(suspicious[['path', 'size', 'entropy']])
