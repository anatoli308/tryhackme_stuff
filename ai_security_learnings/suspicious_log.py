#!/usr/bin/env python3
import sys
from joblib import load

if len(sys.argv) != 2:
    print("Usage: python3 classify_logs.py /path/to/logfile")
    sys.exit(1)

model = load('/opt/dfir-lab/log_model.joblib')

with open(sys.argv[1], 'r') as f:
    lines = f.readlines()

for line in lines:
    if line.strip():
        pred = model.predict([line.strip()])
        if pred[0] == 1:
            print(f"[SUSPICIOUS] {line.strip()}")
