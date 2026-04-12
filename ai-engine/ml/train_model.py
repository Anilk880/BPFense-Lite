import json
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

FEATURE_KEYS = ["file_access", "net", "exec", "sensitive_file"]

def extract_vector(e):
    return [e.get(k, 0) for k in FEATURE_KEYS]

data = []

with open("features.log") as f:
    for line in f:
        e = json.loads(line)
        vec = extract_vector(e)
        data.append(vec)

X = np.array(data)

print(f"[INFO] Training on {len(X)} samples")

model = IsolationForest(contamination=0.1)
model.fit(X)

joblib.dump(model, "model.pkl")

print("[INFO] Model saved")
