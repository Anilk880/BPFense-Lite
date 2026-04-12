import sys
import json
import numpy as np
import joblib
import os

FEATURE_KEYS = ["file_access", "net", "exec", "sensitive_file"]

def extract_vector(e):
    return [e.get(k, 0) for k in FEATURE_KEYS]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

model = joblib.load(MODEL_PATH)

print("[INFO] Model loaded", flush=True)

while True:
    try:
        line = sys.stdin.readline()
        if not line:
            continue

        e = json.loads(line.strip())
        pod = e.get("pod", "unknown")

        # ---------------- RULE SIGNAL ----------------
        rule_flag = 0
        if e.get("exec", 0) == 1 and e.get("sensitive_file", 0) == 1:
            rule_flag = 1

        # ---------------- ML INFERENCE ----------------
        vec = np.array([extract_vector(e)])
        score = model.decision_function(vec)[0]

        # ---------------- THRESHOLDS ----------------
        if score < 0.15:
            level = "HIGH ALERT"
        elif score < 0.25:
            level = "MEDIUM ALERT"
        else:
            level = "NORMAL"

        # 🔥 IMPORTANT: include rule flag
        print(f"{level}|{pod}|{score:.3f}|rule={rule_flag}", flush=True)

    except Exception as ex:
        print(f"[ERROR] {str(ex)}", file=sys.stderr)
        print("NORMAL|unknown|0|rule=0", flush=True)
