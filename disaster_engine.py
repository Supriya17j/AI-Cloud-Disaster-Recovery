import pickle
import json
import pandas as pd
from datetime import datetime

# Load trained model
with open("ml_models/isolation_forest.pkl", "rb") as f:
    model = pickle.load(f)

def detect_cyber_attack(attempts, time_gap_seconds, branch):
    features = pd.DataFrame([[attempts, time_gap_seconds]],
                            columns=["attempts", "time_gap_seconds"])
    prediction = model.predict(features)[0]
    is_attack = prediction == -1

    result = {
        "timestamp": datetime.now().isoformat(),
        "branch": branch,
        "attempts": attempts,
        "time_gap_seconds": time_gap_seconds,
        "is_attack": is_attack,
        "status": "⚠ ATTACK DETECTED" if is_attack else "✓ Normal"
    }
    return result

def run_detection():
    print(f"\n{'='*50}")
    print(f"Cyber Attack Detector — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    # Test cases
    test_logins = [
        {"attempts": 1,  "time_gap_seconds": 1800, "branch": "mumbai"},    # normal
        {"attempts": 1,  "time_gap_seconds": 3600, "branch": "delhi"},     # normal
        {"attempts": 15, "time_gap_seconds": 5,    "branch": "bangalore"}, # attack
        {"attempts": 20, "time_gap_seconds": 2,    "branch": "chennai"},   # attack
        {"attempts": 1,  "time_gap_seconds": 2400, "branch": "hyderabad"}, # normal
    ]

    for login in test_logins:
        result = detect_cyber_attack(
            login["attempts"],
            login["time_gap_seconds"],
            login["branch"]
        )
        print(f"\n📍 {result['branch'].upper()}")
        print(f"   Attempts        : {result['attempts']}")
        print(f"   Time Gap        : {result['time_gap_seconds']}s")
        print(f"   Status          : {result['status']}")

if __name__ == "__main__":
    run_detection()