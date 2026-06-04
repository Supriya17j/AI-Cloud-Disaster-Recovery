import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import json

def train():
    print("Loading login data...")
    df = pd.read_csv("login_data.csv")

    # Features the ML model will learn from
    features = ["attempts", "time_gap_seconds"]
    X = df[features]
    y = df["label"]  # 0 = normal, 1 = attack

    print(f"  ✓ {len(df)} records loaded")
    print(f"  ✓ Normal: {len(df[df.label==0])}, Attacks: {len(df[df.label==1])}")

    # Train Isolation Forest
    print("\nTraining Isolation Forest...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,   # expects ~10% anomalies
        random_state=42
    )
    model.fit(X)

    # Predict — Isolation Forest returns -1 for anomaly, 1 for normal
    predictions = model.predict(X)
    # Convert to 0/1 format (1 = attack, 0 = normal)
    predictions = [1 if p == -1 else 0 for p in predictions]

    # Accuracy results
    print("\nModel Results:")
    print("="*50)
    print(classification_report(y, predictions, target_names=["Normal", "Attack"]))

    print("Confusion Matrix:")
    cm = confusion_matrix(y, predictions)
    print(f"  True Normal  (correct): {cm[0][0]}")
    print(f"  False Alarm  (wrong)  : {cm[0][1]}")
    print(f"  Missed Attack (wrong) : {cm[1][0]}")
    print(f"  True Attack  (correct): {cm[1][1]}")

    # Save model
    with open("ml_models/isolation_forest.pkl", "wb") as f:
        pickle.dump(model, f)
    print("\n  ✓ Model saved to ml_models/isolation_forest.pkl")

    # Save results
    accuracy = sum([1 for a, b in zip(y, predictions) if a == b]) / len(y)
    results = {
        "model": "Isolation Forest",
        "total_records": len(df),
        "normal_records": len(df[df.label==0]),
        "attack_records": len(df[df.label==1]),
        "accuracy": round(accuracy * 100, 2)
    }
    with open("ml_models/results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"  ✓ Accuracy: {results['accuracy']}%")

if __name__ == "__main__":
    train()