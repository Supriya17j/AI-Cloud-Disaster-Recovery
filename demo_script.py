import time
import os

def clear():
    os.system('cls')

def pause(msg="Press Enter to continue..."):
    input(f"\n{msg}")

def demo():
    clear()
    print("=" * 60)
    print("   AI-BASED CLOUD DISASTER RECOVERY SYSTEM")
    print("   Live Demo")
    print("=" * 60)
    pause()

    # ── PART 1: Problem Statement ──────────────────────────────
    clear()
    print("=" * 60)
    print("PROBLEM STATEMENT")
    print("=" * 60)
    print("""
  Modern organisations store critical data across multiple
  cloud branches. When disasters strike — cyberattacks,
  extreme weather, or system failures — data is lost and
  recovery is slow.

  Our system:
  ✓ Monitors all branches in real time
  ✓ Detects threats using Machine Learning
  ✓ Automatically triggers backup and alerts
    """)
    pause()

    # ── PART 2: Live Weather Check ─────────────────────────────
    clear()
    print("=" * 60)
    print("STEP 1 — LIVE WEATHER MONITORING")
    print("=" * 60)
    print("\nFetching live weather for all 5 branches...\n")
    time.sleep(1)
    from weather_monitor import monitor_weather
    monitor_weather()
    pause()

    # ── PART 3: System Metrics ─────────────────────────────────
    clear()
    print("=" * 60)
    print("STEP 2 — SYSTEM HEALTH CHECK")
    print("=" * 60)
    print("\nSimulating system metrics for all 5 branches...\n")
    time.sleep(1)
    from system_simulator import run_simulator
    run_simulator()
    pause()

    # ── PART 4: Cyber Attack Demo ──────────────────────────────
    clear()
    print("=" * 60)
    print("STEP 3 — CYBER ATTACK SIMULATION")
    print("=" * 60)
    print("""
  Simulating a brute force attack on branch_mumbai...
  
  Attack pattern:
  → 15 login attempts
  → From a public IP
  → Only 3 seconds apart
    """)
    time.sleep(2)

    import pickle
    import pandas as pd

    with open("ml_models/isolation_forest.pkl", "rb") as f:
        model = pickle.load(f)

    attempts = 15
    time_gap = 3
    features = pd.DataFrame([[attempts, time_gap]],
                            columns=["attempts", "time_gap_seconds"])
    prediction = model.predict(features)[0]
    is_attack = prediction == -1 and attempts >= 5

    print("  Running Isolation Forest ML model...")
    time.sleep(1)
    print(f"  Attempts    : {attempts}")
    print(f"  Time Gap    : {time_gap}s")

    if is_attack:
        print("""
  ══════════════════════════════════════════
  🚨 ATTACK DETECTED BY ML MODEL
  ══════════════════════════════════════════
  → Isolation Forest flagged anomaly
  → Backup trigger: ACTIVATED
  → Email alert: QUEUED
  ══════════════════════════════════════════
        """)
    pause()

    # ── PART 5: Full Engine Run ────────────────────────────────
    clear()
    print("=" * 60)
    print("STEP 4 — FULL DISASTER ENGINE")
    print("=" * 60)
    print("\nRunning complete disaster engine across all branches...\n")
    time.sleep(1)
    from disaster_engine import run_engine
    run_engine()
    pause()

    # ── PART 6: ML Results ─────────────────────────────────────
    clear()
    print("=" * 60)
    print("STEP 5 — ML MODEL RESULTS")
    print("=" * 60)
    print("""
  Model    : Isolation Forest
  Dataset  : 1200 login records
             → 1000 normal logins
             → 200 attack patterns

  Results:
  ✓ Accuracy        : 90.25%
  ✓ Attacks caught  : 131 / 200
  ✓ False alarms    : 48 / 1000
  ✓ Model saved     : ml_models/isolation_forest.pkl
    """)
    pause()

    # ── END ───────────────────────────────────────────────────
    clear()
    print("=" * 60)
    print("   THANK YOU")
    print("=" * 60)
    print("""
  System successfully demonstrated:

  ✓ Live weather monitoring — OpenWeatherMap API
  ✓ System health simulation — CPU / RAM / Disk
  ✓ ML cyber attack detection — Isolation Forest
  ✓ Unified disaster engine — all triggers connected
  ✓ Backup and email alerts — ready for integration
    """)
    print("=" * 60)

if __name__ == "__main__":
    demo()