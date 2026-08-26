import pickle
import json
import pandas as pd
import requests
import os
from datetime import datetime
from dotenv import load_dotenv
from backup import upload_to_s3
from alert import send_alert

load_dotenv()

API_KEY = os.getenv("OPENWEATHERMAP_API_KEY")

# Load trained ML model
with open("ml_models/isolation_forest.pkl", "rb") as f:
    model = pickle.load(f)

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

CITIES = {
    "mumbai": "Mumbai,IN",
    "delhi": "Delhi,IN",
    "bangalore": "Bangalore,IN",
    "chennai": "Chennai,IN",
    "hyderabad": "Hyderabad,IN"
}

WEATHER_THRESHOLDS = {
    "wind_speed": 20,
    "humidity": 90,
    "temp": 42
}

SYSTEM_THRESHOLDS = {
    "cpu": 85,
    "ram": 85,
    "disk": 90
}

# ─── Weather Check ───────────────────────────────────────
def check_weather(branch):
    city_code = CITIES[branch]
    url = f"http://api.openweathermap.org/data/2.5/weather?q={city_code}&appid={API_KEY}&units=metric"
    response = requests.get(url)
    alerts = []

    if response.status_code == 200:
        data = response.json()
        temp = data["main"]["temp"]
        humidity = data["main"]["humidity"]
        wind_speed = data["wind"]["speed"]

        if temp >= WEATHER_THRESHOLDS["temp"]:
            alerts.append(f"High temperature: {temp}°C")
        if humidity >= WEATHER_THRESHOLDS["humidity"]:
            alerts.append(f"High humidity: {humidity}%")
        if wind_speed >= WEATHER_THRESHOLDS["wind_speed"]:
            alerts.append(f"High wind speed: {wind_speed} m/s")

    return alerts

# ─── Cyber Attack Check ───────────────────────────────────
def check_cyber(attempts, time_gap_seconds):
    # Rule-based filter — less than 5 attempts can never be an attack
    if attempts < 5:
        return False
    features = pd.DataFrame([[attempts, time_gap_seconds]],
                            columns=["attempts", "time_gap_seconds"])
    prediction = model.predict(features)[0]
    return prediction == -1

# ─── System Metrics Check ─────────────────────────────────
def check_system(branch):
    alerts = []
    try:
        with open(f"branch_{branch}/system_metrics.json") as f:
            metrics = json.load(f)
        if metrics["cpu_usage"] >= SYSTEM_THRESHOLDS["cpu"]:
            alerts.append(f"High CPU: {metrics['cpu_usage']}%")
        if metrics["ram_usage"] >= SYSTEM_THRESHOLDS["ram"]:
            alerts.append(f"High RAM: {metrics['ram_usage']}%")
        if metrics["disk_usage"] >= SYSTEM_THRESHOLDS["disk"]:
            alerts.append(f"High Disk: {metrics['disk_usage']}%")
    except FileNotFoundError:
        pass
    return alerts

# ─── Backup Trigger (Member 2 will connect here) ──────────
def trigger_backup(branch, reason):
    print(f"   🔄 Backup triggered for {branch} — Reason: {reason}")
    upload_to_s3(branch)
    # Member 2's backup.py will be called here
    # Example: backup.upload_to_s3(branch)

# ─── Email Alert Trigger (Member 2 will connect here) ─────
def trigger_email(branch, alerts):
    send_alert(branch, alerts)
    # Member 2's alert.py will be called here
    # Example: alert.send_email(branch, alerts)

# ─── Main Disaster Engine ─────────────────────────────────
def run_engine():
    print(f"\n{'='*50}")
    print(f"Disaster Engine — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    for branch in BRANCHES:
        print(f"\n📍 {branch.upper()}")
        all_alerts = []

        # 1. Weather check
        weather_alerts = check_weather(branch)
        if weather_alerts:
            for a in weather_alerts:
                print(f"   🌩 WEATHER: {a}")
                all_alerts.append(f"[WEATHER] {a}")

        # 2. System check
        system_alerts = check_system(branch)
        if system_alerts:
            for a in system_alerts:
                print(f"   💻 SYSTEM: {a}")
                all_alerts.append(f"[SYSTEM] {a}")

        # 3. Cyber check (simulate a login event)
        import random
        scenario = random.choice(["normal", "normal", "normal", "attack"])
        if scenario == "normal":
            attempts = random.randint(1, 3)
            time_gap = random.randint(600, 7200)
        else:
            attempts = random.randint(8, 20)
            time_gap = random.randint(1, 15)
        is_attack = check_cyber(attempts, time_gap)
        if is_attack:
            msg = f"Cyber attack detected — {attempts} attempts in {time_gap}s"
            print(f"   🚨 CYBER: {msg}")
            all_alerts.append(f"[CYBER] {msg}")

        # 4. Trigger backup and email if any alerts
        if all_alerts:
            trigger_backup(branch, all_alerts[0])
            trigger_email(branch, all_alerts)
        else:
            print(f"   ✓ All clear")

    print(f"\n{'='*50}")
    print("Engine run complete.")
    print(f"{'='*50}\n")

if __name__ == "__main__":
    run_engine()