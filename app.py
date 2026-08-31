from flask import Flask, render_template, jsonify, send_file
import json
import os
import random
from datetime import datetime
from dotenv import load_dotenv
from weather_monitor import get_weather, check_disaster
from system_simulator import simulate_metrics, check_critical

load_dotenv()

app = Flask(__name__, template_folder='dashboard/templates', static_folder='dashboard/static')

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

BUCKET_SUFFIX = "255274109745-ap-south-1-an"

def get_backup_history(branch):
    import boto3
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )
    bucket_name = f"disaster-recovery-{branch}-{BUCKET_SUFFIX}"
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            return []
        backups = []
        for obj in response['Contents']:
            backups.append({
                "file": obj['Key'],
                "size": obj['Size'],
                "last_modified": (obj['LastModified'] + __import__('datetime').timedelta(hours=5, minutes=30)).strftime('%Y-%m-%d %H:%M:%S IST')
            })
        return backups
    except Exception as e:
        print(f"Failed to fetch history for {branch}: {e}")
        return []

def get_branch_status(branch):
    alerts = []
    weather_info = {}
    
    # Weather check
    from weather_monitor import CITIES, DISASTER_THRESHOLDS
    city_code = CITIES[branch]
    weather_data = get_weather(branch, city_code)
    
    if weather_data:
        temp = weather_data["main"]["temp"]
        humidity = weather_data["main"]["humidity"]
        wind_speed = weather_data["wind"]["speed"]
        condition = weather_data["weather"][0]["description"]
        weather_info = {
            "temp": temp,
            "humidity": humidity,
            "wind": wind_speed,
            "condition": condition.title()
        }
        weather_alerts = check_disaster(branch, weather_data)
        alerts.extend(weather_alerts)

    # System check
    simulate_failure = random.random() < 0.2
    metrics = simulate_metrics(branch, simulate_failure)
    system_alerts = check_critical(metrics)
    alerts.extend(system_alerts)

    # Determine status
    if len(alerts) >= 2:
        status = "RED"
    elif len(alerts) == 1:
        status = "YELLOW"
    else:
        status = "GREEN"

    return {
        "branch": branch.upper(),
        "status": status,
        "alerts": alerts,
        "cpu": metrics["cpu_usage"],
        "ram": metrics["ram_usage"],
        "disk": metrics["disk_usage"],
        "weather": weather_info,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/status')
def status():
    branch_data = []
    for branch in BRANCHES:
        branch_data.append(get_branch_status(branch))
    return jsonify(branch_data)

@app.route('/api/backup-history/<branch>')
def backup_history(branch):
    history = get_backup_history(branch)
    return jsonify(history)

@app.route('/api/download/<branch>/<path:s3_key>')
def download_file(branch, s3_key):
    import boto3
    import tempfile
    import os as operating_system

    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
        region_name=os.getenv("AWS_REGION")
    )
    bucket_name = f"disaster-recovery-{branch}-{BUCKET_SUFFIX}"

    try:
        filename = s3_key.split('/')[-1]
        tmp_path = operating_system.path.join(tempfile.gettempdir(), filename)
        s3.download_file(bucket_name, s3_key, tmp_path)
        return send_file(tmp_path, as_attachment=True, download_name=filename)
    except Exception as e:
        print(f"Download error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/trigger-demo', methods=['POST'])
def trigger_demo():
    import random
    from alert import send_alert
    from backup import upload_to_s3

    branch = "bangalore"  # Demo always triggers on Bangalore

    alerts = [
        "[CYBER] Cyber attack detected — 15 attempts in 3s from public IP",
        "[SYSTEM] High CPU: 94.5%",
        "[SYSTEM] High RAM: 91.2%",
        "[WEATHER] High temperature: 43.2°C"
    ]

    print(f"\n{'='*50}")
    print(f"DEMO TRIGGERED — Simulating disaster on {branch.upper()}")
    print(f"{'='*50}")

    # Trigger backup
    backup_success = upload_to_s3(branch)

    # Trigger email
    email_success = send_alert(branch, alerts)

    return jsonify({
        "branch": branch.upper(),
        "alerts": alerts,
        "backup": "Success" if backup_success else "Failed",
        "email": "Sent" if email_success else "Failed",
        "message": f"Demo disaster triggered on {branch.upper()} — backup and email completed"
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)