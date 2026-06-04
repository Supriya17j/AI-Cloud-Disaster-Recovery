import random
import json
from datetime import datetime

BRANCHES = ['mumbai', 'delhi', 'bangalore', 'chennai', 'hyderabad']

NORMAL_RANGES = {
    "cpu": (10, 60),
    "ram": (20, 70),
    "disk": (30, 75)
}

CRITICAL_THRESHOLDS = {
    "cpu": 85,
    "ram": 85,
    "disk": 90
}

def simulate_metrics(branch, simulate_failure=False):
    if simulate_failure:
        cpu = random.uniform(85, 100)
        ram = random.uniform(85, 100)
        disk = random.uniform(90, 100)
    else:
        cpu = random.uniform(*NORMAL_RANGES["cpu"])
        ram = random.uniform(*NORMAL_RANGES["ram"])
        disk = random.uniform(*NORMAL_RANGES["disk"])

    return {
        "branch": branch,
        "timestamp": datetime.now().isoformat(),
        "cpu_usage": round(cpu, 2),
        "ram_usage": round(ram, 2),
        "disk_usage": round(disk, 2)
    }

def check_critical(metrics):
    alerts = []
    if metrics["cpu_usage"] >= CRITICAL_THRESHOLDS["cpu"]:
        alerts.append(f"🔴 High CPU usage: {metrics['cpu_usage']}%")
    if metrics["ram_usage"] >= CRITICAL_THRESHOLDS["ram"]:
        alerts.append(f"🔴 High RAM usage: {metrics['ram_usage']}%")
    if metrics["disk_usage"] >= CRITICAL_THRESHOLDS["disk"]:
        alerts.append(f"🔴 High Disk usage: {metrics['disk_usage']}%")
    return alerts

def run_simulator():
    print(f"\n{'='*50}")
    print(f"System Monitor — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}")

    for branch in BRANCHES:
        # Randomly simulate a failure for demo purposes
        simulate_failure = random.random() < 0.2  # 20% chance
        metrics = simulate_metrics(branch, simulate_failure)

        print(f"\n💻 {branch.upper()}")
        print(f"   CPU  : {metrics['cpu_usage']}%")
        print(f"   RAM  : {metrics['ram_usage']}%")
        print(f"   Disk : {metrics['disk_usage']}%")

        alerts = check_critical(metrics)
        if alerts:
            print(f"   ⚠ SYSTEM ALERTS:")
            for alert in alerts:
                print(f"     → {alert}")
        else:
            print(f"   ✓ All systems normal")

        # Save metrics to branch folder
        with open(f"branch_{branch}/system_metrics.json", "w") as f:
            json.dump(metrics, f, indent=2)

if __name__ == "__main__":
    run_simulator()