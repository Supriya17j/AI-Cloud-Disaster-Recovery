"""Stage 1: monitoring, cyber-event simulation, external events."""
import os, random
from config.settings import DEMO_MODE
from modules.db import ex, now, audit
try:
    import psutil
except ImportError:
    psutil = None

CYBER_EVENTS = {"ransomware": "critical", "malware": "high",
                "unauthorized_access": "high", "credential_abuse": "medium"}

def collect_metrics(simulate=False):
    """Real psutil readings; falls back to simulated enterprise data."""
    if psutil and not simulate:
        cpu = psutil.cpu_percent(interval=0.2); ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage(os.path.abspath(os.sep)).percent
    elif simulate and DEMO_MODE:
        cpu, ram, disk = random.uniform(15, 60), random.uniform(30, 65), random.uniform(40, 70)
    else:
        raise RuntimeError("Live psutil telemetry is unavailable; enable DEMO_MODE for simulated collection")
    m = dict(ts=now(), cpu=round(cpu, 1), ram=round(ram, 1), disk=round(disk, 1),
             logins=random.randint(20, 80), failed_logins=random.randint(0, 6), suspicious=random.randint(0, 2))
    m["id"] = ex("INSERT INTO metrics(ts,cpu,ram,disk,logins,failed_logins,suspicious) VALUES(?,?,?,?,?,?,?)",
                 (m["ts"], m["cpu"], m["ram"], m["disk"], m["logins"], m["failed_logins"], m["suspicious"]))
    return m

def simulate_cyber_event(etype, ts=None):
    sev = CYBER_EVENTS[etype]
    ex("INSERT INTO cyber_events(ts,category,type,severity,detail) VALUES(?,?,?,?,?)",
       (ts or now(), "cyber", etype, sev, f"Simulated {etype} event"))
    audit("CYBER_EVENT", etype)

def add_external_event(etype, detail=""):
    """Manual entry: severe weather / power failure / datacenter issue."""
    ex("INSERT INTO cyber_events(ts,category,type,severity,detail) VALUES(?,?,?,?,?)",
       (now(), "external", etype, "medium", detail))
    audit("EXTERNAL_EVENT", etype)
