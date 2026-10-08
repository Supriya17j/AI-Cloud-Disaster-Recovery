"""Stage 2: disaster simulation."""
from modules.db import q, ex, now, audit
from modules.monitor import simulate_cyber_event
from modules.backup import tamper_backup

TYPES = ["ransomware attack", "backup tampering", "dependency failure", "system failure", "recovery environment failure"]

def simulate(dtype):
    if dtype not in TYPES: raise ValueError("unknown disaster type")
    detail = ""
    if dtype == "ransomware attack":
        simulate_cyber_event("ransomware")
    elif dtype == "backup tampering":
        newest = q("SELECT backup_id FROM recovery_points ORDER BY created_at DESC LIMIT 1")
        if newest: tamper_backup(newest[0]["backup_id"]); detail = newest[0]["backup_id"]
    ex("INSERT INTO disasters(ts,type,status,detail) VALUES(?,?,?,?)", (now(), dtype, "active", detail))
    audit("DISASTER", dtype)

def active():
    return q("SELECT * FROM disasters WHERE status='active' ORDER BY ts")

def resolve_all():
    ex("UPDATE disasters SET status='resolved' WHERE status='active'")
    ex("UPDATE cyber_events SET resolved=1 WHERE resolved=0")
