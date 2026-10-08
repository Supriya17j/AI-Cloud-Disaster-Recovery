"""Test data generator and demo helpers."""
import os, shutil, random
from datetime import datetime, timedelta
from config.settings import BACKUP_DIR, RESTORE_DIR
from modules.db import conn, ex, init_db
from modules import monitor, backup

def reset_all():
    c = conn()
    for t in ("metrics","risk_scores","cyber_events","backups","recovery_points","disasters","recovery_assessments","recovery_history","audit_logs","monitoring_state","security_events","agent_assessments","agent_activity","telemetry","anomaly_history"):
        c.execute(f"DELETE FROM {t}")
    c.commit(); c.close()
    for d in (BACKUP_DIR, RESTORE_DIR): shutil.rmtree(d, ignore_errors=True); os.makedirs(d, exist_ok=True)

def history(n=40):
    """Synthetic metrics + risk history for charts and the anomaly model."""
    from modules.risk import assess_risk
    for _ in range(n): assess_risk(monitor.collect_metrics(simulate=True))

def baseline():
    """3 healthy recovery points at -3h, -2h, -1h."""
    for h in (3, 2, 1):
        ts = (datetime.now() - timedelta(hours=h)).isoformat(timespec="seconds")
        backup.create_backup(risk_score=round(random.uniform(8, 18), 1), suspicious=0, created_at=ts)

def insert_attack(ts, etype="ransomware"):
    ex("INSERT INTO cyber_events(ts,category,type,severity,detail) VALUES(?,?,?,?,?)", (ts.isoformat(timespec="seconds"), "cyber", etype, "critical", "seeded attack"))
