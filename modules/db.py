"""SQLite helpers + automatic schema creation."""
import sqlite3, datetime as dt, json
from config.settings import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS metrics(id INTEGER PRIMARY KEY, ts TEXT, cpu REAL, ram REAL, disk REAL, logins INTEGER, failed_logins INTEGER, suspicious INTEGER);
CREATE TABLE IF NOT EXISTS risk_scores(id INTEGER PRIMARY KEY, ts TEXT, score REAL, level TEXT, reasons TEXT, anomaly TEXT, decision TEXT);
CREATE TABLE IF NOT EXISTS cyber_events(id INTEGER PRIMARY KEY, ts TEXT, category TEXT, type TEXT, severity TEXT, detail TEXT, resolved INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY, backup_id TEXT UNIQUE, created_at TEXT, risk_score REAL, sha256 TEXT, path TEXT, storage TEXT, size INTEGER, status TEXT);
CREATE TABLE IF NOT EXISTS recovery_points(id INTEGER PRIMARY KEY, backup_id TEXT, created_at TEXT, risk_score REAL, suspicious INTEGER);
CREATE TABLE IF NOT EXISTS disasters(id INTEGER PRIMARY KEY, ts TEXT, type TEXT, status TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS recovery_assessments(id INTEGER PRIMARY KEY, ts TEXT, backup_id TEXT, readiness REAL, classification TEXT, hard_failure TEXT, details TEXT);
CREATE TABLE IF NOT EXISTS recovery_history(id INTEGER PRIMARY KEY, ts TEXT, backup_id TEXT, rto_s REAL, rpo_min REAL, status TEXT, report_path TEXT);
CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY, ts TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS monitoring_state(id INTEGER PRIMARY KEY CHECK(id = 1), security_state TEXT NOT NULL, recovery_state TEXT NOT NULL, last_event_state TEXT, backup_id TEXT, recovery_id TEXT, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS security_events(event_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, event_type TEXT NOT NULL, risk_score REAL NOT NULL, security_state TEXT NOT NULL, anomaly_count INTEGER NOT NULL, system_status TEXT NOT NULL, ai_decision TEXT NOT NULL, backup_id TEXT, recovery_id TEXT, recovery_status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agent_assessments(id INTEGER PRIMARY KEY, recovery_id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, recovery_point TEXT, backup_integrity REAL, threat_score REAL, anomaly_score REAL, system_health REAL, recovery_safety_score REAL, agent_decision TEXT, decision_reason TEXT, status TEXT);
CREATE TABLE IF NOT EXISTS agent_activity(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, agent_name TEXT NOT NULL, status TEXT NOT NULL, action TEXT NOT NULL, confidence REAL, decision TEXT);
CREATE TABLE IF NOT EXISTS telemetry(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, source TEXT NOT NULL, cpu REAL, memory REAL, disk REAL, network_in REAL, network_out REAL, failed_logins REAL, suspicious REAL, status_check_failed REAL, system_health REAL, valid INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS anomaly_history(id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, anomaly_detected INTEGER NOT NULL, anomaly_score REAL, classification TEXT NOT NULL, model TEXT NOT NULL, baseline_size INTEGER NOT NULL, confidence REAL, explanation TEXT);
CREATE TABLE IF NOT EXISTS robust_decisions(id INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, timestamp TEXT NOT NULL, decision TEXT NOT NULL, confidence REAL, reason TEXT, authority TEXT, selected_recovery_point TEXT, selected_recovery_agent TEXT, blocking_factors TEXT, agent_trust TEXT, readiness_score REAL);
"""

def now(): return dt.datetime.now().isoformat(timespec="seconds")

def conn():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

def init_db():
    c = conn(); c.executescript(SCHEMA); c.commit(); c.close()

def q(sql, a=()):
    c = conn()
    try: return [dict(r) for r in c.execute(sql, a).fetchall()]
    finally: c.close()

def ex(sql, a=()):
    c = conn(); cur = c.execute(sql, a); c.commit(); i = cur.lastrowid; c.close(); return i

def audit(action, detail=""):
    ex("INSERT INTO audit_logs(ts,action,detail) VALUES(?,?,?)", (now(), action, detail if isinstance(detail, str) else json.dumps(detail)))
