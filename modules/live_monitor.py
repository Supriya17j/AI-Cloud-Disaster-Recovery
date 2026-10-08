"""Live monitoring orchestration and recovery state transitions."""
import json
import os
import uuid

from aws.dynamodb_store import put_event, recent_events
from aws.cloudwatch_store import collect as collect_cloudwatch
from config.settings import DEMO_MODE
from modules import backup, risk
from modules.db import ex, now, q

SECURITY_STATES = ("NORMAL", "ELEVATED", "HIGH", "CRITICAL", "COMPROMISED")
RECOVERY_STATES = (
    "MONITORING", "RISK_DETECTED", "COMPROMISED", "BACKUP_IN_PROGRESS", "BACKUP_COMPLETE",
    "ASSESSING_RECOVERY", "SAFE_POINT_SELECTED", "RECOVERY_AUTHORIZATION_REQUIRED",
    "RECOVERY_IN_PROGRESS", "RECOVERY_COMPLETE", "RECOVERY_FAILED",
)


def _security_state(result, active_events):
    if any(event["type"] in {"ransomware", "ransomware_like_behavior", "backup_tampering"} for event in active_events):
        return "COMPROMISED"
    severity = result.get("severity", "LOW")
    return {"LOW": "NORMAL", "MEDIUM": "ELEVATED", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}.get(severity, "NORMAL")


def _system_status(system_risk):
    if system_risk >= 75:
        return "CRITICAL"
    if system_risk >= 50:
        return "DEGRADED"
    return "HEALTHY"


def _state_row():
    return (q("SELECT * FROM monitoring_state WHERE id=1") or [None])[0]


def _save_state(security_state, recovery_state, last_event_state=None, backup_id=None, recovery_id=None):
    ex("""INSERT INTO monitoring_state(id,security_state,recovery_state,last_event_state,backup_id,recovery_id,updated_at)
           VALUES(1,?,?,?,?,?,?)
           ON CONFLICT(id) DO UPDATE SET security_state=excluded.security_state,
           recovery_state=excluded.recovery_state,last_event_state=excluded.last_event_state,
           backup_id=COALESCE(excluded.backup_id,monitoring_state.backup_id),
           recovery_id=COALESCE(excluded.recovery_id,monitoring_state.recovery_id),updated_at=excluded.updated_at""",
       (security_state, recovery_state, last_event_state, backup_id, recovery_id, now()))


def _record_event(state, result, anomaly_count, system_status, decision, backup_id=None):
    event = {
        "event_id": "EVT-" + uuid.uuid4().hex[:8].upper(),
        "timestamp": now(),
        "event_type": "SECURITY_ALARM" if state in {"HIGH", "CRITICAL", "COMPROMISED"} else "SECURITY_STATE_CHANGE",
        "risk_score": round(float(result.get("overall_risk", 0)), 2),
        "security_state": state,
        "anomaly_count": anomaly_count,
        "system_status": system_status,
        "AI_decision": decision,
        "backup_id": backup_id or "",
        "recovery_id": "",
        "recovery_status": "BACKUP_COMPLETE" if backup_id else "MONITORING",
    }
    ex("""INSERT INTO security_events(event_id,timestamp,event_type,risk_score,security_state,anomaly_count,
           system_status,ai_decision,backup_id,recovery_id,recovery_status)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)""", tuple(event.values()))
    put_event(event)
    return event


def collect():
    csv_path = os.getenv("CYBER_CSV_PATH")
    cloudwatch = collect_cloudwatch()
    event_filter = "" if DEMO_MODE else " AND detail NOT LIKE 'Simulated%' AND detail NOT LIKE 'DEMO%'"
    indicators = {
        "failed_logins": len(q(f"SELECT id FROM cyber_events WHERE category='cyber' AND type IN ('unauthorized_access','credential_abuse'){event_filter} AND resolved=0")),
        "suspicious": len(q(f"SELECT id FROM cyber_events WHERE category='cyber'{event_filter} AND resolved=0")),
    }
    telemetry = risk.collect_telemetry(cloudwatch, indicators)
    anomaly = risk.detect_telemetry_anomaly(telemetry)
    system_metrics = risk.telemetry_system_metrics(telemetry)
    result = risk.assess_risk_engine(
        cyber_csv=csv_path if csv_path and os.path.exists(csv_path) else None,
        system_metrics=system_metrics,
        cloudwatch_alarm=cloudwatch.get("alarm_status", "NOT_CONFIGURED"),
        telemetry_anomaly=anomaly,
    )
    ex("INSERT INTO risk_scores(ts,score,level,reasons,anomaly,decision) VALUES(?,?,?,?,?,?)",
       (now(), result["overall_risk"], result["severity"], json.dumps(result.get("risk_evidence", [])),
        "anomalous" if result.get("anomalies_detected", 0) else "normal", result.get("severity")))
    system = result["system"]
    active_events = q(f"SELECT type FROM cyber_events WHERE category='cyber' AND resolved=0{event_filter} ORDER BY id DESC")
    state = _security_state(result, active_events)
    previous = _state_row()
    previous_state = previous["security_state"] if previous else "NORMAL"
    anomaly_count = int(result.get("anomalies_detected", 0)) + len(active_events)
    system_status = _system_status(system["system_risk_score"])
    decision = "Protect backup" if state in {"CRITICAL", "COMPROMISED"} else "Continue monitoring"
    recovery_state = "COMPROMISED" if state == "COMPROMISED" else "RISK_DETECTED" if state in {"ELEVATED", "HIGH", "CRITICAL"} else "MONITORING"
    backup_id = previous.get("backup_id") if previous else None
    event = None
    significant = state != previous_state and (state in {"ELEVATED", "HIGH", "CRITICAL", "COMPROMISED"})
    if significant:
        if state in {"CRITICAL", "COMPROMISED"}:
            recovery_state = "BACKUP_IN_PROGRESS"
            backup_id = backup.create_backup(result["overall_risk"], anomaly_count)["backup_id"]
            recovery_state = "BACKUP_COMPLETE"
        event = _record_event(state, result, anomaly_count, system_status, decision, backup_id)
        _save_state(state, recovery_state, state, backup_id)
    elif previous is None:
        _save_state(state, recovery_state)
    else:
        _save_state(state, previous["recovery_state"], previous["last_event_state"], backup_id)

    latest_state = _state_row()
    return snapshot(result, latest_state, event, anomaly_count, system_status, decision, cloudwatch, telemetry, anomaly)


def snapshot(result=None, state=None, event=None, anomaly_count=0, system_status="UNKNOWN", decision="Continue monitoring", cloudwatch=None, telemetry=None, anomaly=None):
    state = state or _state_row() or {"security_state": "NORMAL", "recovery_state": "MONITORING"}
    result = result or risk.get_current_risk_analysis()
    events = q("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 25")
    dynamo_events = recent_events(25)
    known_ids = {event["event_id"] for event in events}
    events = sorted(events + [event for event in dynamo_events if event.get("event_id") not in known_ids],
                    key=lambda item: item.get("timestamp", ""), reverse=True)[:25]
    return {
        "monitoring": True,
        "updated_at": now(),
        "security_state": state["security_state"],
        "recovery_state": state["recovery_state"],
        "risk_score": result.get("overall_risk", 0),
        "risk_level": result.get("severity", "LOW"),
        "ai_decision": decision,
        "anomaly_count": anomaly_count,
        "system_status": system_status,
        "system": result.get("system", {}),
        "weather": result.get("weather", {}),
        "risk_factors": result.get("risk_factors", {}),
        "cloudwatch_alarm": result.get("cloudwatch_alarm", "NOT_CONFIGURED"),
        "alarm": {
            "active": state["security_state"] in {"HIGH", "CRITICAL", "COMPROMISED"} or result.get("severity") in {"HIGH", "CRITICAL"} or result.get("cloudwatch_alarm") == "ALARM",
            "severity": "CRITICAL" if state["security_state"] == "COMPROMISED" else result.get("severity", "LOW"),
            "reason": "High fused risk, compromise indicator, or active CloudWatch alarm" if state["security_state"] in {"HIGH", "CRITICAL", "COMPROMISED"} or result.get("severity") in {"HIGH", "CRITICAL"} or result.get("cloudwatch_alarm") == "ALARM" else "No high-risk alarm",
        },
        "cloudwatch": cloudwatch or {"status": "DISABLED"},
        "telemetry": telemetry or {},
        "anomaly": anomaly or {},
        "cyber": result.get("cyber", {}),
        "backup": (q("SELECT backup_id,created_at,status FROM backups ORDER BY created_at DESC LIMIT 1") or [None])[0],
        "recovery": (q("SELECT ts,backup_id,status FROM recovery_history ORDER BY id DESC LIMIT 1") or [None])[0],
        "event": event,
        "events": events,
    }