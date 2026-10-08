"""Evidence-backed agent workflow for trust-aware recovery assessment."""
import uuid
from datetime import datetime

from aws.dynamodb_store import put_assessment, recent_assessments
from config.settings import DEMO_MODE
from modules import readiness
from modules.db import ex, now, q


def _clamp(value):
    return round(max(0.0, min(100.0, float(value))), 1)


def _age_score(created_at, reference):
    age_minutes = max(0.0, (reference - datetime.fromisoformat(created_at)).total_seconds() / 60)
    return _clamp(100 - (age_minutes / 240.0 * 100)), age_minutes


def _threat_score(live):
    event_filter = "" if DEMO_MODE else " AND detail NOT LIKE 'Simulated%' AND detail NOT LIKE 'DEMO%'"
    active = q(f"SELECT type,severity FROM cyber_events WHERE category='cyber' AND resolved=0{event_filter}")
    if any(event["severity"] == "critical" or event["type"] in {"ransomware", "ransomware_like_behavior", "backup_tampering"} for event in active):
        return 100.0
    cyber = live.get("cyber", {})
    return _clamp(max(float(cyber.get("cyber_risk_score", 0) or 0), float(live.get("risk_score", 0) or 0) * 0.45))


def _assessment_rows(gate, live):
    reference = datetime.now()
    threat = _threat_score(live)
    anomaly = _clamp(live.get("cyber", {}).get("anomaly_percentage", 0) or 0)
    system_health = _clamp(100 - float(live.get("system", {}).get("system_risk_score", 0) or 0))
    rows = []
    for item in gate.get("assessments", []):
        age_reliability, age_minutes = _age_score(item["created_at"], reference)
        integrity = 100.0 if item["integrity"] else 0.0
        point_threat = 100.0 if item["phase"] == "after" else max(threat, 75.0) if item["phase"] == "during" else threat
        trust = _clamp(
            integrity * 0.30
            + (100 - point_threat) * 0.25
            + (100 - anomaly) * 0.15
            + system_health * 0.15
            + age_reliability * 0.15
        )
        decision = "SELECTED" if item["backup_id"] == gate.get("recommended") else "ALTERNATIVE"
        if item["hard_failure"] or item["classification"] in {"RISKY", "NOT READY"}:
            decision = "REJECTED"
        rows.append({
            "recovery_point": item["backup_id"], "timestamp": item["created_at"],
            "backup_integrity": integrity, "threat_score": _clamp(point_threat),
            "anomaly_score": anomaly, "system_health": system_health,
            "recovery_safety_score": trust, "status": item["classification"],
            "decision": decision, "phase": item["phase"], "readiness": item["readiness"],
            "reasons": item["reasons"], "age_minutes": round(age_minutes, 1),
        })
    return rows


def _record_assessment(row, gate, live, activities):
    recovery_id = "REC-" + uuid.uuid4().hex[:10].upper()
    latest = (q("SELECT * FROM agent_assessments ORDER BY id DESC LIMIT 1") or [None])[0]
    if latest and all(str(latest.get(key)) == str(row.get(key)) for key in ("recovery_point", "recovery_safety_score", "decision")):
        return latest["recovery_id"]
    reason = (gate.get("reasons") or row.get("reasons") or ["No decision reason recorded"])[0]
    record = {
        "assessment_id": recovery_id, "recovery_id": recovery_id, "timestamp": now(), "recovery_point": row.get("recovery_point"),
        "backup_integrity": row.get("backup_integrity"), "threat_score": row.get("threat_score"),
        "anomaly_score": row.get("anomaly_score"), "system_health": row.get("system_health"),
        "recovery_safety_score": row.get("recovery_safety_score"), "agent_decision": gate.get("decision"),
        "decision_reason": reason, "status": row.get("status"),
    }
    ex("""INSERT INTO agent_assessments(recovery_id,timestamp,recovery_point,backup_integrity,threat_score,
       anomaly_score,system_health,recovery_safety_score,agent_decision,decision_reason,status)
       VALUES(?,?,?,?,?,?,?,?,?,?,?)""", tuple(record[key] for key in ("recovery_id", "timestamp", "recovery_point", "backup_integrity", "threat_score", "anomaly_score", "system_health", "recovery_safety_score", "agent_decision", "decision_reason", "status")))
    record["telemetry"] = str(live.get("telemetry", {}))
    record["agent_states"] = str(activities)
    put_assessment(record)
    return recovery_id


def _activity(activities, agent_name, status, action, confidence, decision):
    latest = (q("SELECT * FROM agent_activity WHERE agent_name=? ORDER BY id DESC LIMIT 1", (agent_name,)) or [None])[0]
    if not latest or (latest["status"], latest["action"], latest.get("decision")) != (status, action, decision):
        ex("INSERT INTO agent_activity(timestamp,agent_name,status,action,confidence,decision) VALUES(?,?,?,?,?,?)",
           (now(), agent_name, status, action, confidence, decision))
    activities.append({"timestamp": now(), "agent_name": agent_name, "status": status, "action": action,
                       "confidence": confidence, "decision": decision})


def evaluate(live):
    gate = readiness.decide()
    rows = _assessment_rows(gate, live)
    selected = next((row for row in rows if row["recovery_point"] == gate.get("recommended")), None)
    selected = selected or (rows[0] if rows else None)
    activities = []
    cloudwatch = live.get("cloudwatch", {})
    _activity(activities, "Monitoring Agent", "ACTIVE", f"CloudWatch: {cloudwatch.get('status', 'UNAVAILABLE')}", 96 if cloudwatch.get("status") == "CONNECTED" else None, cloudwatch.get("status"))
    threat = _threat_score(live)
    _activity(activities, "Threat Detection Agent", "ANALYZING", f"Threat score {threat:.0f}/100", _clamp(100 - threat), "ANALYZING")
    safety = selected["recovery_safety_score"] if selected else 0
    _activity(activities, "Recovery Assessment Agent", "EVALUATING", f"Safety score {safety:.0f}/100", safety, gate.get("decision"))
    _activity(activities, "Recovery Point Selection Agent", "SELECTED" if gate.get("recommended") else "REJECTED", gate.get("recommended") or "No eligible recovery point", safety, gate.get("decision"))
    _activity(activities, "Recovery Execution Agent", "WAITING FOR APPROVAL", "Authorization-controlled execution", safety, gate.get("decision"))
    latest_recovery = (q("SELECT * FROM recovery_history ORDER BY id DESC LIMIT 1") or [None])[0]
    recovery_status = latest_recovery.get("status") if latest_recovery else None
    _activity(activities, "Recovery Verification Agent", recovery_status or "PENDING", "Waiting for recovery execution" if not recovery_status else "Recovery result observed", None, recovery_status or "PENDING")
    recovery_id = _record_assessment(selected or {}, gate, live, activities) if selected else None
    raw_reasons = gate.get("reasons")
    gate_reasons = [str(reason) for reason in raw_reasons] if isinstance(raw_reasons, list) else []
    pipeline = [
        {"stage": "CloudWatch Monitoring", "state": cloudwatch.get("status", "UNAVAILABLE"), "input": "Configured AWS metrics and alarms", "decision": cloudwatch.get("alarm_status", "NOT_CONFIGURED"), "reason": ", ".join(cloudwatch.get("active_alarms", [])) or "No active alarm recorded", "timestamp": cloudwatch.get("latest_timestamp") or now()},
        {"stage": "Anomaly Detection", "state": live.get("cyber", {}).get("status", "NOT_RUN"), "input": f"{live.get('cyber', {}).get('records_analyzed', 0)} records", "decision": f"{live.get('anomaly_count', 0)} anomalies", "reason": "Isolation Forest output", "timestamp": live.get("updated_at")},
        {"stage": "Threat Assessment", "state": "ANALYZING", "input": f"Threat score {threat:.0f}/100", "decision": live.get("security_state", "UNKNOWN"), "reason": "Active cyber events, cyber risk, and fused risk", "timestamp": live.get("updated_at")},
        {"stage": "Recovery Point Assessment", "state": "EVALUATING", "input": f"{len(rows)} recovery points", "decision": gate.get("decision", "NO SAFE RECOVERY POINT AVAILABLE"), "reason": "Integrity, attack phase, RPO/RTO, dependency, and environment checks", "timestamp": now()},
        {"stage": "Trust/Safety Score", "state": "CALCULATED", "input": "Transparent weighted evidence formula", "decision": f"{safety:.1f}/100", "reason": "30% integrity + 25% low threat + 15% low anomaly + 15% system health + 15% point reliability", "timestamp": now()},
        {"stage": "Recovery Point Selection", "state": "SELECTED" if gate.get("recommended") else "REJECTED", "input": "Eligible recovery points", "decision": gate.get("recommended") or "NONE", "reason": gate_reasons[0] if gate_reasons else "No eligible point", "timestamp": now()},
        {"stage": "Recovery Approval", "state": "WAITING FOR APPROVAL", "input": gate.get("decision", "NO SAFE RECOVERY POINT AVAILABLE"), "decision": "AUTHORIZATION REQUIRED" if gate.get("decision") != "SAFE TO RECOVER" else "READY FOR AUTHORIZATION", "reason": "Recovery remains human-authorized", "timestamp": now()},
        {"stage": "Recovery Execution", "state": "WAITING", "input": gate.get("recommended") or "No selected point", "decision": "NOT STARTED", "reason": "No destructive recovery is automatic", "timestamp": now()},
        {"stage": "Post-Recovery Verification", "state": "PENDING", "input": "Recovery result", "decision": "PENDING", "reason": "Verification begins after authorized execution", "timestamp": now()},
    ]
    return {
        "gate": gate, "recovery_points": rows, "selected": selected,
        "safety_score": safety, "safety_label": "SAFE TO RECOVER" if safety >= 80 else "REVIEW REQUIRED" if safety >= 50 else "RECOVERY BLOCKED",
        "formula": "30% integrity + 25% low threat + 15% low anomaly + 15% system health + 15% point reliability",
        "recovery_id": recovery_id, "activities": activities,
        "pipeline": pipeline,
        "history": q("SELECT * FROM agent_assessments ORDER BY id DESC LIMIT 12"),
        "dynamodb_history": recent_assessments(12),
        "activity_timeline": q("SELECT * FROM agent_activity ORDER BY id DESC LIMIT 30"),
        "telemetry_history": q("SELECT timestamp,cpu,memory,disk,network_in,network_out FROM telemetry ORDER BY id DESC LIMIT 60"),
        "anomaly_history": q("SELECT timestamp,anomaly_score,classification FROM anomaly_history ORDER BY id DESC LIMIT 60"),
        "risk_history": q("SELECT ts,score,level FROM risk_scores ORDER BY id DESC LIMIT 60"),
        "safety_history": q("SELECT timestamp,recovery_safety_score FROM agent_assessments ORDER BY id DESC LIMIT 60"),
    }


def authoritative_decision(agents):
    gate = agents.get("gate", {})
    decision = gate.get("decision", "NO SAFE RECOVERY POINT AVAILABLE")
    if decision == "SAFE TO RECOVER":
        normalized = "SAFE"
    elif decision in {"RECOVER WITH HUMAN APPROVAL", "USE EARLIER RECOVERY POINT"}:
        normalized = "REVIEW"
    else:
        normalized = "BLOCKED"
    selected = agents.get("selected") if normalized != "BLOCKED" else None
    return {
        "decision": normalized,
        "selected_recovery_point": selected.get("recovery_point") if selected else None,
        "safety_score": agents.get("safety_score", 0),
        "reason": gate.get("explanation") or "All recovery points failed safety checks",
        "gate_decision": decision,
        "assessment_timestamp": now(),
    }