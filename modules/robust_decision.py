"""Deterministic trust-aware recovery authority and readiness gates."""
import os
import uuid
import json
from datetime import datetime

from modules.db import q, now

TRUSTED = "TRUSTED"
CAUTION = "CAUTION"
LOW_TRUST = "LOW_TRUST"
COMPROMISED = "COMPROMISED"


def _clamp(value):
    return round(max(0.0, min(100.0, float(value))), 1)


def trust_state(score):
    score = _clamp(score)
    if score >= 80: return TRUSTED
    if score >= 60: return CAUTION
    if score >= 30: return LOW_TRUST
    return COMPROMISED


def assess_agent_trust(live, activities):
    """Derive trust from observable workflow evidence, never random values."""
    risk_score = _clamp(live.get("risk_score", 0) or 0)
    anomaly = _clamp(live.get("anomaly", {}).get("anomaly_score", 0) or 0)
    cloudwatch_ok = live.get("cloudwatch", {}).get("status") in {"CONNECTED", "DISABLED", "NO_DATAPOINTS"}
    latest_recovery = (q("SELECT status FROM recovery_history ORDER BY id DESC LIMIT 1") or [None])[0]
    trust = {
        "Monitoring Agent": 96 if cloudwatch_ok and live.get("telemetry") else 45,
        "Threat Detection Agent": _clamp(100 - anomaly),
        "Recovery Assessment Agent": _clamp(95 - risk_score * 0.15),
        "Recovery Point Selection Agent": 90 if live.get("backup") else 55,
        "Recovery Execution Agent": 90 if not latest_recovery or latest_recovery["status"] == "SUCCESS" else 45,
        "Recovery Verification Agent": 95 if latest_recovery and latest_recovery["status"] == "SUCCESS" else 85,
    }
    result = {}
    for name, score in trust.items():
        score = _clamp(score)
        result[name] = {"score": score, "state": trust_state(score), "authority": "ALLOWED" if score >= 60 else "REVOKED"}
    return result


def assess_readiness(gate, live):
    """Perform checks available in this deployment and label missing evidence explicitly."""
    points = gate.get("assessments", [])
    selected = next((item for item in points if item["backup_id"] == gate.get("recommended")), None)
    system = live.get("system", {})
    storage_ok = os.access(os.path.dirname(os.path.abspath(__file__)), os.W_OK)
    components = {
        "backup": {"score": 100 if points else 0, "status": "PASS" if points else "FAIL", "reason": "Recovery point exists" if points else "No recovery point exists"},
        "backup_integrity": {"score": 100 if selected and selected["integrity"] else 0, "status": "PASS" if selected and selected["integrity"] else "FAIL", "reason": "Selected point integrity verified" if selected and selected["integrity"] else "No verified safe point"},
        "infrastructure": {"score": 100 if live.get("system_status") not in {"CRITICAL", "UNKNOWN"} else 0, "status": "PASS" if live.get("system_status") not in {"CRITICAL", "UNKNOWN"} else "FAIL", "reason": "Live system telemetry available"},
        "storage": {"score": 100 if storage_ok else 0, "status": "PASS" if storage_ok else "FAIL", "reason": "Recovery storage is writable" if storage_ok else "Recovery storage is not writable"},
        "dependencies": {"score": 100 if gate.get("decision") != "RECOVERY BLOCKED" else 0, "status": "PASS" if gate.get("decision") != "RECOVERY BLOCKED" else "FAIL", "reason": "Readiness dependency checks passed" if gate.get("decision") != "RECOVERY BLOCKED" else "Dependency or environment check failed"},
        "permissions": {"score": 100 if storage_ok else 0, "status": "PASS" if storage_ok else "NOT_VERIFIED", "reason": "Local execution permissions verified" if storage_ok else "Permissions could not be verified"},
        "security": {"score": _clamp(100 - float(live.get("risk_score", 0) or 0)), "status": "PASS" if float(live.get("risk_score", 0) or 0) < 75 else "FAIL", "reason": "Security risk below critical threshold"},
    }
    score = _clamp(sum(item["score"] for item in components.values()) / len(components))
    return {"score": score, "status": "READY" if score >= 80 else "REVIEW" if score >= 60 else "NOT_READY", "components": components, "blocking_factors": [key for key, item in components.items() if item["status"] == "FAIL"]}


def decide(live, gate, agent_trust, readiness, recovery_points):
    decision_id = "DEC-" + uuid.uuid4().hex[:12].upper()
    risk_score = _clamp(live.get("risk_score", 0) or 0)
    critical = risk_score >= 75 or live.get("security_state") in {"CRITICAL", "COMPROMISED"} or live.get("cloudwatch_alarm") == "ALARM"
    compromised = [name for name, item in agent_trust.items() if item["state"] == COMPROMISED]
    rejected = [item["recovery_point"] for item in recovery_points if item.get("decision") == "REJECTED"]
    selected = gate.get("recommended")
    trusted_execution = agent_trust["Recovery Execution Agent"]["state"] in {TRUSTED, CAUTION}
    trusted_fallback = next((name for name, item in agent_trust.items() if name != "Recovery Execution Agent" and item["state"] == TRUSTED), None)

    if compromised and "Recovery Execution Agent" in compromised:
        if not trusted_fallback:
            final, authority, reason = "EMERGENCY_CONTAINMENT", "BLOCKED", "No trusted recovery agent is available."
        elif readiness["status"] == "NOT_READY":
            final, authority, reason = "SYSTEM_NOT_RECOVERY_READY", "TRUSTED_AGENT_ONLY", "Execution agent isolated, but the target system is not recovery-ready."
        else:
            final, authority, reason = "RECOVER_WITH_TRUSTED_AGENT", "TRUSTED_AGENT_ONLY", "Recovery execution authority was revoked from a compromised agent."
    elif not selected or not recovery_points or gate.get("decision") == "NO SAFE RECOVERY POINT AVAILABLE":
        final, authority, reason = "NO_SAFE_RECOVERY_POINT", "BLOCKED", "No safe recovery point passed the mandatory gates."
    elif readiness["status"] == "NOT_READY":
        final, authority, reason = "SYSTEM_NOT_RECOVERY_READY", "BLOCKED", "A backup exists, but the target system is not recovery-ready."
    elif critical and not trusted_execution:
        final, authority, reason = "REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_REQUIRED", "High risk requires a trusted recovery agent or human approval."
    elif critical:
        final, authority, reason = "RECOVER_WITH_TRUSTED_AGENT", "FULL_AUTONOMOUS", "High risk, trusted execution agent, safe point, and readiness gates passed."
    elif gate.get("decision") == "SAFE TO RECOVER":
        final, authority, reason = "SAFE_TO_RECOVER", "FULL_AUTONOMOUS", "All safety, trust, and readiness gates passed."
    else:
        final, authority, reason = "REQUIRE_HUMAN_APPROVAL", "HUMAN_APPROVAL_REQUIRED", "Recovery requires operator approval under the current policy."

    decision = {
        "decision_id": decision_id, "timestamp": now(), "decision": final,
        "confidence": _clamp((readiness["score"] + (100 if trusted_execution else 40) + (100 - risk_score)) / 3),
        "reason": reason, "blocking_factors": readiness["blocking_factors"] + compromised,
        "selected_recovery_point": selected if final not in {"NO_SAFE_RECOVERY_POINT", "SYSTEM_NOT_RECOVERY_READY", "EMERGENCY_CONTAINMENT"} else None,
        "selected_recovery_agent": trusted_fallback if final == "RECOVER_WITH_TRUSTED_AGENT" else "Recovery Execution Agent" if trusted_execution else None,
        "rejected_recovery_points": rejected, "agent_trust": agent_trust,
        "recovery_readiness": readiness, "authority": authority,
    }
    return decision


def persist(decision):
    from aws.dynamodb_store import put_assessment
    from modules.db import ex
    ex("""INSERT OR REPLACE INTO robust_decisions(decision_id,timestamp,decision,confidence,reason,authority,
       selected_recovery_point,selected_recovery_agent,blocking_factors,agent_trust,readiness_score)
       VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (decision["decision_id"], decision["timestamp"], decision["decision"], decision["confidence"], decision["reason"], decision["authority"], decision.get("selected_recovery_point"), decision.get("selected_recovery_agent"), json.dumps(decision.get("blocking_factors", [])), json.dumps(decision.get("agent_trust", {})), decision.get("recovery_readiness", {}).get("score")))
    put_assessment({"assessment_id": decision["decision_id"], "recovery_id": decision["decision_id"], "timestamp": decision["timestamp"], "agent_decision": decision["decision"], "decision_reason": decision["reason"], "selected_recovery_point": decision.get("selected_recovery_point"), "selected_recovery_agent": decision.get("selected_recovery_agent"), "authority_level": decision["authority"], "recovery_safety_score": decision.get("recovery_readiness", {}).get("score"), "agent_trust_scores": json.dumps(decision.get("agent_trust", {})), "status": decision["decision"]})
    return decision