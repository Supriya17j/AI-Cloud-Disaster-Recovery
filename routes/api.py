"""REST endpoints used by the dashboard."""
import json, logging, os, tempfile
from flask import Blueprint, jsonify, request
from config.settings import DEMO_MODE, RTO_TARGET_S, RPO_TARGET_MIN
from modules.db import q, audit
from modules import monitor, risk, backup, disaster, readiness, recovery, seed, live_monitor, agent_workflow, robust_decision
from modules import demo_attack
bp = Blueprint("api", __name__, url_prefix="/api")
log = logging.getLogger(__name__)

def ok(msg, **kw): return jsonify(dict(ok=True, message=msg, **kw))

@bp.get("/recovery/live")
def recovery_live():
    return jsonify(ok=True, **live_monitor.collect())

@bp.get("/dashboard/live")
def dashboard_live():
    live, agents, decision, robust = _robust_contract()
    return jsonify(ok=True, live=live, agents=agents, decision=decision, robust_decision=robust, demo_mode=DEMO_MODE)

def _live_contract():
    live = live_monitor.collect()
    agents = agent_workflow.evaluate(live)
    return live, agents, agent_workflow.authoritative_decision(agents)

def _robust_contract():
    live = live_monitor.collect()
    agents = agent_workflow.evaluate(live)
    trust = robust_decision.assess_agent_trust(live, agents["activities"])
    readiness_state = robust_decision.assess_readiness(agents["gate"], live)
    robust = robust_decision.decide(live, agents["gate"], trust, readiness_state, agents["recovery_points"])
    robust_decision.persist(robust)
    agents["agent_trust"] = trust
    agents["recovery_readiness"] = readiness_state
    decision = agent_workflow.authoritative_decision(agents)
    decision.update({"decision": robust["decision"], "selected_recovery_point": robust["selected_recovery_point"], "safety_score": agents["safety_score"], "gate_decision": robust["decision"], "reason": robust["reason"]})
    return live, agents, decision, robust

@bp.get("/recovery-decision")
def recovery_decision():
    _, _, _, robust = _robust_contract()
    return jsonify(ok=True, **robust)

@bp.get("/telemetry")
def telemetry():
    live, _, _ = _live_contract()
    return jsonify(ok=True, telemetry=live.get("telemetry", {}), cloudwatch=live.get("cloudwatch", {}), history=q("SELECT * FROM telemetry ORDER BY id DESC LIMIT 60"))

@bp.get("/ai-detection")
def ai_detection_status():
    live, agents, decision, robust = _robust_contract()
    return jsonify(ok=True, anomaly=live.get("anomaly", {}), cyber=live.get("cyber", {}), live=live, agent=next((item for item in agents["activities"] if item["agent_name"] == "Threat Detection Agent"), {}), decision=decision, robust_decision=robust)

@bp.get("/risk-status")
def risk_status():
    live, agents, decision, robust = _robust_contract()
    risk_factors = live.get("risk_factors", {}) or {}
    dominant_source = max(risk_factors.items(), key=lambda item: float(item[1] or 0))[0] if risk_factors else "none"
    analysis = {
        "overall_risk": live.get("risk_score"), "severity": live.get("risk_level"),
        "weather_risk": live.get("weather", {}).get("weather_risk_score", 0),
        "cyber_risk": live.get("cyber", {}).get("cyber_risk_score", 0),
        "system_risk": live.get("system", {}).get("system_risk_score", 0),
        "weather": live.get("weather", {}), "cyber": live.get("cyber", {}),
        "system": live.get("system", {}), "risk_factors": live.get("risk_factors", {}),
        "dominant_source": dominant_source,
        "model": live.get("anomaly", {}).get("model", "Isolation Forest"),
        "model_status": live.get("anomaly", {}).get("classification", "WARMING_UP"),
        "processing_time_seconds": 0, "risk_evidence": [live.get("anomaly", {}).get("explanation", "No anomaly explanation available.")],
    }
    return jsonify(ok=True, risk={"score": live.get("risk_score"), "level": live.get("risk_level"), "factors": live.get("risk_factors")}, analysis=analysis, decision=decision, robust_decision=robust, history=agents.get("risk_history", []))

@bp.get("/agent-status")
def agent_status():
    live, agents, decision, robust = _robust_contract()
    return jsonify(ok=True, agents=agents, decision=decision, robust_decision=robust, updated_at=live.get("updated_at"))

@bp.errorhandler(Exception)
def err(e):
    log.exception("API error"); return jsonify(ok=False, message=str(e)), 500

@bp.get("/state")
def state():
    live, agents, authoritative, robust = _robust_contract()
    r = (q("SELECT * FROM risk_scores ORDER BY id DESC LIMIT 1") or [None])[0]
    gate = agents["gate"]
    r = dict(r or {}, score=live.get("risk_score"), level=live.get("risk_level"), anomaly=live.get("anomaly", {}).get("classification"), decision=live.get("risk_level"))
    rh = (q("SELECT * FROM recovery_history ORDER BY id DESC LIMIT 1") or [None])[0]
    act = disaster.active()
    metric = live.get("telemetry") or (q("SELECT * FROM metrics ORDER BY id DESC LIMIT 1") or [None])[0]
    event_filter = "" if DEMO_MODE else " WHERE detail NOT LIKE 'Simulated%' AND detail NOT LIKE 'DEMO%'"
    last_event = (q(f"SELECT * FROM cyber_events{event_filter} ORDER BY id DESC LIMIT 1") or [None])[0]
    latest_backup = (q("SELECT backup_id,created_at,risk_score,storage,status FROM backups ORDER BY created_at DESC LIMIT 1") or [None])[0]
    latest_assessment = (q("SELECT * FROM recovery_assessments ORDER BY id DESC LIMIT 1") or [None])[0]
    cards = {"Current Risk Score": r["score"] if r else "-", "Risk Level": r["level"] if r else "-",
             "Backup Status": (q("SELECT status FROM backups ORDER BY id DESC LIMIT 1") or [{"status": "none"}])[0]["status"],
             "Recovery Points": q("SELECT COUNT(*) n FROM recovery_points")[0]["n"],
             "Disaster Status": ", ".join(d["type"] for d in act) or "None",
             "Readiness Score": gate.get("readiness", "-"), "Recommended Recovery Point": gate.get("recommended") or "-",
             "Recovery Decision": gate.get("decision", "-"), "RTO (s)": rh["rto_s"] if rh else "-", "RPO (min)": rh["rpo_min"] if rh else "-"}
    asm = q("SELECT * FROM recovery_assessments ORDER BY id DESC LIMIT 6")
    parsed_asm = [dict(a, details=json.loads(a["details"])) for a in asm]
    selected_assessment = next((a for a in parsed_asm if a["backup_id"] == gate.get("recommended")), parsed_asm[0] if parsed_asm else None)
    risk_reasons = json.loads(r["reasons"]) if r and r.get("reasons") else []
    recovery_points = q("""SELECT r.backup_id,r.created_at,r.risk_score,r.suspicious,b.status,b.storage,b.size
                           FROM recovery_points r LEFT JOIN backups b ON b.backup_id=r.backup_id
                           ORDER BY r.created_at DESC LIMIT 20""")
    selected_backup = None
    if gate.get("recommended"):
        rows = q("SELECT backup_id,created_at,risk_score,storage,status,size FROM backups WHERE backup_id=?", (gate["recommended"],))
        selected_backup = rows[0] if rows else None
    risk_analysis = risk.get_current_risk_analysis()
    return jsonify(cards=cards, gate=gate, latest_metric=metric, latest_risk=r, risk_reasons=risk_reasons,
        latest_event=last_event, latest_backup=latest_backup, latest_assessment=latest_assessment,
        selected_assessment=selected_assessment, selected_backup=selected_backup,
        active_disasters=act, recovery_points=recovery_points,
        targets={"rto_s": RTO_TARGET_S, "rpo_min": RPO_TARGET_MIN},
        assessment=parsed_asm,
        backups=q("SELECT backup_id,created_at,risk_score,storage,status FROM backups ORDER BY created_at DESC LIMIT 15"),
        recoveries=q("SELECT ts,backup_id,rto_s,rpo_min,status FROM recovery_history ORDER BY id DESC LIMIT 10"),
        events=q("SELECT ts,category,type,severity,detail FROM cyber_events ORDER BY id DESC LIMIT 15"),
        risk_trend=q("SELECT ts,score FROM (SELECT * FROM risk_scores ORDER BY id DESC LIMIT 30) ORDER BY id"),
        backup_timeline=q("SELECT created_at ts,risk_score score FROM backups ORDER BY created_at LIMIT 30"),
        readiness_trend=q("SELECT ts,readiness score FROM (SELECT * FROM recovery_assessments ORDER BY id DESC LIMIT 30) ORDER BY id"),
        risk_analysis=risk_analysis, live=live, agents=agents, decision=authoritative, robust_decision=robust)

@bp.post("/collect")
def collect():
    m = monitor.collect_metrics(); r = risk.assess_risk(m); msg = f"Risk {r['score']} ({r['level']}) -> {r['decision']}"
    if r["decision"] in ("Perform Backup", "Immediate Backup"):
        raw_score, raw_suspicious = r.get("score"), m.get("suspicious")
        score = raw_score if isinstance(raw_score, (int, float)) else 0.0
        suspicious = raw_suspicious if isinstance(raw_suspicious, (int, float)) else 0
        backup.create_backup(score, int(suspicious)); msg += " | backup created"
    return ok(msg, risk=r)

@bp.post("/risk-analysis")
def risk_analysis():
    uploaded = request.files.get("cyber_csv")
    cyber_csv = None
    if uploaded and uploaded.filename:
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as temporary:
            uploaded.save(temporary.name)
            cyber_csv = temporary.name
    try:
        result = risk.assess_risk_engine(cyber_csv=cyber_csv)
        return ok("Risk analysis complete", risk=result)
    finally:
        if cyber_csv and os.path.exists(cyber_csv):
            os.remove(cyber_csv)

@bp.post("/demo/ransomware")
def demo_ransomware():
    if not DEMO_MODE: return jsonify(ok=False, message="Set DEMO_MODE=true to run the ransomware-like demo"), 403
    payload = request.get_json(silent=True) or {}
    result = demo_attack.trigger(upload_s3=bool(payload.get("upload_s3")))
    return jsonify(ok=True, message="High-risk alarm generated" if result["alarm"] else "Demo anomaly recorded", **result), 201 if result["alarm"] else 200

@bp.post("/backup")
def manual_backup():
    last = (q("SELECT score FROM risk_scores ORDER BY id DESC LIMIT 1") or [{"score": 0}])[0]["score"]
    return ok("Backup created: " + str(backup.create_backup(float(last or 0))["backup_id"]))

@bp.post("/cyber/<etype>")
def cyber(etype):
    if not DEMO_MODE: return jsonify(ok=False, message="Simulated cyber events require DEMO_MODE=true"), 403
    monitor.simulate_cyber_event(etype); return ok(f"DEMO / SIMULATED EVENT: {etype} stored")

@bp.post("/external")
def external(): monitor.add_external_event(request.json.get("type", "severe weather"), request.json.get("detail", "")); return ok("External event stored")

@bp.post("/disaster/<dtype>")
def dis(dtype):
    if not DEMO_MODE: return jsonify(ok=False, message="Simulated disasters require DEMO_MODE=true"), 403
    disaster.simulate(dtype.replace("_", " ")); return ok(f"DEMO / SIMULATED EVENT: {dtype.replace('_', ' ')}")

@bp.post("/reset-disasters")
def resolve(): disaster.resolve_all(); return ok("Disasters resolved")

@bp.post("/assess")
def assess(): g = readiness.decide(); return ok(g["decision"], gate=g)

@bp.post("/recover")
def recover():
    b = request.get_json(silent=True) or {}
    _, _, _, robust = _robust_contract()
    approved = bool(b.get("approved"))
    if robust["decision"] in {"NO_SAFE_RECOVERY_POINT", "SYSTEM_NOT_RECOVERY_READY", "EMERGENCY_CONTAINMENT", "ISOLATE_COMPROMISED_AGENT"}:
        return jsonify(ok=False, message=robust["reason"], robust_decision=robust), 403
    if robust["authority"] == "HUMAN_APPROVAL_REQUIRED" and not approved:
        return jsonify(ok=False, message="Human approval is required by the robust recovery authority policy", robust_decision=robust), 403
    r = recovery.execute(b.get("backup_id") or robust.get("selected_recovery_point"), approved)
    r["robust_decision"] = robust
    return jsonify(r)

@bp.post("/demo")
def demo():
    if not DEMO_MODE: return jsonify(ok=False, message="Set DEMO_MODE=true to load demo data"), 403
    seed.reset_all(); seed.baseline(); return ok("DEMO MODE: baseline data loaded")
