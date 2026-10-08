"""CORE CONTRIBUTION: Recovery Readiness Assessment + Recovery Decision Gate."""
import os, json, shutil
from datetime import datetime
from config.settings import DATA, BACKUP_DIR, RTO_TARGET_S, RPO_TARGET_MIN, PRE_ATTACK_WINDOW_MIN
from modules.db import q, ex, now, audit
from modules.backup import verify_integrity, inspect_recovery_folder

def _dt(s): return datetime.fromisoformat(s)

def attack_start():
    r = q("SELECT ts FROM cyber_events WHERE category='cyber' AND resolved=0 AND severity IN ('high','critical') ORDER BY ts LIMIT 1")
    return _dt(r[0]["ts"]) if r else None

def phase(created, T):
    """Before / During (pre-attack suspicious window) / After attack."""
    if T is None: return "clean"
    d = (created - T).total_seconds() / 60
    if d >= 0: return "after"
    return "during" if d >= -PRE_ATTACK_WINDOW_MIN else "before"

def context():
    act = {d["type"]: d for d in q("SELECT * FROM disasters WHERE status='active'")}
    dep_ok, dep_msg = True, "database, backup store, pandas available"
    try:
        q("SELECT 1")
        if not os.access(BACKUP_DIR, os.W_OK): raise OSError("backup dir not writable")
    except Exception as e:
        dep_ok, dep_msg = False, str(e)
    if "dependency failure" in act: dep_ok, dep_msg = False, "dependency failure reported (service/db/network dependency down)"
    env_ok, env_msg = True, "recovery environment has free disk and is reachable"
    if shutil.disk_usage(DATA).free < 50 * 1024 * 1024: env_ok, env_msg = False, "insufficient free disk"
    if "recovery environment failure" in act: env_ok, env_msg = False, "recovery environment failure reported"
    ctrl_ok = "system failure" not in act
    last = q("SELECT level,anomaly FROM risk_scores ORDER BY id DESC LIMIT 1")
    return dict(dep_ok=dep_ok, dep_msg=dep_msg, env_ok=env_ok, env_msg=env_msg, ctrl_ok=ctrl_ok,
                ctrl_msg="controller healthy" if ctrl_ok else "controller degraded (system failure)",
                predicted=last[0] if last else None,
                ref=_dt(act[sorted(act)[0]]["ts"]) if act else datetime.now())

def assess_rp(rp, T, ctx):
    created = _dt(rp["created_at"]); ph = phase(created, T)
    integ, imsg = verify_integrity(rp["backup_id"])
    folder_safe, folder_msg = inspect_recovery_folder(rp["backup_id"])
    integ = integ and folder_safe
    if not folder_safe: imsg = folder_msg
    safety = 0 if ph == "after" else 30 if ph == "during" else max(0, 100 - rp["risk_score"] * 0.6 - rp["suspicious"] * 8)
    age = max(0, (ctx["ref"] - created).total_seconds() / 60)
    rpo_ok = age <= RPO_TARGET_MIN
    rpo_pts = 10 if rpo_ok else 10 * max(0, 1 - (age - RPO_TARGET_MIN) / RPO_TARGET_MIN)
    est_rto = 5 + (rp["size"] / 1048576) * 2
    rto_ok = est_rto <= RTO_TARGET_S
    s = 20 * integ + 25 * safety / 100 + rpo_pts + (10 if rto_ok else 0) + 15 * ctx["dep_ok"] + 15 * ctx["env_ok"] + 5 * ctx["ctrl_ok"]
    reasons = [f"Integrity: {imsg}", f"Attack phase: {ph} (safety score {safety:.0f}/100)",
               f"RPO: backup age {age:.0f} min vs target {RPO_TARGET_MIN} -> {'OK' if rpo_ok else 'EXCEEDED'}",
               f"RTO: estimated {est_rto:.1f}s vs target {RTO_TARGET_S}s -> {'OK' if rto_ok else 'EXCEEDED'}",
               f"Dependencies: {ctx['dep_msg']}", f"Environment: {ctx['env_msg']}", f"Controller: {ctx['ctrl_msg']}"]
    if ctx["predicted"]: reasons.append(f"Predicted condition: risk {ctx['predicted']['level']}, behaviour {ctx['predicted']['anomaly']}")
    if ph == "during": s = min(s, 55); reasons.append("Created inside pre-attack window -> readiness capped (suspicious)")
    hard = None
    if not integ or ph == "after": hard = "REJECT RECOVERY POINT"
    elif not ctx["dep_ok"] or not ctx["env_ok"]: hard = "RECOVERY BLOCKED"
    s = round(s, 1)
    cls = "NOT READY" if hard else "READY" if s >= 80 else "PARTIALLY READY" if s >= 60 else "RISKY" if s >= 40 else "NOT READY"
    ex("INSERT INTO recovery_assessments(ts,backup_id,readiness,classification,hard_failure,details) VALUES(?,?,?,?,?,?)",
       (now(), rp["backup_id"], s, cls, hard, json.dumps(reasons)))
    return dict(backup_id=rp["backup_id"], created_at=rp["created_at"], phase=ph, integrity=bool(integ), safety=round(safety),
                readiness=s, classification=cls, hard_failure=hard, reasons=reasons)

def decide():
    """Recovery Decision Gate. Hard-failure rules override numeric scores."""
    ctx = context(); T = attack_start()
    rps = q("SELECT r.*, b.size FROM recovery_points r JOIN backups b ON b.backup_id=r.backup_id ORDER BY r.created_at DESC")
    A = [assess_rp(r, T, ctx) for r in rps]
    out = dict(assessments=A, recommended=None, readiness=0, reasons=[], evidence=[], attack_start=T.isoformat() if T else None)
    eligible = [a for a in A if not a["hard_failure"] and a["classification"] in ("READY", "PARTIALLY READY")]
    if not A:
        d = "NO SAFE RECOVERY POINT AVAILABLE"; out["reasons"].append("No recovery points exist")
    elif not ctx["dep_ok"] or not ctx["env_ok"]:
        d = "RECOVERY BLOCKED"
        if not ctx["dep_ok"]: out["reasons"].append("Dependency readiness failed: " + ctx["dep_msg"])
        if not ctx["env_ok"]: out["reasons"].append("Recovery environment failed: " + ctx["env_msg"])
    elif not eligible:
        d = "NO SAFE RECOVERY POINT AVAILABLE"; out["reasons"].append("Every recovery point is rejected, compromised or below readiness threshold")
    else:
        best = next((a for a in eligible if a["classification"] == "READY"), eligible[0])
        out["recommended"] = best["backup_id"]; out["readiness"] = best["readiness"]
        newest = A[0]
        anomalous = bool(ctx["predicted"]) and ctx["predicted"]["anomaly"] == "anomalous" and ctx["predicted"]["level"] in ("High", "Critical")
        if newest is best and best["classification"] == "READY" and ctx["ctrl_ok"] and not anomalous:
            d = "SAFE TO RECOVER"; out["reasons"].append("Newest recovery point passed every check")
        elif newest is best:
            d = "RECOVER WITH HUMAN APPROVAL"; out["reasons"].append("Point is usable but needs operator confirmation (partial readiness, degraded controller or anomalous predicted state)")
        elif not newest["integrity"]:
            d = "REJECT RECOVERY POINT"; out["reasons"].append(f"Newest point {newest['backup_id']} failed integrity; fallback available: {best['backup_id']}")
        else:
            d = "USE EARLIER RECOVERY POINT"; out["reasons"].append(f"Newest point {newest['backup_id']} is {newest['classification']} ({newest['phase']}-attack); use {best['backup_id']}")
    out["decision"] = d
    for a in A[:5]: out["evidence"].append(f"{a['backup_id']}: {a['classification']} ({a['readiness']}) " + "; ".join(a["reasons"][:2]))
    out["explanation"] = f"Decision '{d}'. " + " ".join(out["reasons"])
    audit("GATE", json.dumps({k: out[k] for k in ("decision", "recommended", "readiness", "reasons")}))
    return out
