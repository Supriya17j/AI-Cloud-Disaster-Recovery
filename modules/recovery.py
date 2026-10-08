"""Recovery execution: restore, validate, dependency check, RTO/RPO, report."""
import os, json, shutil, time, logging
import pandas as pd
from datetime import datetime
from config.settings import RESTORE_DIR, LOG_DIR, RTO_TARGET_S
from modules.db import q, ex, now, audit
from modules.backup import sha256_file
from modules import readiness, disaster
log = logging.getLogger(__name__)

def execute(backup_id=None, approved=False):
    t0 = time.time(); gate = readiness.decide(); d = gate["decision"]
    if d not in ("SAFE TO RECOVER", "RECOVER WITH HUMAN APPROVAL", "USE EARLIER RECOVERY POINT"):
        return dict(ok=False, message=f"Recovery refused by gate: {d}", gate=gate)
    if d != "SAFE TO RECOVER" and not approved:
        return dict(ok=False, message=f"Decision '{d}' requires human approval (tick the approval box)", gate=gate)
    target = backup_id or gate["recommended"]
    ok_ids = [a["backup_id"] for a in gate["assessments"] if not a["hard_failure"] and a["classification"] in ("READY", "PARTIALLY READY")]
    if target not in ok_ids:
        return dict(ok=False, message=f"{target} is not an eligible recovery point", gate=gate)
    b = q("SELECT * FROM backups WHERE backup_id=?", (target,))[0]
    dest = os.path.join(RESTORE_DIR, target + "_" + datetime.now().strftime("%H%M%S")); os.makedirs(dest, exist_ok=True)
    shutil.copy(os.path.join(b["path"], "payload.csv"), dest)                       # 1. restore
    valid = sha256_file(os.path.join(dest, "payload.csv")) == b["sha256"]          # 2. validate restore
    try: rows = len(pd.read_csv(os.path.join(dest, "payload.csv"))); deps = True   # 3. dependency check
    except Exception: rows, deps = 0, False
    ctx = readiness.context(); deps = deps and ctx["dep_ok"]
    ref = ctx["ref"]; rto = (datetime.now() - ref).total_seconds() + 0 if q("SELECT 1 FROM disasters WHERE status='active'") else time.time() - t0
    rpo = max(0, (ref - datetime.fromisoformat(b["created_at"])).total_seconds() / 60)
    status = "SUCCESS" if valid and deps else "FAILED"
    report = dict(backup_id=target, gate_decision=d, restore_valid=valid, dependencies_ok=deps, rows_restored=rows,
                  rto_seconds=round(rto, 2), rto_target=RTO_TARGET_S, rto_met=rto <= RTO_TARGET_S,
                  rpo_minutes=round(rpo, 1), status=status, generated=now())
    rp = os.path.join(LOG_DIR, f"recovery_report_{target}.json")
    with open(rp, "w") as f: json.dump(report, f, indent=2)
    ex("INSERT INTO recovery_history(ts,backup_id,rto_s,rpo_min,status,report_path) VALUES(?,?,?,?,?,?)",
       (now(), target, report["rto_seconds"], report["rpo_minutes"], status, rp))
    if status == "SUCCESS": disaster.resolve_all()
    audit("RECOVERY", report)
    return dict(ok=status == "SUCCESS", message=f"Recovery {status} from {target}", report=report, gate=gate)
