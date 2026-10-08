"""Local/S3 backups, integrity hash, recovery points, backup decision."""
import os, json, hashlib, uuid, logging
import pandas as pd
from datetime import datetime
from config.settings import BACKUP_DIR, STORAGE_MODE
from modules.db import q, ex, now, audit
log = logging.getLogger(__name__)

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
    return h.hexdigest()

def create_backup(risk_score=0.0, suspicious=0, created_at=None):
    ts = created_at or now()
    bid = "BKP-" + datetime.fromisoformat(ts).strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    folder = os.path.join(BACKUP_DIR, bid); os.makedirs(folder, exist_ok=True)
    payload = os.path.join(folder, "payload.csv")
    df = pd.DataFrame(q("SELECT * FROM metrics"))
    (df if not df.empty else pd.DataFrame({"note": ["empty-system-snapshot"]})).to_csv(payload, index=False)
    h = sha256_file(payload)
    meta = dict(backup_id=bid, timestamp=ts, risk_score=risk_score, sha256=h)
    with open(os.path.join(folder, "metadata.json"), "w") as f: json.dump(meta, f, indent=2)
    storage = "local"
    if STORAGE_MODE == "cloud":
        try:
            from aws.s3_store import upload_backup; upload_backup(bid, folder); storage = "s3"
        except Exception as e:
            log.error("S3 upload failed, kept local: %s", e)
    ex("INSERT INTO backups(backup_id,created_at,risk_score,sha256,path,storage,size,status) VALUES(?,?,?,?,?,?,?,?)",
       (bid, ts, risk_score, h, folder, storage, os.path.getsize(payload), "ok"))
    ex("INSERT INTO recovery_points(backup_id,created_at,risk_score,suspicious) VALUES(?,?,?,?)", (bid, ts, risk_score, suspicious))
    audit("BACKUP", bid)
    return meta

def verify_integrity(backup_id):
    b = q("SELECT * FROM backups WHERE backup_id=?", (backup_id,))
    if not b: return False, "backup record missing"
    p = os.path.join(b[0]["path"], "payload.csv")
    if not os.path.exists(p) and b[0]["storage"] == "s3":
        try:
            from aws.s3_store import download_backup; download_backup(backup_id, b[0]["path"])
        except Exception as e: return False, f"cannot fetch from S3: {e}"
    if not os.path.exists(p): return False, "payload file missing"
    actual = sha256_file(p)
    return (actual == b[0]["sha256"]), ("hash matches" if actual == b[0]["sha256"] else "HASH MISMATCH (tampered/corrupt)")


def inspect_recovery_folder(backup_id):
    """Scan a recovery folder before assessment; never modify the folder."""
    rows = q("SELECT path FROM backups WHERE backup_id=?", (backup_id,))
    if not rows: return False, "recovery folder missing"
    folder = rows[0]["path"]
    suspicious_names = ("ransom", "encrypted", ".locked", "decrypt", "attacker")
    for root, _, files in os.walk(folder):
        for name in files:
            if any(marker in name.lower() for marker in suspicious_names):
                return False, f"suspicious recovery artifact detected: {name}"
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) <= 2_000_000:
                    content = open(path, "rb").read().lower()
                    if any(marker.encode() in content for marker in ("encrypted-by-attacker", "ransomware", "decrypt files")):
                        return False, f"suspicious recovery content detected: {name}"
            except OSError:
                return False, f"recovery artifact could not be inspected: {name}"
    return True, "recovery folder scan passed"

def tamper_backup(backup_id):
    b = q("SELECT path FROM backups WHERE backup_id=?", (backup_id,))
    with open(os.path.join(b[0]["path"], "payload.csv"), "ab") as f: f.write(b"\n#ENCRYPTED-BY-ATTACKER#")
    audit("TAMPER", backup_id)

def decide_backup(level):
    from modules.risk import DECISIONS
    return DECISIONS[level]
