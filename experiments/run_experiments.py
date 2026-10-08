"""Runs the 6 required experiments on an isolated temp database."""
import os, sys, tempfile
from datetime import datetime, timedelta
os.environ["CRR_DATA_DIR"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import db, seed, readiness, disaster
db.init_db()
H = lambda **k: datetime.now() - timedelta(**k)

def exp2(): seed.insert_attack(H(minutes=55)); db.ex("INSERT INTO disasters(ts,type,status,detail) VALUES(?,?,?,?)", (db.now(), "ransomware attack", "active", ""))
def exp6(): seed.insert_attack(H(hours=4)); db.ex("INSERT INTO disasters(ts,type,status,detail) VALUES(?,?,?,?)", (db.now(), "ransomware attack", "active", ""))
CASES = [("1 Healthy backup available", lambda: None, "SAFE TO RECOVER"),
         ("2 Latest recovery point suspicious", exp2, "USE EARLIER RECOVERY POINT"),
         ("3 Backup tampering", lambda: disaster.simulate("backup tampering"), "REJECT RECOVERY POINT"),
         ("4 Dependency failure", lambda: disaster.simulate("dependency failure"), "RECOVERY BLOCKED"),
         ("5 Recovery environment failure", lambda: disaster.simulate("recovery environment failure"), "RECOVERY BLOCKED"),
         ("6 No safe recovery point", exp6, "NO SAFE RECOVERY POINT AVAILABLE")]
passed = 0
for name, setup, expected in CASES:
    seed.reset_all(); seed.baseline(); setup(); g = readiness.decide()
    good = g["decision"] == expected; passed += good
    print(f"[{'PASS' if good else 'FAIL'}] Experiment {name}\n   decision={g['decision']} recommended={g['recommended']} readiness={g['readiness']}\n   {g['explanation']}")
print(f"\n{passed}/{len(CASES)} experiments passed")
