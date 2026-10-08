"""Central configuration. All secrets come from environment variables."""
import os
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(BASE, ".env"))
except ImportError:
    pass
DATA = os.getenv("CRR_DATA_DIR", os.path.join(BASE, "data"))
DB_PATH = os.path.join(DATA, "recovery.db")
BACKUP_DIR = os.path.join(DATA, "backups")
RESTORE_DIR = os.path.join(DATA, "restored")
LOG_DIR = os.path.join(BASE, "logs")
STORAGE_MODE = os.getenv("STORAGE_MODE", "local").lower()
RTO_TARGET_S = int(os.getenv("RTO_TARGET_S", "300"))
RPO_TARGET_MIN = int(os.getenv("RPO_TARGET_MIN", "240"))
PRE_ATTACK_WINDOW_MIN = 10   # backups this close before an attack are "suspicious"
DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in {"1", "true", "yes", "on"}
DEMO_CYBER_CSV_PATH = os.getenv("DEMO_CYBER_CSV_PATH", os.path.join(BASE, "data", "demo", "ransomware_attack.csv"))
DEMO_RISK_ALARM_THRESHOLD = float(os.getenv("DEMO_RISK_ALARM_THRESHOLD", "35"))
for d in (DATA, BACKUP_DIR, RESTORE_DIR, LOG_DIR):
    os.makedirs(d, exist_ok=True)
