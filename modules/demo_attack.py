"""Safe, explicit ransomware-like anomaly demonstration."""
import os
import uuid

from config.settings import DEMO_CYBER_CSV_PATH, DEMO_RISK_ALARM_THRESHOLD
from modules import risk
from modules.db import ex, now


def trigger(upload_s3=False):
    if not os.path.exists(DEMO_CYBER_CSV_PATH):
        raise FileNotFoundError(f"Demo CSV not found: {DEMO_CYBER_CSV_PATH}")
    analysis = risk.analyze_cyber_csv(DEMO_CYBER_CSV_PATH)
    high_risk = analysis["anomaly_percentage"] >= DEMO_RISK_ALARM_THRESHOLD and analysis["anomalies_detected"] >= 5
    alarm_id = "ALARM-" + uuid.uuid4().hex[:10].upper()
    severity = "critical" if high_risk else "medium"
    detail = (
        f"DEMO / SIMULATED EVENT: Isolation Forest detected abnormal behavior in {analysis['anomalies_detected']} "
        f"of {analysis['records_analyzed']} telemetry records; anomaly rate {analysis['anomaly_percentage']}%."
    )
    ex("INSERT INTO cyber_events(ts,category,type,severity,detail) VALUES(?,?,?,?,?)",
       (now(), "cyber", "ransomware_like_behavior", severity, detail))
    s3 = {"uploaded": False, "status": "NOT_REQUESTED"}
    if upload_s3:
        try:
            from aws.s3_store import upload_demo_file
            upload_demo_file(DEMO_CYBER_CSV_PATH, "demo/ransomware_attack.csv")
            s3 = {"uploaded": True, "status": "UPLOADED", "object_key": "demo/ransomware_attack.csv"}
        except Exception:
            s3 = {"uploaded": False, "status": "UNAVAILABLE", "message": "S3 upload failed; local demo analysis was retained."}
    return {
        "alarm_id": alarm_id, "alarm": high_risk, "severity": severity,
        "reason": detail, "analysis": analysis, "s3": s3,
        "recovery_action": "RUN RECOVERY ASSESSMENT; NO AUTOMATIC RECOVERY",
    }