# Cyber-Aware Recovery Readiness Assessment for Cloud Disaster Recovery

Contribution: an **explainable Recovery Readiness Assessment and Decision Layer** that evaluates cyber state, backup safety,
dependency readiness, recovery-environment readiness and RTO/RPO constraints *before* recovery execution.
(Disaster recovery, ransomware detection, integrity checks, Isolation Forest and S3 backup are existing techniques, not claimed as inventions.)

## Run (Windows / VS Code)
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py          # open http://127.0.0.1:5000
python experiments\run_experiments.py   # the 6 required demonstrations
```
No AWS credentials needed (local mode is the default). Click **Load Demo Data** first.

## Architecture
modules/monitor (psutil + simulation) → risk (explainable score + IsolationForest) → backup (hash, metadata, recovery points)
→ disaster → **readiness (A–K checks, hard-failure rules, decision gate)** → recovery (restore, validate, RTO/RPO, report).

### Readiness score (100 pts)
Integrity 20 · Safety 25 · RPO 10 · RTO 10 · Dependencies 15 · Environment 15 · Controller 5.
≥80 READY, ≥60 PARTIALLY READY, ≥40 RISKY, else NOT READY. Backup created in the 10 min before an attack ("during") is capped at RISKY.
**Hard rules override scores:** integrity failed or created after attack → REJECT RECOVERY POINT; dependency/environment failure → RECOVERY BLOCKED.
Gate outputs: SAFE TO RECOVER · RECOVER WITH HUMAN APPROVAL · USE EARLIER RECOVERY POINT · REJECT RECOVERY POINT · RECOVERY BLOCKED · NO SAFE RECOVERY POINT AVAILABLE.

## AWS setup (optional)
1. Create an S3 bucket and an IAM user with `s3:PutObject/GetObject/ListBucket` on it.
2. `copy .env.example .env`, fill AWS_* values, set `STORAGE_MODE=cloud`.
3. Backups upload via `aws/s3_store.py` (`upload_backup`, `download_backup`, `list_backups`); local copy is kept, and S3 is used if the local file is missing. Never commit `.env`.

## Dashboard (screenshot descriptions)
Top: 10 KPI cards (risk, level, backup status, recovery points, disaster, readiness, recommended RP, decision, RTO, RPO).
Middle: stage buttons, decision-gate panel with reasons/evidence, per-recovery-point assessment table.
Bottom: Risk Trend, Backup Timeline, Readiness Trend charts; Backup / Recovery / Event tables.

## Database
Schema auto-created in `data/recovery.db` (see `modules/db.py`): metrics, risk_scores, cyber_events, backups, recovery_points, disasters, recovery_assessments, recovery_history, audit_logs.

## Deployment
Local: `python app.py`. Server: `pip install waitress` then `waitress-serve --port=5000 app:app`; keep `.env` outside version control.

## Viva tip
Build understanding module by module: risk.py → backup.py → readiness.py (the contribution) → recovery.py.
