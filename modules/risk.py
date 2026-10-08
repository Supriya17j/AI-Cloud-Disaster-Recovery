"""Real-time weather, cyber, and system risk analysis."""
import json
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

import numpy as np
import pandas as pd
import psutil
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from modules.db import ex, now, q

CURRENT_RISK_ANALYSIS = {}
WEATHER_RISK_FIELDS = (
    "temperature",
    "precipitation",
    "wind_speed",
    "humidity",
    "pressure",
    "weather_condition",
    "weather_code",
)
TELEMETRY_FEATURES = ("cpu", "memory", "disk", "network_in", "network_out", "failed_logins", "suspicious", "system_health", "status_check_failed")


def clamp(value, minimum=0.0, maximum=100.0):
    return max(minimum, min(maximum, float(value)))


def severity_for(score):
    score = clamp(score)
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def calculate_fusion(weather_risk, cyber_risk, system_risk):
    weather = clamp(weather_risk)
    cyber = clamp(cyber_risk)
    system = clamp(system_risk)
    overall = weather * 0.25 + cyber * 0.45 + system * 0.30
    sources = {
        "WEATHER": weather,
        "CYBER": cyber,
        "SYSTEM": system,
    }
    dominant = max(sources, key=sources.get)
    return {
        "weather_risk": round(weather, 2),
        "cyber_risk": round(cyber, 2),
        "system_risk": round(system, 2),
        "overall_risk": round(clamp(overall), 2),
        "severity": severity_for(overall),
        "dominant_source": dominant,
        "risk_factors": {
            "weather": round(weather, 2),
            "cyber": round(cyber, 2),
            "system": round(system, 2),
        },
    }


def _normalize_weather_record(record):
    normalized = {}
    for key, value in record.items():
        lowered = str(key).strip().lower().replace(" ", "_").replace("-", "_")
        if lowered in WEATHER_RISK_FIELDS:
            normalized[lowered] = value
    return normalized


def _weather_risk_from_record(record):
    record = _normalize_weather_record(record)
    factors = {}
    temperature = record.get("temperature")
    precipitation = record.get("precipitation")
    wind_speed = record.get("wind_speed")
    humidity = record.get("humidity")
    pressure = record.get("pressure")

    if temperature is not None:
        factors["temperature"] = round(clamp(abs(float(temperature) - 20.0) / 20.0 * 100), 2)
    if precipitation is not None:
        factors["precipitation"] = round(clamp(float(precipitation) / 50.0 * 100), 2)
    if wind_speed is not None:
        factors["wind_speed"] = round(clamp(float(wind_speed) / 80.0 * 100), 2)
    if humidity is not None:
        factors["humidity"] = round(clamp(abs(float(humidity) - 50.0) / 50.0 * 100), 2)
    if pressure is not None:
        factors["pressure"] = round(clamp(abs(float(pressure) - 1013.0) / 100.0 * 100), 2)

    condition = str(record.get("weather_condition") or record.get("weather_code") or "").lower()
    condition_risk = 0
    severe_conditions = ("severe", "storm", "thunderstorm", "tornado", "flood", "warning", "critical", "emergency")
    if any(item in condition for item in severe_conditions):
        condition_risk = 100
    elif any(item in condition for item in ("rain", "snow", "cloud", "fog")):
        condition_risk = 45
    factors["condition"] = condition_risk

    available = [value for value in factors.values() if value is not None]
    weather_risk = sum(available) / len(available) if available else 0
    return round(clamp(weather_risk), 2), factors, record


def _load_weather_csv(path):
    if not path or not os.path.exists(path):
        return None
    frame = pd.read_csv(path)
    if frame.empty:
        return None
    return _normalize_weather_record(frame.iloc[-1].to_dict())


def normalize_weatherapi_payload(payload):
    current = payload.get("current", {}) if isinstance(payload, dict) else {}
    condition = current.get("condition", {}) if isinstance(current, dict) else {}
    normalized = {
        "temperature": current.get("temp_c", current.get("temperature")),
        "precipitation": current.get("precip_mm", current.get("precipitation")),
        "wind_speed": current.get("wind_kph", current.get("wind_speed")),
        "humidity": current.get("humidity"),
        "pressure": current.get("pressure_mb", current.get("pressure")),
        "weather_condition": condition.get("text") if isinstance(condition, dict) else None,
        "weather_code": condition.get("code") if isinstance(condition, dict) else None,
    }
    return {key: value for key, value in normalized.items() if value is not None}


def fetch_weather_data():
    weather_csv = os.getenv("WEATHER_CSV_PATH")
    if weather_csv and os.path.exists(weather_csv):
        return _load_weather_csv(weather_csv)

    weather_key = os.getenv("WEATHER_API_KEY")
    weather_location = os.getenv("WEATHER_LOCATION", "local")
    weather_url = os.getenv("WEATHER_API_URL")
    if weather_key:
        weather_url = "https://api.weatherapi.com/v1/forecast.json?key={}&q={}&days=1&aqi=no".format(
            weather_key, weather_location
        )
    if not weather_url:
        return None
    request = Request(weather_url, headers={"User-Agent": "CyberRecoveryRiskEngine/1.0"})
    try:
        with urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, ValueError, OSError):
        return None

    if isinstance(payload, list):
        payload = payload[-1] if payload else {}
    if isinstance(payload, dict):
        if "current" in payload:
            return normalize_weatherapi_payload(payload)
        return _normalize_weather_record(payload)
    return None


def calculate_weather_risk():
    weather = fetch_weather_data()
    if not weather:
        return {"weather_risk_score": 0, "weather_metrics": {}, "risk_factors": [], "source": "none"}
    score, factors, record = _weather_risk_from_record(weather)
    return {
        "weather_risk_score": score,
        "weather_metrics": {key: record.get(key) for key in WEATHER_RISK_FIELDS if key in record},
        "risk_factors": [
            {"factor": factor, "risk": value}
            for factor, value in factors.items()
            if value > 0
        ],
        "source": "API" if os.getenv("WEATHER_API_URL") else "CSV",
    }


def _numeric_feature_columns(frame):
    numeric_columns = []
    for column in frame.columns:
        if column.lower() in {"timestamp", "time", "date", "source_ip", "src_ip", "ip", "event_id", "id", "label", "category", "type", "severity", "status"}:
            continue
        try:
            numeric = pd.to_numeric(frame[column], errors="coerce")
            if numeric.notna().any():
                numeric_columns.append(column)
        except (TypeError, ValueError):
            continue
    return numeric_columns


def analyze_cyber_csv(csv_path):
    if not csv_path or not os.path.exists(csv_path):
        return {
            "records_uploaded": 0,
            "records_analyzed": 0,
            "anomalies_detected": 0,
            "anomaly_percentage": 0.0,
            "anomaly_score": 0.0,
            "cyber_risk_score": 0.0,
            "suspicious_records": [],
            "suspicious_timestamps": [],
            "model": "Isolation Forest",
            "status": "NO_CYBER_CSV",
            "processing_time_seconds": 0.0,
        }

    started = time.perf_counter()
    frame = pd.read_csv(csv_path)
    records_uploaded = int(len(frame))
    if records_uploaded == 0:
        return {
            "records_uploaded": 0,
            "records_analyzed": 0,
            "anomalies_detected": 0,
            "anomaly_percentage": 0.0,
            "anomaly_score": 0.0,
            "cyber_risk_score": 0.0,
            "suspicious_records": [],
            "suspicious_timestamps": [],
            "model": "Isolation Forest",
            "status": "EMPTY_CYBER_CSV",
            "processing_time_seconds": round(time.perf_counter() - started, 4),
        }

    numeric_columns = _numeric_feature_columns(frame)
    if len(numeric_columns) < 2 or len(frame) < 2:
        return {
            "records_uploaded": records_uploaded,
            "records_analyzed": int(len(frame)),
            "anomalies_detected": 0,
            "anomaly_percentage": 0.0,
            "anomaly_score": 0.0,
            "cyber_risk_score": 0.0,
            "suspicious_records": [],
            "suspicious_timestamps": [],
            "model": "Isolation Forest",
            "status": "INSUFFICIENT_NUMERIC_FEATURES",
            "processing_time_seconds": round(time.perf_counter() - started, 4),
        }

    features = frame[numeric_columns].apply(pd.to_numeric, errors="coerce").fillna(0).to_numpy(dtype=float)
    scaled = StandardScaler().fit_transform(features)
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42, n_jobs=-1)
    model.fit(scaled)
    predictions = model.predict(scaled)
    anomaly_mask = predictions == -1
    anomalies_detected = int(anomaly_mask.sum())
    anomaly_percentage = round(anomalies_detected / records_uploaded * 100, 2)
    anomaly_scores = np.abs(model.score_samples(scaled))
    timestamp_column = next((column for column in frame.columns if column.lower() in {"timestamp", "time", "date"}), None)
    suspicious_records = []
    suspicious_timestamps = []
    for position in np.flatnonzero(anomaly_mask)[:100]:
        timestamp = frame.iloc[position][timestamp_column] if timestamp_column and timestamp_column in frame.columns else None
        suspicious_timestamps.append(str(timestamp) if timestamp is not None else None)
        suspicious_records.append({
            "record": int(position),
            "anomaly_score": round(float(anomaly_scores[position]), 4),
            "timestamp": timestamp,
        })

    return {
        "records_uploaded": records_uploaded,
        "records_analyzed": int(len(frame)),
        "anomalies_detected": anomalies_detected,
        "anomaly_percentage": anomaly_percentage,
        "anomaly_score": round(float(np.mean(anomaly_scores)), 4),
        "cyber_risk_score": anomaly_percentage,
        "suspicious_records": suspicious_records,
        "suspicious_timestamps": [value for value in suspicious_timestamps if value is not None],
        "model": "Isolation Forest",
        "status": "ANALYZED",
        "processing_time_seconds": round(time.perf_counter() - started, 4),
        "features": numeric_columns,
    }


def collect_system_metrics():
    cpu = float(psutil.cpu_percent(interval=None))
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath(os.sep))
    network_before = psutil.net_io_counters(pernic=True)
    time.sleep(0.1)
    network_after = psutil.net_io_counters(pernic=True)
    bytes_delta = sum(max(0, network_after.get(name, network_before.get(name)).bytes_sent +
                                  network_after.get(name, network_before.get(name)).bytes_recv -
                                  (network_before.get(name, network_after.get(name)).bytes_sent +
                                   network_before.get(name, network_after.get(name)).bytes_recv))
                       for name in set(network_after) | set(network_before))
    network_activity = bytes_delta / 0.1
    network_risk = clamp(network_activity / 10_000_000 * 100)
    system_risk = (
        cpu * 0.35
        + memory.percent * 0.30
        + disk.percent * 0.20
        + network_risk * 0.15
    )
    return {
        "cpu": round(cpu, 2),
        "ram": round(float(memory.percent), 2),
        "disk": round(float(disk.percent), 2),
        "network_activity": round(float(network_activity), 2),
        "network_risk": round(network_risk, 2),
        "system_risk_score": round(clamp(system_risk), 2),
        "timestamp": now(),
    }


def collect_telemetry(cloudwatch=None, indicators=None):
    """Persist one real telemetry observation from CloudWatch or local psutil."""
    cloudwatch = cloudwatch or {}
    indicators = indicators or {}
    if cloudwatch.get("status") == "CONNECTED":
        record = {
            "timestamp": cloudwatch.get("latest_timestamp") or now(), "source": "CloudWatch",
            "cpu": cloudwatch.get("cpu"), "memory": cloudwatch.get("memory"), "disk": cloudwatch.get("disk"),
            "network_in": cloudwatch.get("network_in"), "network_out": cloudwatch.get("network_out"),
            "failed_logins": indicators.get("failed_logins"), "suspicious": indicators.get("suspicious"),
            "status_check_failed": cloudwatch.get("status_check_failed"),
        }
    else:
        before = psutil.net_io_counters()
        time.sleep(0.1)
        after = psutil.net_io_counters()
        record = {
            "timestamp": now(), "source": "local-psutil", "cpu": round(float(psutil.cpu_percent(interval=0.1)), 2),
            "memory": round(float(psutil.virtual_memory().percent), 2), "disk": round(float(psutil.disk_usage(os.path.abspath(os.sep)).percent), 2),
            "network_in": round(max(0, after.bytes_recv - before.bytes_recv) / 0.1, 2),
            "network_out": round(max(0, after.bytes_sent - before.bytes_sent) / 0.1, 2),
            "failed_logins": indicators.get("failed_logins"), "suspicious": indicators.get("suspicious"), "status_check_failed": None,
        }
    available = [record[key] for key in TELEMETRY_FEATURES if record.get(key) is not None]
    record["system_health"] = (100.0 if record.get("status_check_failed") == 0 else 0.0) if record.get("status_check_failed") is not None else None
    record["system_risk_score"] = round(clamp(
        (record["cpu"] or 0) * 0.35 + (record["memory"] or 0) * 0.30 + (record["disk"] or 0) * 0.20
        + clamp((record["network_in"] or 0) / 10_000_000 * 100) * 0.075
        + clamp((record["network_out"] or 0) / 10_000_000 * 100) * 0.075
    ), 2) if available else None
    record["valid"] = bool(available)
    record["id"] = ex("""INSERT INTO telemetry(timestamp,source,cpu,memory,disk,network_in,network_out,failed_logins,
       suspicious,status_check_failed,system_health,valid) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
       tuple(record.get(key) for key in ("timestamp", "source", "cpu", "memory", "disk", "network_in", "network_out", "failed_logins", "suspicious", "status_check_failed", "system_health", "valid")))
    return record


def _rows_to_features(rows, columns):
    frame = pd.DataFrame([{column: row.get(column) for column in columns} for row in rows])
    frame = frame.apply(pd.to_numeric, errors="coerce")
    frame = frame.loc[:, frame.notna().any()]
    return frame.fillna(frame.median(numeric_only=True)).fillna(0), list(frame.columns)


def detect_telemetry_anomaly(telemetry, window=100):
    """Fit Isolation Forest on prior valid observations and score the current one."""
    baseline = q("SELECT * FROM telemetry WHERE valid=1 ORDER BY id DESC LIMIT ?", (window + 1,))
    baseline = [row for row in baseline if row["id"] != telemetry.get("id")]
    result = {
        "anomaly_detected": False, "anomaly_score": None, "classification": "WARMING_UP",
        "model": "Isolation Forest", "timestamp": telemetry["timestamp"], "baseline_size": len(baseline),
        "confidence": None, "feature_deviations": [],
        "explanation": "Collecting real telemetry until the rolling baseline is large enough to score behavior.",
    }
    if len(baseline) < 10:
        ex("INSERT INTO anomaly_history(timestamp,anomaly_detected,anomaly_score,classification,model,baseline_size,confidence,explanation) VALUES(?,?,?,?,?,?,?,?)",
           (result["timestamp"], 0, None, result["classification"], result["model"], result["baseline_size"], None, result["explanation"]))
        return result
    frame, columns = _rows_to_features(baseline + [telemetry], list(TELEMETRY_FEATURES))
    if len(columns) < 2:
        result["classification"] = "INSUFFICIENT_FEATURES"
        return result
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42, n_jobs=-1)
    model.fit(frame.iloc[:-1].to_numpy(dtype=float))
    current = frame.iloc[-1].to_numpy(dtype=float).reshape(1, -1)
    prediction = int(model.predict(current)[0])
    current_decision = float(model.decision_function(current)[0])
    baseline_decisions = model.decision_function(frame.iloc[:-1].to_numpy(dtype=float))
    low, high = float(np.min(baseline_decisions)), float(np.max(baseline_decisions))
    score = 0.0 if high == low else clamp((high - current_decision) / (high - low) * 100)
    means = frame.iloc[:-1].mean()
    stds = frame.iloc[:-1].std().replace(0, np.nan)
    deviations = []
    for column in columns:
        deviation = abs(float(frame.iloc[-1][column]) - float(means[column])) / float(stds[column]) if pd.notna(stds[column]) else 0
        if deviation >= 1:
            deviations.append({"feature": column, "current": round(float(frame.iloc[-1][column]), 2), "baseline": round(float(means[column]), 2), "level": "HIGH" if deviation >= 2 else "MEDIUM", "standard_deviations": round(deviation, 2)})
    result.update({
        "anomaly_detected": prediction == -1, "anomaly_score": round(score, 2),
        "classification": "HIGH_ANOMALY" if score >= 75 else "MEDIUM_ANOMALY" if score >= 50 else "NORMAL",
        "confidence": round(clamp(score), 2), "feature_deviations": deviations,
        "explanation": "Abnormal behavior detected because multiple telemetry features significantly deviated from the learned baseline." if deviations and prediction == -1 else "No significant multi-feature deviation was detected against the rolling baseline.",
    })
    ex("INSERT INTO anomaly_history(timestamp,anomaly_detected,anomaly_score,classification,model,baseline_size,confidence,explanation) VALUES(?,?,?,?,?,?,?,?)",
       (result["timestamp"], int(result["anomaly_detected"]), result["anomaly_score"], result["classification"], result["model"], result["baseline_size"], result["confidence"], result["explanation"]))
    return result


def telemetry_system_metrics(telemetry):
    return {
        "cpu": telemetry.get("cpu"), "ram": telemetry.get("memory"), "disk": telemetry.get("disk"),
        "network_activity": telemetry.get("network_in"), "network_in": telemetry.get("network_in"),
        "network_out": telemetry.get("network_out"), "network_risk": clamp((telemetry.get("network_in") or 0) / 10_000_000 * 100),
        "system_health": telemetry.get("system_health"), "system_risk_score": telemetry.get("system_risk_score") or 0, "timestamp": telemetry.get("timestamp"),
        "source": telemetry.get("source"),
    }


def assess_risk_engine(cyber_csv=None, weather_csv=None, system_metrics=None, cloudwatch_alarm="NOT_CONFIGURED", telemetry_anomaly=None):
    weather = calculate_weather_risk()
    if weather_csv and os.path.exists(weather_csv):
        weather = calculate_weather_risk()
        weather_source = _load_weather_csv(weather_csv)
        if weather_source:
            weather = {
                "weather_risk_score": _weather_risk_from_record(weather_source)[0],
                "weather_metrics": weather_source,
                "risk_factors": [
                    {"factor": factor, "risk": value}
                    for factor, value in _weather_risk_from_record(weather_source)[1].items()
                    if value > 0
                ],
                "source": "CSV",
            }
    cyber = analyze_cyber_csv(cyber_csv) if cyber_csv else {
        "records_uploaded": 0, "records_analyzed": telemetry_anomaly.get("baseline_size", 0) + 1 if telemetry_anomaly else 0,
        "anomalies_detected": int(telemetry_anomaly.get("anomaly_detected", False)) if telemetry_anomaly else 0,
        "anomaly_percentage": telemetry_anomaly.get("anomaly_score", 0) if telemetry_anomaly else 0,
        "anomaly_score": telemetry_anomaly.get("anomaly_score") if telemetry_anomaly and telemetry_anomaly.get("anomaly_score") is not None else 0.0,
        "cyber_risk_score": (telemetry_anomaly.get("anomaly_score") or 0) if telemetry_anomaly else 0,
        "suspicious_records": [], "suspicious_timestamps": [], "model": "Isolation Forest",
        "status": telemetry_anomaly.get("classification", "WARMING_UP") if telemetry_anomaly else "WARMING_UP",
        "processing_time_seconds": 0.0, "baseline_size": telemetry_anomaly.get("baseline_size", 0) if telemetry_anomaly else 0,
        "confidence": telemetry_anomaly.get("confidence") if telemetry_anomaly else None,
        "feature_deviations": telemetry_anomaly.get("feature_deviations", []) if telemetry_anomaly else [],
        "explanation": telemetry_anomaly.get("explanation") if telemetry_anomaly else "No telemetry anomaly result available.",
    }
    system = system_metrics or collect_system_metrics()
    if cloudwatch_alarm == "ALARM":
        system = dict(system)
        system["system_risk_score"] = round(max(float(system.get("system_risk_score") or 0), 85.0), 2)
    fusion = calculate_fusion(
        weather_risk=weather["weather_risk_score"],
        cyber_risk=cyber["cyber_risk_score"],
        system_risk=system["system_risk_score"],
    )
    result = {
        **fusion,
        "weather": weather,
        "cyber": cyber,
        "system": system,
        "records_analyzed": cyber["records_analyzed"],
        "records_uploaded": cyber["records_uploaded"],
        "anomalies_detected": cyber["anomalies_detected"],
        "anomaly_percentage": cyber["anomaly_percentage"],
        "anomaly_score": cyber["anomaly_score"],
        "suspicious_timestamps": cyber["suspicious_timestamps"],
        "processing_time_seconds": cyber["processing_time_seconds"],
        "cloudwatch_alarm": cloudwatch_alarm,
        "model": cyber["model"],
        "model_status": cyber["status"],
        "risk_evidence": [
            f"Weather risk {weather['weather_risk_score']} / 100 from {weather['source']} source",
            f"Cyber risk {cyber['cyber_risk_score']} / 100 from {cyber['model']} on {cyber['records_analyzed']} records",
            f"System risk {system['system_risk_score']} / 100 from live system telemetry",
            f"CloudWatch alarm status: {cloudwatch_alarm}",
            f"Risk fusion weights: weather 25%, cyber 45%, system 30%",
        ],
    }
    CURRENT_RISK_ANALYSIS.clear()
    CURRENT_RISK_ANALYSIS.update(result)
    return result


def get_current_risk_analysis():
    return dict(CURRENT_RISK_ANALYSIS)


def assess_risk(m):
    """Backward-compatible database-backed assessment used by existing workflows."""
    cpu = float(m.get("cpu", 0))
    ram = float(m.get("ram", 0))
    disk = float(m.get("disk", 0))
    failed_logins = int(m.get("failed_logins", 0))
    suspicious = int(m.get("suspicious", 0))
    score = round(min(100, cpu * 0.28 + ram * 0.24 + disk * 0.20 + min(failed_logins, 50) * 0.20 + min(suspicious, 10) * 0.08), 1)
    reasons = [
        f"CPU {cpu:.1f}%: +{cpu * 0.28:.1f}",
        f"RAM {ram:.1f}%: +{ram * 0.24:.1f}",
        f"Disk {disk:.1f}%: +{disk * 0.20:.1f}",
        f"Failed logins {failed_logins}: +{min(failed_logins, 50) * 0.20:.1f}",
        f"Suspicious events {suspicious}: +{min(suspicious, 10) * 0.08:.1f}",
    ]
    level = severity_for(score)
    ex("INSERT INTO risk_scores(ts,score,level,reasons,anomaly,decision) VALUES(?,?,?,?,?,?)",
       (now(), score, level, json.dumps(reasons), "not_assessed", level))
    return dict(score=score, level=level, reasons=reasons, anomaly="not_assessed", decision=level)
