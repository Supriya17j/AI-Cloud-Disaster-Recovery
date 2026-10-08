"""CloudWatch metric and alarm retrieval using the boto3 credential chain."""
import logging
import os
from datetime import datetime, timedelta, timezone

log = logging.getLogger(__name__)


def _enabled():
    return os.getenv("CLOUDWATCH_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


def _dimensions():
    name = os.getenv("CLOUDWATCH_DIMENSION_NAME")
    value = os.getenv("CLOUDWATCH_DIMENSION_VALUE")
    return [{"Name": name, "Value": value}] if name and value else []


def _client():
    import boto3
    return boto3.client(
        "cloudwatch",
        region_name=os.getenv("AWS_REGION") or None,
        endpoint_url=os.getenv("AWS_CLOUDWATCH_ENDPOINT_URL") or None,
    )


def _metric(client, name, statistic, start, end):
    response = client.get_metric_statistics(
        Namespace=os.getenv("CLOUDWATCH_NAMESPACE", "AWS/EC2"),
        MetricName=name,
        Dimensions=_dimensions(),
        StartTime=start,
        EndTime=end,
        Period=max(60, int(os.getenv("CLOUDWATCH_PERIOD_S", "60"))),
        Statistics=[statistic],
    )
    points = response.get("Datapoints", [])
    if not points:
        return None, None
    point = max(points, key=lambda item: item["Timestamp"])
    return round(float(point[statistic]), 2), point["Timestamp"].isoformat()


def _alarm_status(client):
    names = [name.strip() for name in os.getenv("CLOUDWATCH_ALARM_NAMES", "").split(",") if name.strip()]
    kwargs = {"AlarmNames": names} if names else {}
    response = client.describe_alarms(**kwargs)
    alarms = response.get("MetricAlarms", []) + response.get("CompositeAlarms", [])
    active = [alarm for alarm in alarms if alarm.get("StateValue") == "ALARM"]
    return ("ALARM" if active else "OK" if alarms else "NOT_CONFIGURED"), [alarm.get("AlarmName") for alarm in active]


def _system_risk(metrics):
    weights = {"cpu": 0.35, "memory": 0.30, "disk": 0.20, "network": 0.15}
    values = {key: metrics.get(key) for key in weights}
    available = {key: value for key, value in values.items() if value is not None}
    if not available:
        return None
    total_weight = sum(weights[key] for key in available)
    score = sum(float(available[key]) * weights[key] for key in available) / total_weight
    return round(max(0, min(100, score)), 2)


def collect():
    """Return only CloudWatch values; no local/random fallback is used here."""
    base = {
        "enabled": _enabled(), "status": "DISABLED", "latest_timestamp": None,
        "cpu": None, "memory": None, "disk": None, "network": None, "network_in": None, "network_out": None,
        "application_health": None, "alarm_status": "NOT_CONFIGURED", "active_alarms": [],
    }
    if not base["enabled"]:
        return base
    try:
        client = _client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(minutes=max(1, int(os.getenv("CLOUDWATCH_LOOKBACK_MIN", "10"))))
        names = {
            "cpu": (os.getenv("CLOUDWATCH_CPU_METRIC", "CPUUtilization"), "Average"),
            "memory": (os.getenv("CLOUDWATCH_MEMORY_METRIC", ""), "Average"),
            "disk": (os.getenv("CLOUDWATCH_DISK_METRIC", ""), "Average"),
            "network_in": (os.getenv("CLOUDWATCH_NETWORK_METRIC", "NetworkIn"), "Sum"),
            "network_out": (os.getenv("CLOUDWATCH_NETWORK_OUT_METRIC", "NetworkOut"), "Sum"),
            "application_health": (os.getenv("CLOUDWATCH_HEALTH_METRIC", ""), "Average"),
            "status_check_failed": (os.getenv("CLOUDWATCH_STATUS_CHECK_METRIC", "StatusCheckFailed"), "Maximum"),
        }
        timestamps = []
        for field, (name, statistic) in names.items():
            if not name:
                continue
            value, timestamp = _metric(client, name, statistic, start, end)
            base[field] = value
            if timestamp:
                timestamps.append(timestamp)
        base["network"] = base.get("network_in")
        base["latest_timestamp"] = max(timestamps) if timestamps else None
        base["alarm_status"], base["active_alarms"] = _alarm_status(client)
        base["status"] = "CONNECTED" if timestamps or base["alarm_status"] != "NOT_CONFIGURED" else "NO_DATAPOINTS"
        base["system_risk_score"] = _system_risk(base)
        return base
    except Exception as error:
        log.warning("CloudWatch collection unavailable: %s", error)
        base["status"] = "UNAVAILABLE"
        base["error"] = "CloudWatch request failed; check AWS region, IAM permissions, and metric configuration."
        return base