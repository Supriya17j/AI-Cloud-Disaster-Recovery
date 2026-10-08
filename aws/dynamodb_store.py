"""Optional DynamoDB metadata persistence for monitoring events."""
import os
import logging
import uuid

log = logging.getLogger(__name__)


def _enabled():
    return os.getenv("DYNAMODB_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


def _table():
    if not _enabled():
        return None
    import boto3

    resource = boto3.resource(
        "dynamodb",
        region_name=os.getenv("AWS_REGION"),
        endpoint_url=os.getenv("AWS_DYNAMODB_ENDPOINT_URL") or None,
    )
    name = os.getenv("AWS_DYNAMODB_TABLE", "RecoveryEvents")
    table = resource.Table(name)
    try:
        table.load()
    except resource.meta.client.exceptions.ResourceNotFoundException:
        table = resource.create_table(
            TableName=name,
            KeySchema=[{"AttributeName": "event_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "event_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table.wait_until_exists()
    return table


def put_event(event):
    """Persist event metadata only; failures never stop local monitoring."""
    table = _table()
    if table is None:
        return False
    try:
        table.put_item(Item={key: str(value) if value is not None else "" for key, value in event.items()})
        return True
    except Exception:
        log.exception("DynamoDB event write failed")
        return False


def recent_events(limit=25):
    table = _table()
    if table is None:
        return []
    try:
        response = table.scan(Limit=limit)
        return sorted(response.get("Items", []), key=lambda item: item.get("timestamp", ""), reverse=True)[:limit]
    except Exception:
        log.exception("DynamoDB event read failed")
        return []


def put_assessment(assessment):
    """Persist recovery assessment metadata; backup payloads never enter DynamoDB."""
    item = dict(assessment)
    item.setdefault("event_id", "ASM-" + uuid.uuid4().hex[:12].upper())
    item["event_type"] = "RECOVERY_ASSESSMENT"
    return put_event(item)


def recent_assessments(limit=25):
    items = recent_events(limit * 2)
    return [item for item in items if item.get("event_type") == "RECOVERY_ASSESSMENT"][:limit]