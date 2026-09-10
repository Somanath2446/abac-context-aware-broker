"""
broker/audit_log.py

Day 8-9: every request - allowed or denied - gets logged with: timestamp,
requester_id, object_id, decision, reason.
Day 10: upgraded to DynamoDB as the primary store, with the original local
JSONL file kept as a fallback if DynamoDB is unreachable. A logging failure
should never crash the broker or block a legitimate request/response, so
even the fallback write is best-effort.
"""

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
TABLE_NAME = os.getenv("AUDIT_LOG_TABLE_NAME", "AuditLog")

# --- local JSONL fallback (identical to the Day 8-9 implementation) --------

LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "audit.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
_local_lock = threading.Lock()


def _local_log_event(entry: dict) -> None:
    with _local_lock:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")


# --- DynamoDB primary --------------------------------------------------------

_dynamo_table = None


def _get_table():
    global _dynamo_table
    if _dynamo_table is None:
        resource = boto3.resource("dynamodb", region_name=AWS_REGION)
        _dynamo_table = resource.Table(TABLE_NAME)
    return _dynamo_table


def log_event(requester_id: str, object_id: str, decision: str, reason: str) -> None:
    """Append one audit entry. decision should be "allow" or "deny"."""
    entry = {
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "requester_id": requester_id,
        "object_id": object_id,
        "decision": decision,
        "reason": reason,
    }
    try:
        _get_table().put_item(Item=entry)
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[audit_log] DynamoDB unavailable, falling back to local file: {e}")
        _local_log_event(entry)


def fetch_all_entries() -> list:
    """
    Used only by a separate reporting script, never by the broker's request
    path — the broker itself only ever writes (PutItem), never reads its
    own audit table back. Falls back to reading the local JSONL file if
    DynamoDB is unreachable.
    """
    try:
        table = _get_table()
        items = []
        resp = table.scan()
        items.extend(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        return sorted(items, key=lambda e: e.get("timestamp", ""))
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[audit_log] DynamoDB unavailable, reading local file instead: {e}")
        if not LOG_PATH.exists():
            return []
        with open(LOG_PATH) as f:
            return [json.loads(line) for line in f if line.strip()]