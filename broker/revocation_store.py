"""
broker/revocation_store.py

Day 6-7: token_id -> revoked(bool) table.
Day 10: upgraded to DynamoDB as the primary store, with the original local
JSON file kept as a fallback if DynamoDB is unreachable (network issue,
missing table, bad credentials, etc.) — so a broken AWS connection degrades
the broker rather than crashing it outright. Every write still happens to
the local file too when DynamoDB succeeds is NOT required; the fallback
only engages if DynamoDB itself fails, to keep the two stores from silently
drifting apart in the common case.

Interface (register_token, is_revoked, revoke_token, get_token_info) is
unchanged from Day 6-7 — main.py doesn't need to know which backend is
actually serving a given call.
"""

import json
import os
import threading
from pathlib import Path
from typing import Optional

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from dotenv import load_dotenv

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
TABLE_NAME = os.getenv("REVOCATION_TABLE_NAME", "RevocationTokens")

# --- local JSON fallback (identical to the Day 6-7 implementation) ---------

STORE_PATH = Path(__file__).resolve().parent / "revocation_store.json"
_local_lock = threading.Lock()


def _local_load() -> dict:
    if not STORE_PATH.exists():
        return {}
    with open(STORE_PATH) as f:
        return json.load(f)


def _local_save(data: dict) -> None:
    with open(STORE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def _local_register_token(token_id: str, object_id: str, requester_id: str) -> None:
    with _local_lock:
        data = _local_load()
        data[token_id] = {"revoked": False, "object_id": object_id, "requester_id": requester_id}
        _local_save(data)


def _local_is_revoked(token_id: str) -> bool:
    with _local_lock:
        data = _local_load()
        entry = data.get(token_id)
        return bool(entry and entry.get("revoked", False))


def _local_revoke_token(token_id: str) -> bool:
    with _local_lock:
        data = _local_load()
        if token_id not in data:
            return False
        data[token_id]["revoked"] = True
        _local_save(data)
        return True


def _local_get_token_info(token_id: str) -> Optional[dict]:
    with _local_lock:
        data = _local_load()
        return data.get(token_id)


# --- DynamoDB primary --------------------------------------------------------

_dynamo_table = None


def _get_table():
    global _dynamo_table
    if _dynamo_table is None:
        resource = boto3.resource("dynamodb", region_name=AWS_REGION)
        _dynamo_table = resource.Table(TABLE_NAME)
    return _dynamo_table


def register_token(token_id: str, object_id: str, requester_id: str) -> None:
    try:
        _get_table().put_item(
            Item={
                "token_id": token_id,
                "revoked": False,
                "object_id": object_id,
                "requester_id": requester_id,
            }
        )
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[revocation_store] DynamoDB unavailable, falling back to local file: {e}")
        _local_register_token(token_id, object_id, requester_id)


def is_revoked(token_id: str) -> bool:
    try:
        resp = _get_table().get_item(Key={"token_id": token_id})
        item = resp.get("Item")
        return bool(item and item.get("revoked", False))
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[revocation_store] DynamoDB unavailable, falling back to local file: {e}")
        return _local_is_revoked(token_id)


def revoke_token(token_id: str) -> bool:
    try:
        table = _get_table()
        # Confirm the token exists first — UpdateItem alone would silently
        # create a new item for an unknown token_id instead of reporting "not found".
        existing = table.get_item(Key={"token_id": token_id}).get("Item")
        if not existing:
            return False
        table.update_item(
            Key={"token_id": token_id},
            UpdateExpression="SET revoked = :true_val",
            ExpressionAttributeValues={":true_val": True},
        )
        return True
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[revocation_store] DynamoDB unavailable, falling back to local file: {e}")
        return _local_revoke_token(token_id)


def get_token_info(token_id: str) -> Optional[dict]:
    try:
        resp = _get_table().get_item(Key={"token_id": token_id})
        return resp.get("Item")
    except (ClientError, EndpointConnectionError, NoCredentialsError) as e:
        print(f"[revocation_store] DynamoDB unavailable, falling back to local file: {e}")
        return _local_get_token_info(token_id)