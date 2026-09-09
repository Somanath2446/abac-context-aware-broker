"""
broker/revocation_store.py

Day 6-7: a simple token_id -> revoked(bool) table, backed by a local JSON
file. Swap to DynamoDB later if time allows — the three functions below
(register_token, is_revoked, revoke_token) are the whole interface main.py
depends on, so the storage backend can change without touching the broker.
"""

import json
import threading
from pathlib import Path
from typing import Optional

STORE_PATH = Path(__file__).resolve().parent / "revocation_store.json"

# Simple in-process lock — fine for a single-worker demo. A real multi-worker
# deployment would need a real datastore (DynamoDB) instead of a shared file.
_lock = threading.Lock()


def _load() -> dict:
    if not STORE_PATH.exists():
        return {}
    with open(STORE_PATH) as f:
        return json.load(f)


def _save(data: dict) -> None:
    with open(STORE_PATH, "w") as f:
        json.dump(data, f, indent=2)


def register_token(token_id: str, object_id: str, requester_id: str) -> None:
    """Record a newly granted token as not-revoked, with basic metadata for audit purposes."""
    with _lock:
        data = _load()
        data[token_id] = {
            "revoked": False,
            "object_id": object_id,
            "requester_id": requester_id,
        }
        _save(data)


def is_revoked(token_id: str) -> bool:
    """True if the token exists and has been revoked. Unknown tokens are treated as not-revoked
    (they're simply new — see main.py, which only checks this for client-supplied token_ids)."""
    with _lock:
        data = _load()
        entry = data.get(token_id)
        return bool(entry and entry.get("revoked", False))


def revoke_token(token_id: str) -> bool:
    """Mark a token revoked. Returns True if the token existed, False if unknown."""
    with _lock:
        data = _load()
        if token_id not in data:
            return False
        data[token_id]["revoked"] = True
        _save(data)
        return True


def get_token_info(token_id: str) -> Optional[dict]:
    with _lock:
        data = _load()
        return data.get(token_id)
