"""
broker/main.py

Day 2: proved the request -> S3 -> response pipeline works, no policy logic.
Day 3-4: extended the request schema to accept the full context a real ABAC
policy engine needs — role, source_network, device_id, timestamp — on top
of the original object_id/requester_id.
Day 5: wires in Person B's evaluate(attributes, rules). Every request is now
evaluated against policy_engine/rules.json before a presigned URL is ever
generated. A denied request never touches S3 — no URL is created, so none
can leak. Denied requests get HTTP 403 with a reason string; allowed
requests proceed to generate_presigned_url exactly as before.
Day 6-7: adds a revocation list. Every granted request mints a token_id
(UUID4), returned to the client, which can optionally be sent back on a
later request to reuse that same grant (e.g. renewing a URL before it
expires). If an owner revokes that token_id via POST /revoke/{token_id},
any future request presenting it is denied — even if the policy engine
would otherwise say allow. This is a fallback layer that sits on top of
(not instead of) attribute-based policy evaluation.

For this demo, source_network and device_id are NOT auto-detected from the
real request (that would need reverse-proxy / client cert setup out of
scope here) — they're fields a "trusted test client" sends explicitly, as
scoped. timestamp is optional: if the client doesn't send one, the broker
stamps the request with its own server time.

Run:
    uvicorn broker.main:app --reload --port 8000
    (or, if 'uvicorn' isn't on PATH: python -m uvicorn broker.main:app --reload --port 8000)

Test (allowed, matches the test-file-smoke-test rule in rules.json):
    curl -X POST http://localhost:8000/request-access ^
      -H "Content-Type: application/json" ^
      -d "{\"object_id\": \"test1.txt\", \"requester_id\": \"user123\", \"role\": \"tester\", \"source_network\": \"dev-network\", \"device_id\": \"laptop-42\"}"

Then revoke the token_id from that response:
    curl -X POST http://localhost:8000/revoke/<token_id>

And retry the original request WITH that same token_id included — it should
now be denied even though the policy engine would still say allow.
"""

import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Allow `from storage.s3_client import ...` / `from policy_engine.evaluate import ...`
# when running from the project root.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from broker import revocation_store
from policy_engine.evaluate import evaluate
from storage.s3_client import generate_presigned_url

app = FastAPI(title="ABAC Broker")

# Rules are loaded once at startup, not per-request — they don't change
# between requests, and re-reading the file on every call would be wasted work.
RULES_PATH = Path(__file__).resolve().parent.parent / "policy_engine" / "rules.json"
with open(RULES_PATH) as f:
    RULES = json.load(f)


class AccessRequest(BaseModel):
    object_id: str
    requester_id: str
    role: str = Field(..., description="Requester's role, e.g. 'nurse', 'auditor'. Free-text for now.")
    source_network: str = Field(..., description="Simulated network context, e.g. 'hospital-vpn', 'public-wifi'.")
    device_id: str = Field(..., description="Simulated device identifier, e.g. 'laptop-42'.")
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Request time. If omitted, the broker stamps its own server time (UTC).",
    )
    token_id: Optional[str] = Field(
        default=None,
        description="Optional: reuse an existing grant's token_id (e.g. to renew a URL). "
        "Omit to mint a new one. If this token was revoked, the request is denied "
        "even if policy would otherwise allow it.",
    )


@app.post("/request-access")
def request_access(req: AccessRequest):
    """
    Day 5: evaluate against policy_engine/rules.json.
    Day 6-7: then check the revocation list — even a policy "allow" is
    overridden if the client's token_id has been revoked. A denied request
    (by either policy or revocation) never touches S3.
    """
    attributes = {
        "object_id": req.object_id,
        "requester_id": req.requester_id,
        "role": req.role,
        "source_network": req.source_network,
        "device_id": req.device_id,
        "timestamp": (req.timestamp or datetime.now(timezone.utc)).isoformat(),
    }

    allowed, reason = evaluate(attributes, RULES)

    if not allowed:
        return JSONResponse(
            status_code=403,
            content={"attributes": attributes, "allowed": False, "reason": reason},
        )

    # Revocation check happens AFTER policy allows, as a fallback layer on top.
    if req.token_id is not None and revocation_store.is_revoked(req.token_id):
        return JSONResponse(
            status_code=403,
            content={
                "attributes": attributes,
                "allowed": False,
                "reason": f"token '{req.token_id}' has been revoked",
            },
        )

    token_id = req.token_id or str(uuid.uuid4())
    if req.token_id is None:
        # brand new grant - register it as not-revoked so /revoke/{token_id} has something to find
        revocation_store.register_token(token_id, req.object_id, req.requester_id)

    url = generate_presigned_url(req.object_id, expiry_seconds=60)

    return {
        "attributes": attributes,
        "allowed": True,
        "reason": reason,
        "token_id": token_id,
        "url": url,
        "expiry_seconds": 60,
    }


@app.post("/revoke/{token_id}")
def revoke(token_id: str):
    """Owner-revokes-access action. Marks a previously granted token_id as revoked."""
    found = revocation_store.revoke_token(token_id)
    if not found:
        return JSONResponse(
            status_code=404,
            content={"revoked": False, "reason": f"unknown token_id '{token_id}'"},
        )
    return {"revoked": True, "token_id": token_id}


@app.get("/health")
def health():
    return {"status": "ok"}