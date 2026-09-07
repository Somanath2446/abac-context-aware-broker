"""
broker/main.py

Day 2: proved the request -> S3 -> response pipeline works, no policy logic.
Day 3-4: extends the request schema to accept the full context a real ABAC
policy engine needs to evaluate — role, source_network, device_id, timestamp
— on top of the original object_id/requester_id. Still no policy check yet;
that's Day 5, once Person B's evaluate() function is ready to wire in.

For this demo, source_network and device_id are NOT auto-detected from the
real request (that would need reverse-proxy / client cert setup out of
scope here) — they're fields a "trusted test client" sends explicitly, as
scoped. timestamp is optional: if the client doesn't send one, the broker
stamps the request with its own server time.

Run:
    uvicorn broker.main:app --reload --port 8000
    (or, if 'uvicorn' isn't on PATH: python -m uvicorn broker.main:app --reload --port 8000)

Test:
    curl -X POST http://localhost:8000/request-access ^
      -H "Content-Type: application/json" ^
      -d "{\"object_id\": \"test1.txt\", \"requester_id\": \"user123\", \"role\": \"nurse\", \"source_network\": \"hospital-vpn\", \"device_id\": \"laptop-42\"}"
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Allow `from storage.s3_client import ...` when running from the project root.
sys.path.append(str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI
from pydantic import BaseModel, Field

from storage.s3_client import generate_presigned_url

app = FastAPI(title="ABAC Broker (attribute intake - no policy check yet)")


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


@app.post("/request-access")
def request_access(req: AccessRequest):
    """
    Attribute intake (Day 3-4): the broker now receives and validates the
    full context object, but does NOT evaluate policy on it yet. Every
    request still gets a presigned URL unconditionally — that's still the
    Day 2 baseline behavior, kept as-is until Day 5 wires in evaluate().

    The `attributes` dict below is exactly the shape Day 5 will hand to
    Person B's evaluate(attributes, rules) function.
    """
    attributes = {
        "object_id": req.object_id,
        "requester_id": req.requester_id,
        "role": req.role,
        "source_network": req.source_network,
        "device_id": req.device_id,
        "timestamp": (req.timestamp or datetime.now(timezone.utc)).isoformat(),
    }

    # TODO (Day 5): decision = evaluate(attributes, rules)
    #   if decision.allow: generate URL (below)
    #   else: return 403 with decision.reason

    url = generate_presigned_url(req.object_id, expiry_seconds=60)

    return {
        "attributes": attributes,
        "url": url,
        "expiry_seconds": 60,
    }


@app.get("/health")
def health():
    return {"status": "ok"}