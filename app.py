import hashlib
import hmac
import json
import logging
import os

from fastapi import FastAPI, Header, HTTPException, Request

SECRET = os.environ.get("WEBHOOK_SECRET", "").encode()
log = logging.getLogger("uvicorn.error")
app = FastAPI()


def valid_signature(raw: bytes, header: str) -> bool:
    if not SECRET:  # no secret configured = reject everything, never accept everything
        return False
    expected = "sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)  # constant-time, blocks timing attacks


@app.post("/webhook")
async def webhook(request: Request,
                  x_hub_signature_256: str = Header(""),
                  x_github_event: str = Header("")):
    raw = await request.body()  # sign the exact bytes GitHub sent, not re-serialised JSON
    if not valid_signature(raw, x_hub_signature_256):
        raise HTTPException(401, "bad signature")

    payload = json.loads(raw)
    if x_github_event == "pull_request" and payload.get("action") in {"opened", "synchronize", "reopened"}:
        log.info("PR #%s on %s, head %s",
                 payload["number"], payload["repository"]["full_name"],
                 payload["pull_request"]["head"]["sha"][:7])
    return {"ok": True}