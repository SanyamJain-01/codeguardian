import hashlib
import hmac

from fastapi.testclient import TestClient

import app


def test_signature(monkeypatch):
    monkeypatch.setattr(app, "SECRET", b"s3cret")
    client = TestClient(app.app)
    body = b'{"action":"opened"}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()

    assert client.post("/webhook", content=body, headers={"X-Hub-Signature-256": "sha256=bad"}).status_code == 401
    assert client.post("/webhook", content=body, headers={"X-Hub-Signature-256": good}).status_code == 200