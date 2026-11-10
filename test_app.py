import hashlib
import hmac
import json
import secrets

from fastapi.testclient import TestClient

import agents
import app

VULN = '''import sqlite3, subprocess
def get_user(name):
    return sqlite3.connect("db").execute("SELECT * FROM users WHERE name = '%s'" % name)
def run(cmd):
    return subprocess.call(cmd, shell=True)
'''


def test_signature(monkeypatch):
    monkeypatch.setattr(app, "SECRET", b"s3cret")
    client = TestClient(app.app)
    body = b'{"action":"opened"}'
    good = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert client.post("/webhook", content=body, headers={"X-Hub-Signature-256": "sha256=bad"}).status_code == 401
    assert client.post("/webhook", content=body, headers={"X-Hub-Signature-256": good}).status_code == 200


def test_scan(tmp_path):
    (tmp_path / "vuln.py").write_text(VULN)
    (tmp_path / "config.py").write_text(f'TOKEN = "ghp_{secrets.token_hex(18)}"\n')  # fake token, made at runtime
    (tmp_path / "untouched.py").write_text(VULN)  # not part of the PR, must be ignored

    found, errors = app.scan(str(tmp_path), ["vuln.py", "config.py"])

    assert errors == [], errors
    assert {"semgrep", "bandit", "gitleaks"} <= {f["tool"] for f in found}
    assert all(f["file"] != "untouched.py" for f in found)
    assert any(f["line"] == 3 for f in found), "SQL injection missed"
    assert any(f["line"] == 5 for f in found), "shell=True missed"
    assert len({(f["file"], f["line"]) for f in found}) == len(found), "duplicates not merged"


def test_report_escapes_and_lists_errors():
    f = {"tool": "bandit", "rule": "B608", "severity": "MEDIUM", "file": "a.py", "line": 3, "message": "sql"}
    body = app.report([f], {0: {"risk": "a | b", "fix": "use params", "false_positive": True}}, [], ["semgrep: Timeout"])
    assert body.startswith(app.MARK)
    assert "(likely false positive) a \\| b" in body and "use params" in body and "Not run: semgrep" in body


def test_pr_event_schedules_review(monkeypatch):
    monkeypatch.setattr(app, "SECRET", b"s3cret")
    calls = []
    monkeypatch.setattr(app, "review", lambda *a: calls.append(a))
    body = json.dumps({"action": "opened", "number": 7, "repository": {"full_name": "o/r"},
                       "pull_request": {"head": {"sha": "abc", "repo": {"clone_url": "https://github.com/o/r.git"}}}}).encode()
    sig = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    r = TestClient(app.app).post("/webhook", content=body,
                                 headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "pull_request"})
    assert r.status_code == 200
    assert calls == [("o/r", 7, "https://github.com/o/r.git", "abc")]


def test_triage_drops_invented_findings(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    f = {"tool": "bandit", "rule": "B1", "severity": "LOW", "file": "a.py", "line": 1, "message": "m"}
    monkeypatch.setattr(agents, "LLM_KEY", "k")
    monkeypatch.setattr(agents, "llm_json", lambda p: {"items": [{"id": 0, "risk": "r", "fix": "x"}, {"id": 99, "risk": "invented"}]})
    assert list(app.triage(str(tmp_path), [f])) == [0]  # id 99 was never sent, so it's dropped


def fake_github(monkeypatch, head_sha, security=()):
    """Stub out GitHub, git and the agents; return the list of GitHub calls made."""
    calls = []

    def gh(method, path, **kw):
        calls.append((method, path, kw.get("json", {}).get("state")))
        if path.endswith("/files"):
            return [{"filename": "a.py", "status": "added", "patch": ""}]
        if path.endswith("/pulls/7"):
            return {"head": {"sha": head_sha}}
        return []

    result = {"security": list(security), "notes": {}, "quality": [], "errors": []}
    monkeypatch.setattr(app, "gh", gh)
    monkeypatch.setattr(app.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(app, "GRAPH", type("G", (), {"invoke": staticmethod(lambda s: result)}))
    return calls


def test_stale_review_does_not_overwrite_the_comment(monkeypatch):
    calls = fake_github(monkeypatch, head_sha="newer")
    app.review("o/r", 7, "https://github.com/o/r.git", "old")
    assert ("POST", "/repos/o/r/statuses/old", "pending") in calls
    assert not any("comments" in path and method in ("POST", "PATCH") for method, path, _ in calls)


def test_high_severity_finding_fails_the_check(monkeypatch):
    sql = {"tool": "semgrep", "rule": "sqli", "severity": "ERROR", "file": "a.py", "line": 3, "message": "m"}
    calls = fake_github(monkeypatch, head_sha="abc", security=[sql])
    app.review("o/r", 7, "https://github.com/o/r.git", "abc")
    assert ("POST", "/repos/o/r/issues/7/comments", None) in calls
    assert calls[-1] == ("POST", "/repos/o/r/statuses/abc", "failure")


def test_git_errors_never_leak_the_token(monkeypatch):
    def fail(cmd, **kw):
        raise app.subprocess.CalledProcessError(128, cmd)  # cmd holds the token URL

    fake_github(monkeypatch, head_sha="abc")
    monkeypatch.setattr(app, "TOKEN", "ghp_secret")
    monkeypatch.setattr(app.subprocess, "run", fail)
    try:
        app.run_review("o/r", 7, "https://github.com/o/r.git", "abc")
    except RuntimeError as e:
        assert "ghp_secret" not in str(e) and e.__suppress_context__  # traceback hides the git error
    else:
        raise AssertionError("expected RuntimeError")
