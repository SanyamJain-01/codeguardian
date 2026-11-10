import hashlib
import hmac
import json
import logging
import os
import subprocess
from fastapi import FastAPI, Header, HTTPException, Request
from pathlib import Path

SEMGREP_CONFIG = os.environ.get("SEMGREP_CONFIG", "p/default")
RANK = {"CRITICAL": 0, "HIGH": 0, "ERROR": 0, "MEDIUM": 1, "WARNING": 1, "LOW": 2, "INFO": 2}


SECRET = os.environ.get("WEBHOOK_SECRET", "").encode()
log = logging.getLogger("uvicorn.error")
app = FastAPI()


def valid_signature(raw: bytes, header: str) -> bool:
    if not SECRET:  # no secret configured = reject everything, never accept everything
        return False
    expected = "sha256=" + hmac.new(SECRET, raw, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)  # constant-time, blocks timing attacks
def run(cmd, cwd):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=300)


def finding(tool, rule, sev, file, line, msg):
    """One shape for every scanner's output."""
    return {"tool": tool, "rule": rule, "severity": sev.upper(),
            "file": os.path.normpath(file), "line": line, "message": msg.strip()}


def semgrep(root, files):
    r = run(["semgrep", "scan", "--config", SEMGREP_CONFIG, "--json", "--metrics", "off", "--quiet", *files], root)
    if r.returncode not in (0, 1):  # 0 = clean, 1 = findings, anything else = it failed
        raise RuntimeError(f"exit {r.returncode}")
    return [finding("semgrep", x["check_id"].split(".")[-1], x["extra"]["severity"], x["path"],
                    x["start"]["line"], x["extra"]["message"]) for x in json.loads(r.stdout)["results"]]


def bandit(root, files):
    py = [f for f in files if f.endswith(".py")]  # Bandit only understands Python
    if not py:
        return []
    data = json.loads(run(["bandit", "-f", "json", "-q", *py], root).stdout or "{}")
    return [finding("bandit", x["test_id"], x["issue_severity"], x["filename"], x["line_number"],
                    x["issue_text"]) for x in data.get("results", [])]


def gitleaks(root, files):
    out = Path(root) / ".gitleaks.json"
    run(["gitleaks", "dir", ".", "--no-banner", "--redact", "--report-format", "json",
         "--report-path", str(out)], root)
    changed = {os.path.normpath(f) for f in files}
    return [finding("gitleaks", x["RuleID"], "HIGH", x["File"], x["StartLine"], x["Description"])
            for x in json.loads(out.read_text() or "[]") if os.path.normpath(x["File"]) in changed]


def scan(root, files):
    """Run all scanners on the changed files. Returns (findings, errors)."""
    found, errors = [], []
    for tool in (semgrep, bandit, gitleaks):
        try:
            found += tool(root, files)
        except Exception as e:  # one broken scanner must not hide the others' results
            errors.append(f"{tool.__name__}: {type(e).__name__} {e}"[:120])
    found.sort(key=lambda f: (RANK.get(f["severity"], 3), f["file"], f["line"]))
    seen, unique = set(), []
    for f in found:  # Semgrep and Bandit often flag the same line; keep the most severe one
        if (f["file"], f["line"]) not in seen:
            seen.add((f["file"], f["line"]))
            unique.append(f)
    return unique, errors

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