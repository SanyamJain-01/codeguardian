import tempfile
import httpx
from fastapi import BackgroundTasks   # add to the existing fastapi import line instead, if you prefer


import hashlib
import hmac
import json
import logging
import os
import subprocess
from fastapi import FastAPI, Header, HTTPException, Request
from pathlib import Path
GH = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
MARK = "<!-- codeguardian -->"   # hidden tag so we can find our own comment later
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
def cell(s):
    """Make text safe inside a markdown table cell."""
    return str(s).replace("|", "\\|").replace("\n", " ")[:300]


def report(findings, errors):
    if findings:
        rows = ["| Severity | Location | Rule | Issue |", "|---|---|---|---|"]
        for f in findings:
            rows.append("| " + " | ".join(cell(x) for x in (
                f["severity"], f"`{f['file']}:{f['line']}`", f"{f['tool']}/{f['rule']}", f["message"])) + " |")
        body = f"**{len(findings)} finding(s)**, most severe first.\n\n" + "\n".join(rows)
    else:
        body = "No issues found in the changed files."
    if errors:
        body += "\n\n<sub>Not run: " + "; ".join(errors) + "</sub>"
    return f"{MARK}\n## CodeGuardian review\n\n{body}"


def gh(method, path, **kw):
    r = httpx.request(method, GH + path, timeout=30, **kw,
                      headers={"Authorization": f"Bearer {TOKEN}", "Accept": "application/vnd.github+json"})
    r.raise_for_status()
    return r.json()


def review(repo, number, clone_url, sha):
    # ponytail: first 100 changed files only; paginate if PRs get bigger
    files = [f["filename"] for f in gh("GET", f"/repos/{repo}/pulls/{number}/files", params={"per_page": 100})
             if f["status"] != "removed"]
    with tempfile.TemporaryDirectory() as root:
        # fetch just the PR's latest commit, not the whole history
        url = clone_url.replace("https://", f"https://x-access-token:{TOKEN}@")
        for cmd in (["git", "init", "-q"],
                    ["git", "fetch", "-q", "--depth", "1", url, sha],
                    ["git", "checkout", "-q", "FETCH_HEAD"]):
            subprocess.run(cmd, cwd=root, check=True, capture_output=True, timeout=300)
        findings, errors = scan(root, files)

    body = report(findings, errors)
    comments = gh("GET", f"/repos/{repo}/issues/{number}/comments", params={"per_page": 100})
    old = next((c for c in comments if c["body"].startswith(MARK)), None)
    if old:  # edit our comment on each push instead of adding a new one
        gh("PATCH", f"/repos/{repo}/issues/comments/{old['id']}", json={"body": body})
    else:
        gh("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})
    log.info("Reviewed PR #%s: %d finding(s)", number, len(findings))

@app.post("/webhook")
async def webhook(request: Request, bg: BackgroundTasks,
                  x_hub_signature_256: str = Header(""),
                  x_github_event: str = Header("")):
    raw = await request.body()
    if not valid_signature(raw, x_hub_signature_256):
        raise HTTPException(401, "bad signature")

    payload = json.loads(raw)
    pr = payload.get("pull_request") or {}
    if (x_github_event == "pull_request"
            and payload.get("action") in {"opened", "synchronize", "reopened"}
            and pr.get("head", {}).get("repo")):  # head repo is gone if the fork was deleted
        bg.add_task(review, payload["repository"]["full_name"], payload["number"],
                    pr["head"]["repo"]["clone_url"], pr["head"]["sha"])
    return {"ok": True}  # GitHub gives up after 10s, so the review runs after we reply