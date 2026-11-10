import hashlib
import hmac
import json

from fastapi.testclient import TestClient

import agents
import app

PATCH = "@@ -0,0 +1,4 @@\n+def get_user(name):\n+    pass\n+def _helper():\n+    pass"


def test_untested_functions_skips_private_and_tested(tmp_path):
    assert agents.untested_functions({"a.py": PATCH}, tmp_path) == {"a.py": ["get_user"]}
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("from a import get_user\n")
    assert agents.untested_functions({"a.py": PATCH}, tmp_path) == {}


def fake_scan(root, files):
    """Pretend scanner: one finding per 'shell=True' in the file."""
    text = (app.Path(root) / files[0]).read_text()
    return [{"file": files[0]}] * text.count("shell=True"), []


def test_verify_fix_keeps_only_real_improvements(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "scan", fake_scan)
    old = "import subprocess\nsubprocess.call(c, shell=True)\n"
    (tmp_path / "a.py").write_text(old)
    assert app.verify_fix(tmp_path, "a.py", old, "import subprocess\nsubprocess.call([c])\n")[0]
    assert not app.verify_fix(tmp_path, "a.py", old, old)[0]                       # no change
    assert not app.verify_fix(tmp_path, "a.py", old, "def broken(:\n")[0]          # does not parse
    assert not app.verify_fix(tmp_path, "a.py", old, old + "subprocess.call(d, shell=True)\n")[0]  # worse
    assert (tmp_path / "a.py").read_text() == old  # the checkout is left as it was


def post_comment(monkeypatch, body, association):
    monkeypatch.setattr(app, "SECRET", b"s3cret")
    calls = []
    monkeypatch.setattr(app, "fix_pr", lambda *a: calls.append(a))
    raw = json.dumps({"action": "created", "repository": {"full_name": "o/r"},
                      "issue": {"number": 7, "pull_request": {}},
                      "comment": {"body": body, "author_association": association}}).encode()
    sig = "sha256=" + hmac.new(b"s3cret", raw, hashlib.sha256).hexdigest()
    TestClient(app.app).post("/webhook", content=raw,
                             headers={"X-Hub-Signature-256": sig, "X-GitHub-Event": "issue_comment"})
    return calls


def test_fix_command_needs_write_access(monkeypatch):
    assert post_comment(monkeypatch, "/codeguardian fix", "OWNER") == [("o/r", 7)]
    assert post_comment(monkeypatch, "/codeguardian fix", "NONE") == []      # a stranger can't trigger it
    assert post_comment(monkeypatch, "looks good to me", "OWNER") == []


def test_fix_opens_pr_into_the_branch_and_never_merges(monkeypatch):
    calls = []

    def gh(method, path, **kw):
        calls.append((method, path, kw.get("json")))
        if path == "/repos/o/r/pulls/7":
            return {"head": {"sha": "abc1234", "ref": "feature", "repo": {"full_name": "o/r", "clone_url": "u"}},
                    "base": {"ref": "main"}}
        if path.endswith("/files"):
            return [{"filename": "a.py", "status": "added", "patch": PATCH}]
        if method == "GET" and "/contents/" in path:
            return {"sha": "blob1", "content": ""}
        if path == "/repos/o/r/pulls":
            return {"html_url": "https://github.com/o/r/pull/8"}
        return {}

    sql = {"tool": "semgrep", "rule": "sqli", "severity": "ERROR", "file": "a.py", "line": 2, "message": "m"}
    monkeypatch.setattr(app, "gh", gh)
    monkeypatch.setattr(app, "checkout", lambda root, url, sha: (app.Path(root) / "a.py").write_text("bad\n"))
    monkeypatch.setattr(app, "analyse", lambda root, f, p, s: {
        "security": [sql], "notes": {}, "quality": [], "untested": {"a.py": ["get_user"]}, "errors": []})
    monkeypatch.setattr(app, "verify_fix", lambda root, file, old, new: (True, "scanner findings 1 to 0"))
    monkeypatch.setattr(agents, "draft_fix", lambda file, src, issues: "good = 1\n")
    monkeypatch.setattr(agents, "draft_tests", lambda file, src, names: "def test_x():\n    assert True\n")

    app.run_fix("o/r", 7)

    assert ("POST", "/repos/o/r/git/refs", {"ref": "refs/heads/codeguardian/fix-7-abc1234", "sha": "abc1234"}) in calls
    puts = {path for method, path, _ in calls if method == "PUT"}
    assert puts == {"/repos/o/r/contents/a.py", "/repos/o/r/contents/tests/test_a.py"}
    opened = next(body for method, path, body in calls if path == "/repos/o/r/pulls" and method == "POST")
    assert opened["base"] == "feature" and opened["head"] == "codeguardian/fix-7-abc1234"
    assert not any("merge" in path for _, path, _ in calls)  # nothing is ever merged


def test_symlinks_and_paths_outside_the_checkout_are_skipped(tmp_path):
    (tmp_path / "real.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to("/etc/hostname")
    assert app.inside(tmp_path, "real.py")
    assert not app.inside(tmp_path, "link.py")
    assert not app.inside(tmp_path, "../outside.py")


def test_fix_never_sends_a_file_with_a_secret_to_the_llm(monkeypatch):
    sent, calls = [], []

    def gh(method, path, **kw):
        calls.append((method, path))
        if path == "/repos/o/r/pulls/7":
            return {"head": {"sha": "abc1234", "ref": "feature", "repo": {"full_name": "o/r", "clone_url": "u"}},
                    "base": {"ref": "main"}}
        if path.endswith("/files"):
            return [{"filename": "a.py", "status": "added", "patch": ""}]
        return {"content": ""}

    leak = {"tool": "gitleaks", "rule": "github-pat", "severity": "HIGH", "file": "a.py", "line": 1, "message": "token"}
    monkeypatch.setattr(app, "gh", gh)
    monkeypatch.setattr(app, "checkout", lambda root, url, sha: (app.Path(root) / "a.py").write_text("T = 'ghp_x'\n"))
    monkeypatch.setattr(app, "analyse", lambda root, f, p, s: {
        "security": [leak], "notes": {}, "quality": [], "untested": {"a.py": ["f"]}, "errors": []})
    monkeypatch.setattr(agents, "draft_fix", lambda *a: sent.append(a) or "")
    monkeypatch.setattr(agents, "draft_tests", lambda *a: sent.append(a) or "")

    app.run_fix("o/r", 7)

    assert sent == []  # nothing from that file reached the LLM
    assert not any(method == "POST" and path.endswith("/git/refs") for method, path in calls)


def test_drafted_tests_never_overwrite_existing_ones(monkeypatch):
    puts = []

    def gh(method, path, **kw):
        if method == "PUT":
            puts.append(path)
        if path == "/repos/o/r/pulls/7":
            return {"head": {"sha": "abc1234", "ref": "feature", "repo": {"full_name": "o/r", "clone_url": "u"}},
                    "base": {"ref": "main"}}
        if path.endswith("/files"):
            return [{"filename": "a.py", "status": "added", "patch": ""}]
        if path == "/repos/o/r/pulls":
            return {"html_url": "x"}
        return {"sha": "s", "content": ""}

    def checkout(root, url, sha):
        (app.Path(root) / "tests").mkdir()
        (app.Path(root) / "tests" / "test_a.py").write_text("def test_old():\n    pass\n")
        (app.Path(root) / "a.py").write_text("def f():\n    pass\n")

    monkeypatch.setattr(app, "gh", gh)
    monkeypatch.setattr(app, "checkout", checkout)
    monkeypatch.setattr(app, "analyse", lambda root, f, p, s: {
        "security": [], "notes": {}, "quality": [], "untested": {"a.py": ["f"]}, "errors": []})
    monkeypatch.setattr(agents, "draft_tests", lambda *a: "def test_f():\n    assert True\n")

    app.run_fix("o/r", 7)

    assert puts == ["/repos/o/r/contents/tests/test_a_codeguardian.py"]
