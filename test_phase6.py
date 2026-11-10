import agents
import app

STANDARDS = agents.STANDARDS.read_text()
PATCH = '''@@ -0,0 +1,3 @@
+import subprocess
+def run(cmd):
+    return subprocess.call(cmd, shell=True)'''


def test_added_lines_follow_the_diff():
    patch = "@@ -10,3 +10,4 @@\n keep\n-old\n+new\n keep2\n+added\n\\ No newline at end of file"
    assert agents.added_lines(patch) == {11: "new", 13: "added"}


def test_retrieval_picks_the_relevant_rule():
    assert "CS-05" in agents.retrieve(agents.load_rules(STANDARDS), "subprocess.call(cmd, shell=True)")


def test_quality_keeps_only_retrieved_rules_on_added_lines(monkeypatch):
    reply = {"items": [{"line": 3, "rule": "CS-05", "message": "shell", "fix": "list"},
                       {"line": 3, "rule": "CS-99", "message": "invented rule"},
                       {"line": 40, "rule": "CS-05", "message": "line not in the PR"}]}
    monkeypatch.setattr(agents, "LLM_KEY", "k")
    monkeypatch.setattr(agents, "llm_json", lambda prompt: reply)
    found = agents.quality_review({"a.py": PATCH}, STANDARDS)
    assert [(f["rule"], f["line"]) for f in found] == [("CS-05", 3)]


def test_graph_runs_both_agents_and_joins_errors(monkeypatch):
    monkeypatch.setattr(app, "scan", lambda root, files: ([], ["semgrep: down"]))
    monkeypatch.setattr(agents, "quality_review", lambda p, s: 1 / 0)  # quality agent crashes
    r = app.GRAPH.invoke({"root": ".", "files": [], "patches": {}, "standards": "", "errors": []})
    assert r["security"] == [] and r["quality"] == []
    assert sorted(e.split(":")[0] for e in r["errors"]) == ["quality", "semgrep"]


def test_report_has_both_sections():
    q = [{"tool": "quality", "rule": "CS-02", "severity": "LOW", "file": "a.py", "line": 6, "message": "print", "fix": "log"}]
    body = app.report([], {}, q, [])
    assert "No security issues" in body and "Coding standards: 1 issue(s)" in body and "CS-02" in body
