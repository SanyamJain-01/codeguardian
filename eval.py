"""Measure CodeGuardian's security agent on labelled samples.

Run from the project folder with your keys loaded:
    set -a; source .env; set +a; python eval.py

Each sample is a small file that either has one known vulnerability (its line ends with #!) or is a safe
lookalike. The script runs the real scanners and the real LLM on every sample, then reports how much was
caught, how much was noise, and what the LLM's false-positive labels changed. Results go to EVAL_RESULTS.md.
"""
import secrets
import statistics
import tempfile
import time
from datetime import date
from pathlib import Path

import agents
import app

# (name, code, vulnerable). In vulnerable samples the vulnerable line ends with "#!" (removed before scanning).
CASES = [
    ("sqli_percent", '''
import sqlite3
def find(name):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM users WHERE name = '%s'" % name).fetchall()  #!
''', True),
    ("sqli_fstring", '''
import sqlite3
def delete(order_id):
    sqlite3.connect("app.db").execute(f"DELETE FROM orders WHERE id = {order_id}")  #!
''', True),
    ("sqli_format", '''
import sqlite3
def rename(user_id, new_name):
    sqlite3.connect("app.db").execute("UPDATE users SET name = '{}' WHERE id = {}".format(new_name, user_id))  #!
''', True),
    ("shell_true", '''
import subprocess
def run(cmd):
    return subprocess.run(cmd, shell=True)  #!
''', True),
    ("os_system", '''
import os
def ping(host):
    os.system("ping -c 1 " + host)  #!
''', True),
    ("eval_input", '''
def calculate(expr):
    return eval(expr)  #!
''', True),
    ("pickle_loads", '''
import pickle
def load(data):
    return pickle.loads(data)  #!
''', True),
    ("yaml_load", '''
import yaml
def parse(text):
    return yaml.load(text, Loader=yaml.Loader)  #!
''', True),
    ("hardcoded_token", '''
API_TOKEN = "ghp_{token}"  #!
def headers():
    return {"Authorization": "Bearer " + API_TOKEN}
''', True),
    ("md5_password", '''
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  #!
''', True),
    ("tls_off", '''
import requests
def fetch(url):
    return requests.get(url, verify=False, timeout=5).text  #!
''', True),
    ("flask_debug", '''
from flask import Flask
app = Flask(__name__)
if __name__ == "__main__":
    app.run(debug=True)  #!
''', True),
    # safe lookalikes: same libraries, used correctly
    ("safe_sql_params", '''
import sqlite3
def find(name):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
''', False),
    ("safe_sql_constant", '''
import sqlite3
def count():
    return sqlite3.connect("app.db").execute("SELECT COUNT(*) FROM users").fetchone()[0]
''', False),
    ("safe_subprocess_list", '''
import subprocess
def ping(host):
    return subprocess.run(["ping", "-c", "1", host], check=True)
''', False),
    ("safe_literal_eval", '''
import ast
def parse_list(text):
    return ast.literal_eval(text)
''', False),
    ("safe_json", '''
import json
def load(data):
    return json.loads(data)
''', False),
    ("safe_yaml", '''
import yaml
def parse(text):
    return yaml.safe_load(text)
''', False),
    ("safe_env_token", '''
import os
API_TOKEN = os.environ["API_TOKEN"]
def headers():
    return {"Authorization": "Bearer " + API_TOKEN}
''', False),
    ("safe_sha256", '''
import hashlib
def checksum(data):
    return hashlib.sha256(data).hexdigest()
''', False),
    ("safe_tls", '''
import requests
def fetch(url):
    return requests.get(url, timeout=5).text
''', False),
    ("safe_random_token", '''
import secrets
def new_session_id():
    return secrets.token_hex(16)
''', False),
]


def materialise(code):
    """(file text, vulnerable line numbers). A fake token is made at runtime so no secret-like string is committed."""
    lines = code.strip("\n").replace("{token}", secrets.token_hex(18)).splitlines()
    targets = {n for n, line in enumerate(lines, 1) if line.rstrip().endswith("#!")}
    text = "\n".join(line[:line.rfind("#!")].rstrip() if n in targets else line for n, line in enumerate(lines, 1))
    return text + "\n", targets


def run_case(name, code):
    """Scan one sample in its own folder. Returns (findings with labels, errors, seconds)."""
    text, targets = materialise(code)
    with tempfile.TemporaryDirectory() as root:
        file = f"{name}.py"
        (Path(root) / file).write_text(text)
        start = time.perf_counter()
        found, errors = app.scan(root, [file])
        try:
            notes = app.triage(root, found)
        except Exception as e:  # measure the scanners anyway
            notes, errors = {}, errors + [f"llm: {e}"[:120]]
        seconds = time.perf_counter() - start
    return [{"rule": f"{f['tool']}/{f['rule']}", "line": f["line"], "severity": f["severity"],
             "real": f["line"] in targets,
             "dismissed": bool(notes.get(i, {}).get("false_positive"))} for i, f in enumerate(found)], errors, seconds


def summarise(results):
    """results: [(name, vulnerable, findings, seconds)] -> metrics for scanners alone and scanners + LLM."""
    def stage(keep):
        vulnerable = [r for r in results if r[1]]
        caught = [r for r in vulnerable if any(f["real"] and keep(f) for f in r[2])]
        kept = [f for r in results for f in r[2] if keep(f)]
        real = [f for f in kept if f["real"]]
        return {"recall": len(caught) / len(vulnerable) if vulnerable else 0,
                "precision": len(real) / len(kept) if kept else 0,
                "noise": len(kept) - len(real), "missed": [r[0] for r in vulnerable if r not in caught]}

    findings = [f for r in results for f in r[2]]
    noise = [f for f in findings if not f["real"]]
    return {"scanners": stage(lambda f: True),
            "with_llm": stage(lambda f: not f["dismissed"]),
            "noise_dismissed": sum(f["dismissed"] for f in noise), "noise_total": len(noise),
            "real_dismissed": sum(f["dismissed"] for f in findings if f["real"]),
            "seconds": statistics.median(r[3] for r in results)}


def main():
    results, errors = [], set()
    for name, code, vulnerable in CASES:
        found, errs, seconds = run_case(name, code)
        errors.update(e.split(":")[0] for e in errs)
        results.append((name, vulnerable, found, seconds))
        flag = "caught" if any(f["real"] for f in found) else ("MISSED" if vulnerable else "safe")
        print(f"{name:22} {flag:7} {len(found)} finding(s)  {seconds:5.1f}s")

    m = summarise(results)
    s, l = m["scanners"], m["with_llm"]
    pct = lambda x: f"{x:.0%}"
    llm_note = "" if agents.LLM_KEY else "\n\n**No LLM key was set, so the LLM rows equal the scanner rows.**"
    report = f"""# CodeGuardian evaluation ({date.today()})

{len(CASES)} labelled Python samples: {sum(c[2] for c in CASES)} with one known vulnerability each, \
{sum(not c[2] for c in CASES)} safe lookalikes using the same libraries correctly. Generated by `eval.py`.

| | Scanners only | Scanners + LLM labels |
|---|---|---|
| Vulnerabilities caught (recall) | {pct(s['recall'])} | {pct(l['recall'])} |
| Reported findings that are real (precision) | {pct(s['precision'])} | {pct(l['precision'])} |
| Noise findings shown | {s['noise']} | {l['noise']} |

- The LLM labelled **{m['noise_dismissed']} of {m['noise_total']}** noise findings as likely false positives.
- It wrongly dismissed **{m['real_dismissed']}** real vulnerabilities.
- Median time per file (scanners + LLM): **{m['seconds']:.1f} s**.
- Missed vulnerabilities: {", ".join(l['missed']) or "none"}.{llm_note}
""" + (f"\nScanners or LLM not run on some samples: {', '.join(sorted(errors))}.\n" if errors else "")
    Path("EVAL_RESULTS.md").write_text(report)
    print("\n" + report)


if __name__ == "__main__":
    main()
