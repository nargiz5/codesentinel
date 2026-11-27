"""Score CodeSentinel, Bandit and Semgrep on the labeled benchmark cases.

Every sink line in ``cases/`` carries a label comment::

    os.system("ping " + host)  # expect: vuln CWE-78
    os.system("uptime")        # expect: safe CWE-78

A tool alert counts for a label when it is on the same file and line and
belongs to the same vulnerability class. Alerts on unlabeled lines (such as
Bandit's ``import subprocess`` warnings) are counted separately.

Usage::

    python benchmark/evaluate.py [--semgrep-rules PATH] [--output RESULTS.md]

Bandit and Semgrep are optional: a tool that is not installed is skipped.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = HERE / "cases"
sys.path.insert(0, str(HERE.parent))

from codesentinel import RULE_INFO, Project, collect_python_files  # noqa: E402

LABEL = re.compile(r"#\s*expect:\s*(vuln|safe)\s+CWE-(\d+)")
CLASSES = {
    "78": "Command injection", "77": "Command injection",
    "89": "SQL injection",
    "94": "Code injection", "95": "Code injection",
    "502": "Deserialization",
    "22": "Path traversal", "23": "Path traversal", "73": "Path traversal",
    "79": "XSS", "80": "XSS",
}
# Tool-specific fixes where the reported CWE does not name the class.
BANDIT_TEST_CLASS = {"B102": "Code injection", "B307": "Code injection",
                     "B506": "Deserialization"}
SEMGREP_KEYWORDS = (("sql", "SQL injection"),)


def load_labels() -> dict[tuple[str, int], tuple[str, str]]:
    labels = {}
    for path in sorted(CASES.rglob("*.py")):
        rel = path.relative_to(CASES).as_posix()
        for number, line in enumerate(path.read_text().splitlines(), start=1):
            match = LABEL.search(line)
            if match:
                labels[(rel, number)] = (match.group(1), CLASSES[match.group(2)])
    return labels


def run_codesentinel() -> set[tuple[str, int, str]]:
    alerts = set()
    for f in Project(collect_python_files([CASES])).run():
        cls = CLASSES.get(str(RULE_INFO[f.rule_id][2]))
        if cls is None:     # a rule class the benchmark does not label
            continue
        alerts.add((Path(f.filename).relative_to(CASES).as_posix(), f.line, cls))
    return alerts


def run_bandit() -> set[tuple[str, int, str]] | None:
    if not shutil.which("bandit"):
        return None
    out = subprocess.run(["bandit", "-r", str(CASES), "-f", "json", "-q"],
                         capture_output=True, text=True).stdout
    alerts = set()
    for r in json.loads(out)["results"]:
        cls = BANDIT_TEST_CLASS.get(r["test_id"]) or CLASSES.get(str(r["issue_cwe"]["id"]))
        if cls:
            rel = Path(r["filename"]).resolve().relative_to(CASES).as_posix()
            alerts.add((rel, r["line_number"], cls))
    return alerts


def run_semgrep(rules: Path | None) -> set[tuple[str, int, str]] | None:
    if not shutil.which("semgrep") or rules is None:
        return None
    out = subprocess.run(["semgrep", "--config", str(rules), "--metrics=off",
                          "--json", "-q", str(CASES)],
                         capture_output=True, text=True).stdout
    alerts = set()
    for r in json.loads(out)["results"]:
        cls = None
        for cwe in r["extra"].get("metadata", {}).get("cwe") or []:
            cls = cls or CLASSES.get(re.match(r"CWE-(\d+)", cwe).group(1))
        for keyword, name in SEMGREP_KEYWORDS:
            if cls is None and keyword in r["check_id"].lower():
                cls = name
        if cls:
            rel = Path(r["path"]).resolve().relative_to(CASES).as_posix()
            alerts.add((rel, r["start"]["line"], cls))
    return alerts


def score(labels, alerts):
    hits = {(f, l) for (f, l, c) in alerts if labels.get((f, l), (None, None))[1] == c}
    counts = defaultdict(lambda: defaultdict(int))
    for key, (kind, cls) in labels.items():
        found = key in hits
        outcome = {("vuln", True): "TP", ("vuln", False): "FN",
                   ("safe", True): "FP", ("safe", False): "TN"}[(kind, found)]
        counts[cls][outcome] += 1
        counts["All"][outcome] += 1
    other = len({(f, l) for (f, l, c) in alerts if (f, l) not in labels})
    return counts, hits, other


def ratio(a, b):
    return f"{a / b:.2f}" if b else "n/a"


def report(labels, results, versions) -> str:
    lines = ["# Benchmark results", "",
             f"{sum(k == 'vuln' for k, _ in labels.values())} vulnerable and "
             f"{sum(k == 'safe' for k, _ in labels.values())} safe labeled sinks "
             f"in `benchmark/cases/`.", "",
             "Tools: " + ", ".join(f"{t} {v}" for t, v in versions.items()), "",
             "## Overall", "",
             "| Tool | TP | FP | FN | TN | Precision | Recall | F1 | Alerts on unlabeled lines |",
             "|------|---:|---:|---:|---:|----------:|-------:|---:|---------------------------:|"]
    scored = {}
    for tool, alerts in results.items():
        counts, hits, other = score(labels, alerts)
        scored[tool] = (counts, hits)
        c = counts["All"]
        p = c["TP"] / (c["TP"] + c["FP"]) if c["TP"] + c["FP"] else 0
        r = c["TP"] / (c["TP"] + c["FN"]) if c["TP"] + c["FN"] else 0
        f1 = 2 * p * r / (p + r) if p + r else 0
        lines.append(f"| {tool} | {c['TP']} | {c['FP']} | {c['FN']} | {c['TN']} | "
                     f"{p:.2f} | {r:.2f} | {f1:.2f} | {other} |")
    classes = sorted({cls for _, cls in labels.values()})
    lines += ["", "## Per class (detected vulnerable / false alarms on safe)", "",
              "| Class | " + " | ".join(results) + " |",
              "|-------|" + "|".join("---:" for _ in results) + "|"]
    for cls in classes:
        cells = []
        for tool in results:
            c = scored[tool][0][cls]
            cells.append(f"{c['TP']}/{c['TP'] + c['FN']} found, {c['FP']} FP")
        lines.append(f"| {cls} | " + " | ".join(cells) + " |")
    lines += ["", "## Per case", "",
              "✓ = correct (vulnerable line reported, or safe line not reported), "
              "✗ = wrong.", "",
              "| Case | Expected | " + " | ".join(results) + " |",
              "|------|----------|" + "|".join(":-:" for _ in results) + "|"]
    for (path, line), (kind, cls) in sorted(labels.items()):
        cells = []
        for tool in results:
            found = (path, line) in scored[tool][1]
            cells.append("✓" if found == (kind == "vuln") else "✗")
        lines.append(f"| `{path}:{line}` | {kind} ({cls}) | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True).stdout.split("\n")[0].strip()
    except OSError:
        return "?"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--semgrep-rules", type=Path,
                        help="Semgrep rules directory (e.g. semgrep-rules/python)")
    parser.add_argument("--output", type=Path, help="Write the Markdown report here")
    args = parser.parse_args()

    labels = load_labels()
    results = {"CodeSentinel": run_codesentinel()}
    versions = {}
    bandit = run_bandit()
    if bandit is not None:
        results["Bandit"] = bandit
        versions["Bandit"] = version(["bandit", "--version"]).split()[-1]
    semgrep = run_semgrep(args.semgrep_rules)
    if semgrep is not None:
        results["Semgrep"] = semgrep
        versions["Semgrep"] = version(["semgrep", "--version"])
    text = report(labels, results, versions)
    if args.output:
        args.output.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
