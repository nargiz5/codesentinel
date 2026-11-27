"""Measure AI triage on CodeSentinel's alerts in real projects.

On the labeled samples every alert is a real vulnerability, so they cannot
show whether the model recognizes false alarms. In four real Flask projects
24 of 28 alerts are false alarms (see ``real_world/alerts.json`` and
docs/REAL_WORLD.md). This script asks the model about each of them.

Setup: check out each project at the commit listed in ``alerts.json``::

    mkdir -p ~/rw && cd ~/rw
    git clone https://github.com/CTFd/CTFd && git -C CTFd checkout f9fa28b2f17b22ec6c631a5b745f47573966f7f2
    git clone https://github.com/flaskbb/flaskbb && git -C flaskbb checkout 63afaa41d6e012a917aa615efcda55531577c3b6
    git clone https://github.com/pgadmin-org/pgadmin4 && git -C pgadmin4 checkout fefe3c58221a58689c90d26b3aa5a6144e4f9f67
    git clone https://github.com/getredash/redash && git -C redash checkout f561a53dc55eeb3f20615be951560dc78bb23f4c

Then (local Ollama by default)::

    python benchmark/evaluate_ai_real_world.py --checkouts ~/rw --output benchmark/AI_REAL_WORLD.md
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from codesentinel import Project, collect_python_files  # noqa: E402
from sentinel_ai import OpenAICompatibleClient, investigate  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--checkouts", type=Path, required=True,
                        help="directory with CTFd/, flaskbb/, pgadmin4/ and redash/")
    parser.add_argument("--output", type=Path, help="write a Markdown report here")
    parser.add_argument("--prompt", choices=("neutral", "report"), default="neutral",
                        help="investigation prompt; 'report' also shows the analyzer's verdict")
    args = parser.parse_args()
    client = OpenAICompatibleClient()
    spec = json.loads((HERE / "real_world" / "alerts.json").read_text())

    rows = []      # (project, file, line, rule, label, verdict, confidence, explanation)
    missing = []
    for name, project in spec["projects"].items():
        root = args.checkouts / name
        files = collect_python_files([root / project["scan_dir"]])
        if not files:
            print(f"{name}: no checkout at {root}", file=sys.stderr)
            return 2
        findings = {(Path(f.filename).relative_to(root).as_posix(), f.line, f.rule_id): f
                    for f in Project(files).run()}
        for alert in project["alerts"]:
            finding = findings.get((alert["file"], alert["line"], alert["rule"]))
            if finding is None:
                missing.append(f"{name}/{alert['file']}:{alert['line']}")
                continue
            source = Path(finding.filename).read_text(encoding="utf-8")
            result = investigate(source, finding, client, args.prompt)
            rows.append((name, alert["file"], alert["line"], alert["rule"], alert["label"],
                         result.verdict, result.confidence, result.explanation))
            print(f"{name}/{alert['file']}:{alert['line']} ({alert['label']}): {result.verdict}",
                  file=sys.stderr)

    false_alarms = Counter(r[5] for r in rows if r[4] == "false_positive")
    review = Counter(r[5] for r in rows if r[4] == "needs_review")
    n_fp = sum(false_alarms.values())
    lines = [
        "# AI triage on real-project alerts", "",
        f"Model: `{client.model}` at `{client.url}`, investigation prompt: `{args.prompt}`", "",
        "Labels are my manual review of each alert (`benchmark/real_world/alerts.json`).", "",
        "| Alerts | model: true_positive | model: false_positive | model: uncertain |",
        "|---|---:|---:|---:|",
        f"| False alarms ({n_fp}) | {false_alarms['true_positive']} | "
        f"**{false_alarms['false_positive']}** (recognized) | {false_alarms['uncertain']} |",
        f"| Needs review ({sum(review.values())}) | {review['true_positive']} | "
        f"{review['false_positive']} | {review['uncertain']} |",
        "",
    ]
    if missing:
        lines += ["Alerts not reproduced by this version of CodeSentinel: "
                  + ", ".join(f"`{m}`" for m in missing), ""]
    lines += ["## Per alert", "", "| Alert | Rule | Label | Verdict | Confidence | Model's explanation |",
              "|---|---|---|---|---:|---|"]
    for name, file, line, rule, label, verdict, conf, why in rows:
        why = why.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| `{name}/{file}:{line}` | {rule} | {label} | {verdict} | {conf:.2f} | {why} |")
    report = "\n".join(lines) + "\n"
    if args.output:
        args.output.write_text(report, encoding="utf-8")
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
