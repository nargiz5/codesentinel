"""Measure the AI layer (sentinel_ai.py) on the labeled benchmark.

* Investigation: for every CodeSentinel alert on a labeled line, does the
  model's verdict agree with the label? The interesting numbers are how many
  of CodeSentinel's false positives the model recognizes, and how many real
  vulnerabilities it wrongly calls false positives.
* Remediation: for every function with a true-positive alert, does the
  proposed fix pass the deterministic verifier? Rejection reasons are listed.

Benchmark labels are stripped before code is shown to the model. Files are not
modified. Results depend on the model; the report names it.

Usage (local Ollama by default; see docs/AI_DESIGN.md for other endpoints)::

    ollama pull qwen2.5-coder:7b
    python benchmark/evaluate_ai.py --output benchmark/AI_RESULTS.md
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from codesentinel import RULE_INFO, Project, collect_python_files  # noqa: E402
from evaluate import CASES, CLASSES, load_labels  # noqa: E402
from sentinel_ai import (  # noqa: E402
    OpenAICompatibleClient, group_by_region, investigate, propose_fix, verify_fix,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", type=Path, help="write a Markdown report here")
    parser.add_argument("--prompt", choices=("neutral", "report"), default="neutral",
                        help="investigation prompt; 'report' also shows the analyzer's verdict")
    parser.add_argument("--skip-fixes", action="store_true", help="only measure investigation")
    args = parser.parse_args()
    client = OpenAICompatibleClient()
    labels = load_labels()

    rows = []          # (case, label, verdict, confidence)
    fixes = []         # (case lines, status, reason)
    files = collect_python_files([CASES])
    # The cases are analyzed as one project, so cross-module flows are included
    # and every fix is re-checked against the other modules too.
    all_findings = Project(files).run()
    for path in files:
        rel = path.relative_to(CASES).as_posix()
        source = path.read_text()
        findings = [f for f in all_findings if f.filename == str(path)]
        for finding in findings:
            label = labels.get((rel, finding.line))
            cls = CLASSES[str(RULE_INFO[finding.rule_id][2])]
            if label is None or label[1] != cls:
                continue
            result = investigate(source, finding, client, args.prompt)
            rows.append((f"{rel}:{finding.line}", label[0], result.verdict, result.confidence))
            print(f"investigate {rel}:{finding.line} ({label[0]}): {result.verdict}", file=sys.stderr)
        for region, group in ([] if args.skip_fixes else group_by_region(source, findings)):
            if not any(labels.get((rel, f.line), ("",))[0] == "vuln" for f in group):
                continue
            replacement, explanation = propose_fix(source, region, group, client)
            if replacement is None:
                fixes.append((f"{rel}:{region.start}-{region.end}", "no_fix", explanation))
            else:
                result = verify_fix(str(path), source, region, group, replacement,
                                    project_files=files)
                fixes.append((f"{rel}:{region.start}-{region.end}", result.status, result.reason))
            print(f"fix {fixes[-1][0]}: {fixes[-1][1]}", file=sys.stderr)

    real = [r for r in rows if r[1] == "vuln"]
    false_alarms = [r for r in rows if r[1] == "safe"]
    verdicts_real = Counter(r[2] for r in real)
    verdicts_fp = Counter(r[2] for r in false_alarms)
    statuses = Counter(f[1] for f in fixes)

    lines = [
        "# AI layer results", "",
        f"Model: `{client.model}` at `{client.url}`, investigation prompt: `{args.prompt}`", "",
        "## Investigation of CodeSentinel alerts", "",
        "| Alerts | true_positive | false_positive | uncertain |",
        "|--------|---:|---:|---:|",
        f"| Real vulnerabilities ({len(real)}) | {verdicts_real['true_positive']} | "
        f"**{verdicts_real['false_positive']}** (wrongly dismissed) | {verdicts_real['uncertain']} |",
        f"| CodeSentinel false positives ({len(false_alarms)}) | {verdicts_fp['true_positive']} | "
        f"**{verdicts_fp['false_positive']}** (recognized) | {verdicts_fp['uncertain']} |",
        "",
        *([] if args.skip_fixes else [
        "## Remediation of true positives", "",
        f"{statuses['verified']} of {len(fixes)} proposed fixes passed the verifier "
        f"({statuses['rejected']} rejected, {statuses['no_fix']} without a usable answer).", "",
        "| Function | Status | Reason |", "|---|---|---|",
        *["| `{}` | {} | {} |".format(case, status, reason.replace("|", "\\|"))
          for case, status, reason in fixes], ""]),
        "", "## Per alert", "", "| Case | Label | Verdict | Confidence |", "|---|---|---|---:|",
        *[f"| `{case}` | {label} | {verdict} | {conf:.2f} |" for case, label, verdict, conf in rows],
        "",
    ]
    report = "\n".join(lines)
    if args.output:
        args.output.write_text(report)
    print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
