"""Score CodeSentinel and Semgrep on the RealVuln Python targets with the same rules.

Usage:
    python benchmark/realvuln/score_realvuln.py --realvuln Real-Vuln-Benchmark --repos checkouts/

``--realvuln`` is a clone of https://github.com/kolega-ai/Real-Vuln-Benchmark
(ground truth and its published Semgrep results); ``--repos`` holds one
checkout per ``realvuln-*`` Python target at the commit pinned in its
``benchmark-manifest.json``.

Matching follows RealVuln's documented rules: same file, CWE in acceptable_cwes,
line within [start-10, end+10]; non-scoring entries withhold findings on their
location; FP traps (is_vulnerable=false) count matches as false positives.
"""
import argparse, json, re, subprocess, sys
from pathlib import Path

CS = str(Path(__file__).resolve().parents[2] / "codesentinel.py")
RVB = REPOS = Path(".")
COVERED = {"89", "78", "77", "94", "95", "502", "22", "23", "79", "918", "1336", "601"}
CS_CWE = {"CS-SQL-001": "CWE-89", "CS-CMD-001": "CWE-78", "CS-EVAL-001": "CWE-95",
          "CS-DESER-001": "CWE-502", "CS-PATH-001": "CWE-22", "CS-XSS-001": "CWE-79",
          "CS-SSRF-001": "CWE-918", "CS-SSTI-001": "CWE-1336", "CS-REDIRECT-001": "CWE-601"}
# A finding may be credited under related CWEs the ground truth commonly uses.
ALIASES = {"CWE-95": {"CWE-94", "CWE-95"}, "CWE-78": {"CWE-78", "CWE-77"},
           "CWE-1336": {"CWE-1336", "CWE-94"}, "CWE-22": {"CWE-22", "CWE-23", "CWE-73"}}

def norm(p): 
    p = p.replace("\\", "/")
    while p.startswith("./"): p = p[2:]
    return p.lstrip("/")

def codesentinel(repo, low):
    args = [sys.executable, "-I", CS, ".", "--json"] + (["--include-low-confidence"] if low else [])
    out = subprocess.run(args, cwd=REPOS / repo, capture_output=True, text=True, timeout=600).stdout
    return [(norm(f["filename"]), CS_CWE[f["rule_id"]], f["line"]) for f in json.loads(out or "[]")]

def semgrep(repo):
    path = RVB / "scan-results" / repo / "semgrep" / "results.json"
    if not path.exists(): return None
    found = []
    for r in json.load(open(path)).get("results", []):
        cwes = r.get("extra", {}).get("metadata", {}).get("cwe", [])
        cwes = [cwes] if isinstance(cwes, str) else cwes
        for c in cwes:
            m = re.match(r"CWE-(\d+)", c)
            if m: found.append((norm(r["path"]), f"CWE-{m.group(1)}", r.get("start", {}).get("line")))
    return found

def within(line, loc):
    s, e = loc.get("start_line"), loc.get("end_line")
    if line is None or s is None: return True
    return s - 10 <= line <= (e if e is not None else s) + 10

def hits(f, entry, cwe_check=True):
    file, cwe, line = f
    if cwe_check and not (ALIASES.get(cwe, {cwe}) & set(entry["acceptable_cwes"])): return False
    locs = [dict(entry.get("location", {}), file=norm(entry["file"]))] + [
        dict(l, file=norm(l.get("file", ""))) for l in entry.get("acceptable_locations", [])]
    return any(file == l["file"] and within(line, l) for l in locs)

def score(findings, gt):
    scored = [e for e in gt if e.get("scoring", "scored") == "scored"]
    ns = [e for e in gt if e.get("scoring") == "non_scoring"]
    tp_ids, fp, tp_f = set(), 0, 0
    for f in findings:
        m = [e for e in scored if hits(f, e)]
        if m:
            vuln = [e for e in m if e["is_vulnerable"]]
            if vuln: tp_ids.add(vuln[0]["id"]); tp_f += 1
            else: fp += 1
        elif f[2] is not None and any(hits(f, e, cwe_check=False) for e in ns):
            continue
        else: fp += 1
    vulns = [e for e in scored if e["is_vulnerable"]]
    cov = [e for e in vulns if any(re.match(r"CWE-(\d+)", c).group(1) in COVERED for c in e["acceptable_cwes"])]
    return dict(findings=len(findings), tp_findings=tp_f, fp=fp, found=len(tp_ids), vulns=len(vulns),
                found_cov=len([e for e in cov if e["id"] in tp_ids]), vulns_cov=len(cov))

def main():
    global RVB, REPOS
    parser = argparse.ArgumentParser()
    parser.add_argument("--realvuln", type=Path, required=True)
    parser.add_argument("--repos", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("realvuln-results.json"))
    args = parser.parse_args()
    RVB, REPOS = args.realvuln, args.repos
    repos = sorted(p.name for p in REPOS.iterdir() if p.is_dir())
    rows = {}
    for repo in repos:
        gt = json.load(open(RVB / "ground-truth" / repo / "ground-truth.json"))["findings"]
        sg = semgrep(repo)
        rows[repo] = {"codesentinel": score(codesentinel(repo, False), gt),
                      "codesentinel_low": score(codesentinel(repo, True), gt),
                      "semgrep": score(sg, gt) if sg is not None else None}
        print(repo, rows[repo]["codesentinel"], rows[repo]["semgrep"], file=sys.stderr)
    json.dump(rows, open(args.output, "w"), indent=1)
    for tool in ("codesentinel", "semgrep"):
        t = {k: sum(v[tool][k] for v in rows.values() if v[tool]) for k in
             ("tp_findings", "fp", "found", "vulns", "found_cov", "vulns_cov")}
        print(f"{tool}: precision {t['tp_findings'] / max(1, t['tp_findings'] + t['fp']):.2f}, "
              f"recall {t['found'] / t['vulns']:.3f}, "
              f"recall in covered classes {t['found_cov'] / t['vulns_cov']:.3f}")

main()
