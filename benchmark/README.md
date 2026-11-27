# Benchmark files

Every number in the documentation comes from a file in this directory. This page says what each file is and how to regenerate it.

## Labeled test cases

| File | Contents |
|---|---|
| [`cases/`](cases) | 31 vulnerable and 24 safe code snippets, each line labeled with `# expect: ...`. The first 51 were written before scoring; 4 were added later from the documented known gaps (one of which has since been fixed) |
| [`RESULTS.md`](RESULTS.md) | CodeSentinel, Bandit and Semgrep on these cases, per class and per line |
| [`evaluate.py`](evaluate.py) | Script that produces `RESULTS.md` |

```bash
pip install bandit==1.9.4 semgrep==1.186.0
git clone https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
git -C /tmp/semgrep-rules checkout a5ad171
python benchmark/evaluate.py --semgrep-rules /tmp/semgrep-rules/python --output benchmark/RESULTS.md
```

## Real code

| File | Contents |
|---|---|
| [`cves/cves.json`](cves/cves.json) | The five CVEs: versions, scan directories, and each tool's result with file and line. Write-up: [Known CVEs](../docs/CVE_VALIDATION.md) |
| [`real_world/alerts.json`](real_world/alerts.json) | The 28 alerts on CTFd, FlaskBB, pgAdmin and Redash, with the pinned commits and my review of each one. Write-up: [Real-world results](../docs/REAL_WORLD.md) |
| [`real_world/codeql.json`](real_world/codeql.json) | CodeQL's 40 alerts on the same four projects |
| [`realvuln/results.json`](realvuln/results.json) | Per-application scores on the RealVuln benchmark |
| [`realvuln/score_realvuln.py`](realvuln/score_realvuln.py) | Script that scores CodeSentinel and Semgrep against RealVuln's labels |

## AI layer

The two runs on the labeled cases use all 55 cases and the current verifier. All four runs use `qwen2.5-coder:7b`, run locally. Two prompts were compared: **report** tells the model a scanner flagged the code; **neutral** (the default) asks it to trace the value and list the checks before deciding. Design and discussion: [AI layer design](../docs/AI_DESIGN.md).

| File | Data | Prompt | Script |
|---|---|---|---|
| [`AI_RESULTS.md`](AI_RESULTS.md) | Labeled cases: verdicts and proposed fixes | report | [`evaluate_ai.py`](evaluate_ai.py) |
| [`AI_RESULTS_NEUTRAL.md`](AI_RESULTS_NEUTRAL.md) | Labeled cases: verdicts | neutral | [`evaluate_ai.py`](evaluate_ai.py) |
| [`AI_REAL_WORLD.md`](AI_REAL_WORLD.md) | The 28 real-project alerts | report | [`evaluate_ai_real_world.py`](evaluate_ai_real_world.py) |
| [`AI_REAL_WORLD_NEUTRAL.md`](AI_REAL_WORLD_NEUTRAL.md) | The 28 real-project alerts | neutral | [`evaluate_ai_real_world.py`](evaluate_ai_real_world.py) |

```bash
python benchmark/evaluate_ai.py --prompt report --output benchmark/AI_RESULTS.md
python benchmark/evaluate_ai.py --prompt neutral --skip-fixes --output benchmark/AI_RESULTS_NEUTRAL.md
python benchmark/evaluate_ai_real_world.py --prompt report --checkouts ~/rw --output benchmark/AI_REAL_WORLD.md
python benchmark/evaluate_ai_real_world.py --prompt neutral --checkouts ~/rw --output benchmark/AI_REAL_WORLD_NEUTRAL.md
```

`--checkouts` is a directory with the four projects at the commits in `real_world/alerts.json`.
