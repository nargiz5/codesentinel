# AI layer results

Model: `qwen2.5-coder:7b` at `http://localhost:11434/v1/chat/completions`, investigation prompt: `report`

## Investigation of CodeSentinel alerts

| Alerts | true_positive | false_positive | uncertain |
|--------|---:|---:|---:|
| Real vulnerabilities (24) | 23 | **0** (wrongly dismissed) | 1 |
| CodeSentinel false positives (1) | 1 | **0** (recognized) | 0 |

## Remediation of true positives

9 of 24 proposed fixes passed the verifier (15 rejected, 0 without a usable answer).

| Function | Status | Reason |
|---|---|---|
| `cmd_injection.py:89-92` | rejected | only allowed APIs: uses flask.request.args.get, which neither the original code nor the list of safe fix APIs contains |
| `cmd_injection.py:71-72` | verified |  |
| `cmd_injection.py:63-67` | verified |  |
| `cmd_injection.py:58-60` | verified |  |
| `cmd_injection.py:53-55` | verified |  |
| `cmd_injection.py:36-37` | rejected | no new risky arguments: passes 'input' in subprocess.run(), which the original code did not |
| `cmd_injection.py:15-16` | verified |  |
| `cmd_injection.py:11-12` | verified |  |
| `code_injection.py:33-34` | verified |  |
| `code_injection.py:20-22` | verified |  |
| `code_injection.py:14-17` | rejected | finding gone: CS-EVAL-001 still reported at line 20 |
| `code_injection.py:10-11` | rejected | only allowed APIs: uses flask.request.args.get, which neither the original code nor the list of safe fix APIs contains |
| `crossmodule/service_utils.py:5-6` | verified |  |
| `deserialization.py:42-44` | rejected | only allowed APIs: uses flask.request.args.get, which neither the original code nor the list of safe fix APIs contains |
| `deserialization.py:27-29` | rejected | function kept: 'yaml_unsafe_loader' is gone |
| `deserialization.py:13-15` | rejected | only allowed APIs: uses flask.request.data.decode, json.JSONDecodeError, which neither the original code nor the list of safe fix APIs contains |
| `path_traversal.py:13-16` | rejected | only allowed APIs: uses flask.request.args.get, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:66-67` | rejected | function kept: 'wrong_sanitizer' is gone |
| `sql_injection.py:57-63` | rejected | only allowed APIs: uses flask.request.form, sqlalchemy.text, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:53-54` | rejected | only allowed APIs: uses flask.request.args.get, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:49-50` | rejected | only allowed APIs: uses flask.request.args.get, sqlalchemy.text, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:23-27` | rejected | only allowed APIs: uses sqlalchemy.text, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:17-20` | rejected | only allowed APIs: uses flask.request.args.get, sqlalchemy.text, which neither the original code nor the list of safe fix APIs contains |
| `sql_injection.py:12-14` | rejected | only allowed APIs: uses flask.request.args.get, sqlalchemy.text, which neither the original code nor the list of safe fix APIs contains |


## Per alert

| Case | Label | Verdict | Confidence |
|---|---|---|---:|
| `cmd_injection.py:12` | vuln | true_positive | 1.00 |
| `cmd_injection.py:16` | vuln | true_positive | 1.00 |
| `cmd_injection.py:37` | vuln | true_positive | 1.00 |
| `cmd_injection.py:55` | vuln | uncertain | 0.00 |
| `cmd_injection.py:60` | vuln | true_positive | 1.00 |
| `cmd_injection.py:66` | vuln | true_positive | 1.00 |
| `cmd_injection.py:72` | vuln | true_positive | 1.00 |
| `cmd_injection.py:92` | vuln | true_positive | 1.00 |
| `code_injection.py:11` | vuln | true_positive | 1.00 |
| `code_injection.py:16` | vuln | true_positive | 1.00 |
| `code_injection.py:22` | vuln | true_positive | 1.00 |
| `code_injection.py:34` | vuln | true_positive | 1.00 |
| `crossmodule/service_utils.py:6` | vuln | true_positive | 1.00 |
| `deserialization.py:15` | vuln | true_positive | 1.00 |
| `deserialization.py:29` | vuln | true_positive | 1.00 |
| `deserialization.py:44` | vuln | true_positive | 1.00 |
| `path_traversal.py:15` | vuln | true_positive | 1.00 |
| `path_traversal.py:74` | safe | true_positive | 1.00 |
| `sql_injection.py:14` | vuln | true_positive | 1.00 |
| `sql_injection.py:20` | vuln | true_positive | 1.00 |
| `sql_injection.py:27` | vuln | true_positive | 1.00 |
| `sql_injection.py:50` | vuln | true_positive | 1.00 |
| `sql_injection.py:54` | vuln | true_positive | 1.00 |
| `sql_injection.py:63` | vuln | true_positive | 1.00 |
| `sql_injection.py:67` | vuln | true_positive | 1.00 |
