# AI layer results

Model: `qwen2.5-coder:7b` at `http://localhost:11434/v1/chat/completions`, investigation prompt: `neutral`

## Investigation of CodeSentinel alerts

| Alerts | true_positive | false_positive | uncertain |
|--------|---:|---:|---:|
| Real vulnerabilities (24) | 22 | **0** (wrongly dismissed) | 2 |
| CodeSentinel false positives (1) | 0 | **0** (recognized) | 1 |


## Per alert

| Case | Label | Verdict | Confidence |
|---|---|---|---:|
| `cmd_injection.py:12` | vuln | true_positive | 1.00 |
| `cmd_injection.py:16` | vuln | true_positive | 1.00 |
| `cmd_injection.py:37` | vuln | true_positive | 1.00 |
| `cmd_injection.py:55` | vuln | true_positive | 1.00 |
| `cmd_injection.py:60` | vuln | true_positive | 1.00 |
| `cmd_injection.py:66` | vuln | true_positive | 1.00 |
| `cmd_injection.py:72` | vuln | true_positive | 1.00 |
| `cmd_injection.py:92` | vuln | true_positive | 1.00 |
| `code_injection.py:11` | vuln | true_positive | 1.00 |
| `code_injection.py:16` | vuln | true_positive | 1.00 |
| `code_injection.py:22` | vuln | true_positive | 1.00 |
| `code_injection.py:34` | vuln | true_positive | 1.00 |
| `crossmodule/service_utils.py:6` | vuln | uncertain | 0.50 |
| `deserialization.py:15` | vuln | true_positive | 1.00 |
| `deserialization.py:29` | vuln | true_positive | 1.00 |
| `deserialization.py:44` | vuln | true_positive | 1.00 |
| `path_traversal.py:15` | vuln | true_positive | 1.00 |
| `path_traversal.py:74` | safe | uncertain | 0.80 |
| `sql_injection.py:14` | vuln | true_positive | 1.00 |
| `sql_injection.py:20` | vuln | true_positive | 1.00 |
| `sql_injection.py:27` | vuln | true_positive | 1.00 |
| `sql_injection.py:50` | vuln | uncertain | 0.50 |
| `sql_injection.py:54` | vuln | true_positive | 1.00 |
| `sql_injection.py:63` | vuln | true_positive | 1.00 |
| `sql_injection.py:67` | vuln | true_positive | 1.00 |
