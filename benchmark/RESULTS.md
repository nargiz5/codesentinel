# Benchmark results

31 vulnerable and 24 safe labeled sinks in `benchmark/cases/`.

Tools: Bandit 1.9.4, Semgrep 1.186.0

## Overall

| Tool | TP | FP | FN | TN | Precision | Recall | F1 | Alerts on unlabeled lines |
|------|---:|---:|---:|---:|----------:|-------:|---:|---------------------------:|
| CodeSentinel | 24 | 1 | 7 | 23 | 0.96 | 0.77 | 0.86 | 0 |
| Bandit | 22 | 10 | 9 | 14 | 0.69 | 0.71 | 0.70 | 4 |
| Semgrep | 26 | 13 | 5 | 11 | 0.67 | 0.84 | 0.74 | 3 |

## Per class (detected vulnerable / false alarms on safe)

| Class | CodeSentinel | Bandit | Semgrep |
|-------|---:|---:|---:|
| Code injection | 4/5 found, 0 FP | 4/5 found, 1 FP | 4/5 found, 0 FP |
| Command injection | 9/10 found, 0 FP | 10/10 found, 6 FP | 10/10 found, 4 FP |
| Deserialization | 3/3 found, 0 FP | 3/3 found, 1 FP | 3/3 found, 2 FP |
| Path traversal | 1/3 found, 1 FP | 0/3 found, 0 FP | 1/3 found, 4 FP |
| SQL injection | 7/7 found, 0 FP | 4/7 found, 2 FP | 5/7 found, 2 FP |
| XSS | 0/3 found, 0 FP | 1/3 found, 0 FP | 3/3 found, 1 FP |

## Per case

✓ = correct (vulnerable line reported, or safe line not reported), ✗ = wrong.

| Case | Expected | CodeSentinel | Bandit | Semgrep |
|------|----------|:-:|:-:|:-:|
| `cmd_injection.py:12` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:16` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:24` | safe (Command injection) | ✓ | ✗ | ✗ |
| `cmd_injection.py:29` | safe (Command injection) | ✓ | ✗ | ✓ |
| `cmd_injection.py:33` | safe (Command injection) | ✓ | ✗ | ✓ |
| `cmd_injection.py:37` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:41` | safe (Command injection) | ✓ | ✗ | ✗ |
| `cmd_injection.py:45` | vuln (Command injection) | ✗ | ✓ | ✓ |
| `cmd_injection.py:50` | safe (Command injection) | ✓ | ✗ | ✗ |
| `cmd_injection.py:55` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:60` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:66` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:72` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `cmd_injection.py:86` | safe (Command injection) | ✓ | ✗ | ✗ |
| `cmd_injection.py:92` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `code_injection.py:11` | vuln (Code injection) | ✓ | ✓ | ✓ |
| `code_injection.py:16` | vuln (Code injection) | ✓ | ✓ | ✓ |
| `code_injection.py:22` | vuln (Code injection) | ✓ | ✗ | ✗ |
| `code_injection.py:26` | safe (Code injection) | ✓ | ✗ | ✓ |
| `code_injection.py:30` | safe (Code injection) | ✓ | ✓ | ✓ |
| `code_injection.py:34` | vuln (Code injection) | ✓ | ✓ | ✓ |
| `code_injection.py:42` | vuln (Code injection) | ✗ | ✓ | ✓ |
| `crossmodule/service_utils.py:6` | vuln (Command injection) | ✓ | ✓ | ✓ |
| `deserialization.py:15` | vuln (Deserialization) | ✓ | ✓ | ✓ |
| `deserialization.py:20` | safe (Deserialization) | ✓ | ✓ | ✗ |
| `deserialization.py:24` | safe (Deserialization) | ✓ | ✓ | ✓ |
| `deserialization.py:29` | vuln (Deserialization) | ✓ | ✓ | ✓ |
| `deserialization.py:34` | safe (Deserialization) | ✓ | ✗ | ✗ |
| `deserialization.py:39` | safe (Deserialization) | ✓ | ✓ | ✓ |
| `deserialization.py:44` | vuln (Deserialization) | ✓ | ✓ | ✓ |
| `path_traversal.py:15` | vuln (Path traversal) | ✓ | ✗ | ✓ |
| `path_traversal.py:21` | safe (Path traversal) | ✓ | ✓ | ✗ |
| `path_traversal.py:28` | safe (Path traversal) | ✓ | ✓ | ✗ |
| `path_traversal.py:34` | vuln (Path traversal) | ✗ | ✗ | ✗ |
| `path_traversal.py:39` | vuln (Path traversal) | ✗ | ✗ | ✗ |
| `path_traversal.py:43` | safe (Path traversal) | ✓ | ✓ | ✓ |
| `path_traversal.py:48` | safe (Path traversal) | ✓ | ✓ | ✓ |
| `path_traversal.py:64` | safe (Path traversal) | ✓ | ✓ | ✗ |
| `path_traversal.py:74` | safe (Path traversal) | ✗ | ✓ | ✗ |
| `sql_injection.py:14` | vuln (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:20` | vuln (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:27` | vuln (SQL injection) | ✓ | ✗ | ✓ |
| `sql_injection.py:32` | safe (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:38` | safe (SQL injection) | ✓ | ✗ | ✗ |
| `sql_injection.py:42` | safe (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:50` | vuln (SQL injection) | ✓ | ✗ | ✗ |
| `sql_injection.py:54` | vuln (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:63` | vuln (SQL injection) | ✓ | ✗ | ✗ |
| `sql_injection.py:67` | vuln (SQL injection) | ✓ | ✓ | ✓ |
| `sql_injection.py:73` | safe (SQL injection) | ✓ | ✗ | ✗ |
| `xss.py:12` | vuln (XSS) | ✗ | ✗ | ✓ |
| `xss.py:17` | safe (XSS) | ✓ | ✓ | ✗ |
| `xss.py:22` | vuln (XSS) | ✗ | ✓ | ✓ |
| `xss.py:27` | vuln (XSS) | ✗ | ✗ | ✓ |
| `xss.py:32` | safe (XSS) | ✓ | ✓ | ✓ |
