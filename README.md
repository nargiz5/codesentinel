# CodeSentinel: taint analysis for Python web applications

[![Tests](https://github.com/nargiz5/codesentinel/actions/workflows/tests.yml/badge.svg)](https://github.com/nargiz5/codesentinel/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

CodeSentinel is a security scanner for Python web applications. It looks for places where data sent by a user (a URL parameter, a form field, a cookie) reaches a dangerous operation, such as a shell command or an SQL query, without being made safe first. For every problem it finds, it shows the path the data took, even across functions and files.

## Why I built it

This is a learning and research project. I work with security scanners in CI/CD pipelines, and I wanted to understand how such tools decide what is dangerous. So I built one myself and compared its results with established tools (CodeQL, Semgrep and Bandit) on real code.

The questions I wanted to answer:

- How do you follow user data through a whole program, across functions and files?
- Why do scanners raise so many false alarms, and how can they be reduced without missing real bugs?
- Can a language model help sort real alerts from false ones, and can its suggested fixes be trusted?

The tool can be run in CI, but its main purpose is to explore these questions and measure the answers.

## How it works, in one picture

The method is called **taint analysis**. Data from the user is marked as *tainted*. The analyzer follows tainted values through assignments, function calls and files. If a tainted value reaches a dangerous call (a *sink*) without passing through something that makes it safe (a *sanitizer*), it is reported.

```
  SOURCE                      PROPAGATION                       SINK
  where user data enters      how it moves                      where it becomes dangerous

  request.args["host"]  ──►  cmd = "ping " + host   ──►  run(cmd)  ──►  os.system(cmd)
                                                          (another file)       │
                                                                               ▼
                                                                 reported: command injection

  request.args["host"]  ──►  shlex.quote(host)  ──►  ...  ──►  os.system(...)
                             (SANITIZER: safe for a shell)              │
                                                                        ▼
                                                                  not reported
```

The same idea in code:

```python
host = request.args.get("host")
os.system("ping " + host)               # reported: user data reaches a shell
os.system("ping " + shlex.quote(host))  # not reported: quoted for the shell
os.system("uptime")                     # not reported: no user data
```

## A real example

pgAdmin 4, a widely used PostgreSQL administration tool, had a remote code execution bug, [CVE-2024-3116](https://nvd.nist.gov/vuln/detail/cve-2024-3116). The user's input is read in one file and executed as a command in another. CodeSentinel reports it with the full path:

```
pgadmin/utils/__init__.py:350:19: HIGH CS-CMD-001: Potential command injection [source=request.data, sink=subprocess.run]
    source pgadmin/misc/__init__.py:231  request.data                  ← user data is read here
    call   pgadmin/misc/__init__.py:238  get_binary_path_versions      ← passed to a function in another file
    sink   pgadmin/utils/__init__.py:350  subprocess.run               ← and executed as a command here
```

## Results

| What was tested | Result |
|---|---|
| [RealVuln](docs/REAL_WORLD.md#an-external-benchmark-realvuln): 26 intentionally vulnerable apps, labeled by other researchers | **87% of alerts are real** (53 of 61). Semgrep, in the same vulnerability classes: 65%. |
| [5 published CVEs](docs/CVE_VALIDATION.md) in real Python web apps | **Found 3.** CodeQL also found 3, a different set; **together they find 4.** [CVE-2022-0339](https://nvd.nist.gov/vuln/detail/CVE-2022-0339) in calibre-web was found only by CodeSentinel. |
| [4 mature Flask apps](docs/REAL_WORLD.md) (CTFd, FlaskBB, pgAdmin, Redash) | **10 alerts**, against 40 for CodeQL, 165 for Semgrep and 689 for Bandit. Every alert was reviewed by hand. The review also pointed to a policy question in pgAdmin: its URL check allows the server to contact any port on localhost. |
| [Labeled test cases](benchmark/RESULTS.md) (31 vulnerable, 24 safe) | **Precision 0.96, recall 0.77.** Bandit: 0.69 / 0.71. Semgrep: 0.67 / 0.84. |

## What I found

Short answers to the three questions above:

1. **Following data across files matters.** Two of the three CVEs CodeSentinel found (in pgAdmin and calibre-web) are visible only by following calls into another module. Remembering each function's result for a given input keeps this fast.
2. **Most false alarms come from code that already protects itself.** On the Flask apps, 24 of the 28 places where user data reaches a dangerous call were protected by the project's own checks (such as `if is_safe_url(next):`). Recognizing such checks by what they do, not by their name, brought the 28 alerts down to 10 and hid none of the known vulnerabilities.
3. **A language model's verdict depends on how the question is asked.** Told that a scanner had flagged the code, a small local model called 23 of 24 false alarms real. Asked neutrally to trace the value first, it recognized 12 of them. Its suggested fixes also need checking: the verifier accepted 9 of 24.

Details are in [Real-world results](docs/REAL_WORLD.md) and [AI layer design](docs/AI_DESIGN.md).

## What it detects

| Vulnerability | Example of a dangerous call |
|---|---|
| SQL injection | `cursor.execute("... WHERE name = '" + name + "'")` |
| Command injection | `os.system(...)`, `subprocess.run(..., shell=True)` |
| Code injection | `eval(...)`, `exec(...)` |
| Unsafe deserialization | `pickle.loads(...)`, `yaml.load(...)` |
| Path traversal | `open(user_path)` |
| Server-side request forgery (SSRF) | `requests.get(user_url)` |
| Server-side template injection | `render_template_string(user_text)` |
| Open redirect | `redirect(user_url)` |
| Cross-site scripting (XSS) | explicit output calls such as `response.write(...)` |

It understands user input from Flask, Django, FastAPI/Starlette, aiohttp and Tornado. The full list of sources, sinks and sanitizers is in [Technical details](docs/DETAILS.md#capabilities).

## How the analysis works

The hard part of this kind of tool is not spotting `os.system(user_input)` in one function. It is deciding what is true about a value after it has passed through ten functions, three conditions and a loop, possibly in another file. CodeSentinel reads the source code without running it, and each step below solves one part of that problem:

| Step | Why it is needed |
|---|---|
| **Walk the program's syntax tree**, keeping for each variable the user inputs its value came from. | This is the core of taint tracking. |
| **Analyze both sides of every `if`, and repeat loops until nothing changes.** | The analyzer cannot know which branch will run, so it considers both. A loop can spread taint on a later pass, so it is repeated until the result is stable. |
| **Follow values into called functions and back out**, including into other files, and remember each function's result for a given input. | Real bugs often cross files, as in the pgAdmin example. Done naively, this explodes: a call tree only 24 levels deep, with each function calling the next twice, has over 16 million paths. Because each function is analyzed once per kind of input (which arguments are tainted), not once per path, that tree takes a few milliseconds. |
| **Record *which* kind of safety a sanitizer gives.** | `shlex.quote` makes a value safe for a shell, but not for SQL. |
| **Trust a project's own safety check only if it really checks.** | `if is_safe_url(next):` is trusted only if `is_safe_url` actually parses the URL and checks its host. A function named `is_safe` that just returns `True` is not trusted. |
| **Limit the work done per file.** | A malicious or unusual file cannot hang or crash a CI run. |

Details: [Technical details](docs/DETAILS.md#how-it-works).

## Usage

```bash
pip install git+https://github.com/nargiz5/codesentinel
codesentinel path/to/project/             # scan
codesentinel path/to/project/ --explain   # also show the source-to-sink path
codesentinel app.py --sarif > out.sarif   # output for GitHub code scanning
```

Python 3.10 or newer, no dependencies. To silence an alert you have reviewed, add `# codesentinel: ignore[CS-SQL-001]` to the line. A project can declare its own safety functions in `.codesentinel.json` ([details](docs/DETAILS.md#project-configuration)).

In GitHub Actions:

```yaml
- uses: nargiz5/codesentinel@main
  with:
    paths: src
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: codesentinel.sarif
```

It is also available as a [pre-commit](https://pre-commit.com) hook (`id: codesentinel`).

## The AI layer: can a model's fixes be trusted?

This part explores the third question. `sentinel-ai` asks a language model (by default a local one, through Ollama, so code does not leave the machine) to explain each finding and to propose a fix. **The model never has the final word.** A fix is accepted only after deterministic checks: CodeSentinel no longer reports the problem, the code still does the same kind of operation (deleting the query is not a fix), and no new risky call was added. The verifier is deliberately strict: with a small local model (`qwen2.5-coder:7b`), it accepted 9 of 24 proposed fixes. It rejected every fix that left the vulnerability in place or deleted the function; most other rejections were fixes that used an API the original code did not, such as SQLAlchemy's `text()`, which a person can still review. The analyzer itself does not depend on this layer and needs no model or network. Details: [AI layer design](docs/AI_DESIGN.md).

```bash
ollama pull qwen2.5-coder:7b       # or any OpenAI-compatible endpoint
sentinel-ai investigate app.py     # add the model's opinion to each finding
sentinel-ai fix app.py             # propose fixes, keep only verified ones
sentinel-ai fix app.py --apply     # write verified fixes to the file
```

## Scope

CodeSentinel focuses on one kind of problem, untrusted data reaching a dangerous call, and aims to be precise about it. Some things are outside that focus or not supported yet:

- Login, authentication and access-control bugs are not data-flow problems, so they are out of scope.
- Method calls on an object stored in a variable (`r = Runner(); r.run(x)`) are not followed yet; this is the next planned step.
- Cross-site scripting is detected only through explicit output calls.

The full list, with the planned next steps, is in [Technical details](docs/DETAILS.md#known-gaps-and-next-steps).

## Documentation

| Document | Read it for |
|---|---|
| [Known CVEs](docs/CVE_VALIDATION.md) | The five real vulnerabilities, compared with CodeQL and Semgrep |
| [Real-world results](docs/REAL_WORLD.md) | Results on open-source apps and on the RealVuln benchmark, with every alert reviewed |
| [Technical details](docs/DETAILS.md) | Rules, supported frameworks, how the analysis works, configuration |
| [AI layer design](docs/AI_DESIGN.md) | How model-suggested fixes are verified |
| [Benchmark files](benchmark/README.md) | What each results file contains and how to reproduce it |

## Tests

315 tests: 271 for the analyzer (vulnerable and safe code snippets) and 44 for the AI layer (with a mock model, no network). They run in CI on Python 3.10, 3.12 and 3.13.

```bash
python -m unittest discover -s tests
```

## Repository layout

```
codesentinel.py   the analyzer
sentinel_ai.py    AI layer: model-suggested fixes, verified by the analyzer
tests/            regression tests
benchmark/        labeled cases, CVE and real-world results, scripts to reproduce them
docs/             technical details and evaluation write-ups
action.yml        GitHub Action (.pre-commit-hooks.yaml for pre-commit)
```

## License

[MIT](LICENSE) © 2026 Nargiz Bakhshaliyeva
