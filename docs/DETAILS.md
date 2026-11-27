# CodeSentinel: technical details

This is the reference for CodeSentinel: how to run it, what it detects, how the analysis works and where it stops. For an overview, start with the [README](../README.md).

**In short:**

- **What it finds:** nine vulnerability classes: SQL injection, command injection, code injection, insecure deserialization, path traversal, XSS, SSRF, template injection and open redirect.
- **How:** it follows user data through the program (taint tracking), into functions and across files, and checks whether the data was made safe for the specific place it is used.
- **Output:** text, JSON or SARIF (for GitHub code scanning), each finding with its source-to-sink path.
- **Quality:** 315 tests, no third-party dependencies.

| Section | Contents |
|---|---|
| [Command-line usage](#command-line-usage) | Running it, exit codes, configuration, silencing findings |
| [Detailed example](#detailed-example) | One file, its findings and the JSON output |
| [Evaluation](#evaluation) | The hand-labeled benchmark |
| [Rules](#rules) and [Capabilities](#capabilities) | Sources, sinks, sanitizers, guards |
| [How it works](#how-it-works) and [Analysis](#analysis) | The analysis, step by step |
| [Known gaps](#known-gaps-and-next-steps) | What it does not do yet |

## Command-line usage

Requires Python 3.10 or newer; scanning code that uses `except*` needs 3.11+. No third-party dependencies.

```bash
git clone https://github.com/nargiz5/codesentinel.git
cd codesentinel
python codesentinel.py path/to/file.py
python codesentinel.py path/to/file.py --json   # JSON output
python codesentinel.py path/to/file.py --sarif  # SARIF 2.1.0 (GitHub code scanning)
python codesentinel.py path/to/dir/ path/to/other.py   # several files and directories
python codesentinel.py path/to/dir/ --include-low-confidence   # also show env/argv-only findings
python codesentinel.py path/to/dir/ --config my-rules.json     # project sanitizers and guards
python codesentinel.py path/to/dir/ --explain   # show source, calls followed and sink
```

```
usage: codesentinel.py [-h] [--json | --sarif] [--include-low-confidence] [--config FILE] [--explain] path [path ...]
```

All files given in one run are analyzed together, so calls between them are followed. Findings whose only sources are environment variables or command-line arguments are marked `confidence: low` (they are set by whoever runs the program) and are hidden unless `--include-low-confidence` is given.

Directories are searched recursively for `*.py` files; hidden directories (`.git`, `.venv`), `venv`, `node_modules`, `site-packages` and `__pycache__` are skipped. A file that cannot be read or parsed is reported on stderr and the scan continues.

| Exit code | Meaning |
|-----------|---------|
| `0` | No findings |
| `1` | At least one finding |
| `2` | No findings, but some file was skipped or only partially analyzed (or a single given file could not be read), or the configuration file is invalid |

### Project configuration

A project can declare its own sanitizers (functions whose result is safe), guards (checks used in a condition) and sources in `.codesentinel.json`, read from the current directory, or in a file given with `--config`:

```json
{
  "sanitizers": {"myapp.urls.safe_next": ["redirect"]},
  "guards": {"myapp.security.is_allowed_path": ["path"]},
  "sources": ["myapp.http.current_request.payload"]
}
```

Names are the dotted import paths of the functions. Contexts are `command`, `sql`, `html`, `path`, `url` (SSRF), `template` and `redirect`; an unknown context is an error (exit code 2). Declared names are trusted as written, so declare only functions you have reviewed. Most projects need no configuration, because guards are also recognized from what they do (see [Guards](#guards)).

### Silencing a finding

After reviewing a finding, mark the line so it is not reported again:

```python
os.system(build_cmd(host))  # codesentinel: ignore[CS-CMD-001]  host is validated in build_cmd
cursor.execute(query)       # codesentinel: ignore
```

`ignore[...]` silences only the listed rules; plain `ignore` silences every rule on that line. The comment may be on any line of a multi-line sink call, and only real comments count (the text inside a string does not). The number of silenced findings is printed on stderr, so suppressions stay visible.

## Detailed example

`app.py`:

```python
import os
import shlex
import sqlite3

def run(cmd):
    os.system("ping -c 1 " + cmd)

host = input("Host: ")
run(host)                                    # command injection
run(shlex.quote(host))                       # safe: quoted for the shell

conn = sqlite3.connect("app.db")
conn.execute(f"SELECT * FROM users WHERE name = '{host}'")   # SQL injection
conn.execute("SELECT * FROM users WHERE name = ?", (host,))  # safe: parameterized
```

```
$ python codesentinel.py app.py
app.py:6:5: HIGH CS-CMD-001: Potential command injection: untrusted data reaches a command execution sink. [source=input, sink=os.system]
app.py:13:1: HIGH CS-SQL-001: Potential SQL injection: untrusted data reaches a SQL execution query. [source=input, sink=conn.execute]
```

The command-injection finding is reported inside `run()`, because the tainted argument is followed into the function. The quoted call and the parameterized query are not reported.

With `--json`, each finding is an object:

```json
{
  "rule_id": "CS-CMD-001",
  "severity": "HIGH",
  "message": "Potential command injection: untrusted data reaches a command execution sink.",
  "source": "input",
  "sink": "os.system",
  "filename": "app.py",
  "line": 6,
  "column": 5,
  "confidence": "high",
  "trace": [
    {"kind": "source", "file": "app.py", "line": 8, "name": "input"},
    {"kind": "call", "file": "app.py", "line": 9, "name": "run"},
    {"kind": "sink", "file": "app.py", "line": 6, "name": "os.system"}
  ]
}
```

`trace` is the path behind the finding (`--explain` prints it): the source was read on line 8, passed to `run()` on line 9, and reached `os.system` on line 6.

## Evaluation

This section covers the labeled samples. The evaluations on code I did not write are in [Known CVEs](CVE_VALIDATION.md) (five CVEs, with CodeQL and Semgrep) and [Real-world results](REAL_WORLD.md) (eleven open-source applications and the RealVuln benchmark).

CodeSentinel was compared with [Bandit](https://github.com/PyCQA/bandit) 1.9.4 and [Semgrep](https://semgrep.dev) 1.186.0 (the `python/` rules of [semgrep-rules](https://github.com/semgrep/semgrep-rules) at commit `a5ad171`) on a small hand-labeled benchmark in [`benchmark/cases/`](../benchmark/cases): 31 vulnerable and 24 safe sink lines in six rule classes. The first 51 cases were written before scoring. Four more were added later on purpose from the [known gaps](#known-gaps-and-next-steps) (tuple unpacking, a check stored in a variable before the `if`), so that the benchmark also contains patterns CodeSentinel got wrong; tuple unpacking has since been fixed. The cases include cases that are hard for taint analysis (instance methods, `pathlib`, `send_file`, Flask HTML responses, cross-module calls, lambdas passed as arguments) as well as safe code that pattern matchers tend to flag (quoted, parameterized, numeric and whitelisted values). An alert counts when it is on the labeled line and in the same vulnerability class.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|------|---:|---:|---:|----------:|-------:|---:|
| CodeSentinel | 24 | 1 | 7 | **0.96** | 0.77 | **0.86** |
| Bandit | 22 | 10 | 9 | 0.69 | 0.71 | 0.70 |
| Semgrep | 26 | 13 | 5 | 0.67 | **0.84** | 0.74 |

What the numbers show:

- **Precision is where taint tracking pays off.** Bandit flags every `os.system` / `eval` / `pickle` call and Semgrep's audit rules do similar; CodeSentinel stays quiet on `shlex.quote`d commands, argv lists, numeric coercion and `secure_filename` paths. Dictionary allow-lists (`{...}.get(user_value, default)`) are not reported either, because a tainted lookup key does not taint the value it selects (see [Real-world results](REAL_WORLD.md)).
- **Its one false alarm is a known gap:** a path check stored in a variable first (`allowed = is_inside_base(name); if allowed:`) is not recognized, while the same check written directly in the `if` is.
- **SQL injection: 7/7**, including flows through helper return values, branches and a wrong-context sanitizer (`shlex.quote` in SQL), which both other tools partly miss.
- **Recall gaps are real:** XSS 0/3 (Flask route return values, `Markup` and `make_response` are not sinks), path traversal 1/3 (`pathlib`, `send_file`), plus method calls on an object stored in a variable (`r = Runner(); r.run(x)`), `subprocess.run(untrusted_string)` and lambdas passed as arguments. Cross-module flows and direct calls such as `self.run(x)` and `Runner(...).run(x)` are followed.

The benchmark is small and written by the author, and most of it was used during development, so it shows how the tool handles the patterns it was built for, not how it does on new code. With 25 alerts, the 95% Wilson interval for precision is 80–99%. For a measure on code I did not write, see [RealVuln](REAL_WORLD.md#an-external-benchmark-realvuln) (87% precision) and the [known CVEs](CVE_VALIDATION.md). Full per-case results are in [`benchmark/RESULTS.md`](../benchmark/RESULTS.md). To reproduce:

```bash
pip install bandit==1.9.4 semgrep==1.186.0
git clone https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules
git -C /tmp/semgrep-rules checkout a5ad171
python benchmark/evaluate.py --semgrep-rules /tmp/semgrep-rules/python --output benchmark/RESULTS.md
```

## Rules

| Rule | Severity | Detects |
|------|----------|---------|
| `CS-SQL-001` | HIGH | SQL injection |
| `CS-CMD-001` | HIGH | Command injection |
| `CS-EVAL-001` | HIGH | Dynamic code execution (`eval` / `exec`) |
| `CS-DESER-001` | HIGH | Insecure deserialization |
| `CS-PATH-001` | MEDIUM | Path traversal |
| `CS-XSS-001` | MEDIUM | Unescaped HTML output |
| `CS-SSRF-001` | MEDIUM | Server-side request forgery (untrusted URL of an outgoing request) |
| `CS-SSTI-001` | HIGH | Server-side template injection |
| `CS-REDIRECT-001` | MEDIUM | Open redirect |

Sinks and sanitizers for each rule are listed under [Sinks](#sinks) and [Sanitizers](#sanitizers).

## How it works

1. Every file is parsed into an AST with Python's `ast` module; all files given in one run form one project.
2. The analyzer walks the statements with an abstract environment that maps each variable name to the set of taint sources it carries, and the contexts (shell, SQL, path, ...) in which it has been made safe.
3. Each branch of an `if` knows the outcome of its test, so a passed [guard](#guards) makes the checked value safe inside it. At branch merges the states are joined by set union; loops are re-analyzed until the state stops changing (a fixed point).
4. Calls to the program's own functions, in the same file or another one, are analyzed with the argument taint and memoized as function summaries, so repeated calls are not re-analyzed.
5. When tainted data reaches a sink without being made safe for that sink's context, a finding is reported, with the path that led there: where the source was read, the calls followed, and the sink.

## Capabilities

### Sources

- `input()`, `sys.argv` and `sys.stdin`.
- `os.environ` (including `os.environ[...]`, `os.environ.get()` and `os.getenv()`).
- Flask-style `request.args`, `request.form`, `request.values`, `request.json`, `request.cookies`, `request.headers`, `request.data`, `request.files`, `request.get_json()` / `request.get_data()` and their `.get()` / subscript accessors (also through `from flask import request as req` and `flask.request`).
- Django / Django REST framework: `request.GET`, `request.POST`, `request.COOKIES`, `request.META`, `request.FILES`, `request.body`, `request.query_params` and their `.get()` accessors.
- Starlette / FastAPI: `request.path_params`, `request.query_params`, `await request.json()`, `await request.body()`, `await request.form()`.
- aiohttp: `request.match_info`, `request.query`, `request.rel_url`, `request.content`, `await request.post()` / `text()` / `read()` / `multipart()`.
- Flask-RESTful / RESTX: `parser.parse_args()` in a module that imports `reqparse` (so `argparse` is not confused with it).
- Tornado, inside `tornado.web.RequestHandler` subclasses only: `self.get_argument()` and its variants, `self.get_cookie()`, `self.request.body`, `.arguments`, `.query`, `.uri`, `.path`, `.headers`, `.files`.
- `http.server`, inside `BaseHTTPRequestHandler` (and `SimpleHTTPRequestHandler`, `CGIHTTPRequestHandler`) subclasses only: `self.path`, `self.headers`, `self.rfile`, `self.requestline`.
- Parameters of web route handlers (`@app.route`, `@router.get`, `@app.post`, ...) start tainted, and so do the parameters of the HTTP-method handlers (`get`, `post`, ...) of class-based views: Flask `MethodView` / `View`, Flask-RESTful and RESTX `Resource`, Django and DRF views, Starlette `HTTPEndpoint`, aiohttp `View`, Tornado handlers, including through a project's own base class. A Django view's `request` parameter itself is not data (its sources are tracked by name).

### Sinks

- **SQL (`CS-SQL-001`):** tainted query strings reaching `.execute()`, `.executemany()`, `.executescript()` and `.exec_driver_sql()` on a database-like receiver (a name containing `cur`, `conn`, `db`, `session`, `engine`, `sql`, ..., the short names `c`, `cr`, `con`, `s`, `self`, or a call such as `conn.cursor()`) unless the call resolves to a user-defined function, plus `pandas.read_sql()` / `read_sql_query()`. Parameterized queries are handled.
- **Command (`CS-CMD-001`):**
  - Always shell: `os.system()`, `os.popen()`, `subprocess.getoutput()` / `getstatusoutput()` and `asyncio.create_subprocess_shell()`.
  - `subprocess.run/call/check_call/check_output/Popen` when `shell=` is true. A non-literal `shell=` value is treated as true.
  - Argv-style execution (`subprocess` argv lists, given positionally, as `args=` or through a variable; `asyncio.create_subprocess_exec`; `os.exec*`, `os.spawn*`, `os.posix_spawn*`; `pty.spawn`) is reported when the program itself is untrusted or when argv explicitly starts a shell (`["sh", "-c", cmd]`), in which case the arguments after `-c` are checked. Ordinary argv-list calls with trusted programs, such as `["ping", "-c", "1", host]`, are not reported.
- **Dynamic code (`CS-EVAL-001`):** tainted arguments passed to `eval()` and `exec()`, including `builtins.exec`.
- **Deserialization (`CS-DESER-001`):** `pickle.load(s)`, `marshal.load(s)`, `dill.load(s)`, `yaml.unsafe_load()`, and `yaml.load()` unless it is given `SafeLoader`, `CSafeLoader` or `BaseLoader`.
- **Path (`CS-PATH-001`):** tainted paths passed to `open()` / `io.open()`. Command-line arguments (`sys.argv`) are not reported here, because a CLI tool opening the file its user names is the normal case; they still reach the other rules.
- **SSRF (`CS-SSRF-001`):** the URL argument of `requests.*`, `httpx.*`, `urllib.request.urlopen/Request` and `urllib3.request`. Untrusted query parameters or methods with a fixed URL are not reported.
- **Template injection (`CS-SSTI-001`):** `flask.render_template_string`, `jinja2.Template`, `django.template.Template` and `mako.template.Template` given an untrusted template source. `html.escape` does not make a template safe.
- **Open redirect (`CS-REDIRECT-001`):** `flask.redirect`, `django.shortcuts.redirect`, `HttpResponseRedirect` and Starlette/FastAPI `RedirectResponse`. URLs built by `flask.url_for` or `django.urls.reverse` are safe.
- **HTML (`CS-XSS-001`):** only `response.write()`, plus an `html_output()` placeholder used by the unit tests. Flask route return values, `Markup` and `make_response` are not sinks yet, which is why XSS is 0 of 3 on the samples.

### Sanitizers

| Sanitizer | Safe for |
|-----------|----------|
| `int()`, `float()` (numeric coercion) | SQL, command, path, HTML |
| `shlex.quote()` | Command |
| `os.path.basename()`, `werkzeug.utils.secure_filename()` | Path |
| `html.escape()` | HTML |
| `hexdigest()` results | every context |
| `flask.url_for()`, `django.urls.reverse()` | Redirect |
| SQLAlchemy `select/insert/update/delete` (and clauses chained on them) | SQL, because values are bound parameters; `text()` and `literal_column()` stay raw SQL |

Sanitization is context-specific: every sanitized value carries the set of contexts it is safe for. A sanitizer for one context never cancels taint of a different value, so `html.escape(a) + shlex.quote(b)` is still reported in a shell. Nested sanitizers keep the contexts of both. A sanitizer name rebound in the scope of the call (`def int(x): ...`, `int = str`) is not trusted; a parameter named `html` in one function does not affect other functions.

### Guards

A guard is a check in a condition. Inside the branch where the check passed, the checked value is safe for the guard's contexts:

```python
if is_safe_url(next_url):            # next_url is safe for redirects here
    return redirect(next_url)
if not is_safe_url(next_url):        # the same after an early exit
    abort(400)                       # (return, raise, abort(), sys.exit())
if plugin in installed_plugins:      # an allow-list the program built itself
    open(os.path.join(root, plugin))  # safe in every context
```

How conditions are read:

- **`and`, `or`, `not` are handled.** `a and b` being true proves both; `a or b` being false proves neither holds. So `if x is None or not is_safe(x): x = default` leaves `x` safe after the `if`.
- **A value is safe after an `if` only if it is safe on every path** that reaches the next statement. Each branch starts from the state before the `if`.
- **Repeated expressions count.** `if is_safe_url(request.args.get("next")): redirect(request.args.get("next"))` is recognized.
- **Safe-returning functions.** A function whose every return is a constant or a checked value (Redash's `get_next_path`) returns a safe value.

**Which functions count as guards.** Django's `url_has_allowed_host_and_scheme` is built in, and guards can be declared in the [configuration](#project-configuration). A project's own functions, in the same module or another scanned one, are recognized by what they do, never by their name. A function is a guard only if all of these hold:

1. it uses its first parameter;
2. it can return a false value;
3. it does both halves of a real check for a context, as in this table:

| Context | It must parse or normalize the value | and decide on the part that matters |
|---|---|---|
| Redirect | `urlparse`, `urlsplit` or `urljoin` | compare the host (`netloc` or `hostname`), directly or through a variable: `==`, `in`, `startswith`/`endswith`, `not host`, or a branch that returns `False` or raises when there is a host |
| URL (SSRF) | `urlparse`, `urlsplit`, `ip_address`, `getaddrinfo`, `gethostbyname` | read an address property (`is_private`, `is_loopback`, ...) or compare the `hostname` as above |
| Path | `realpath`, `abspath`, `normpath` or `Path.resolve` | compare it to a root (`startswith`, `commonpath`, `is_relative_to`, `.parents`) |

A function that calls another guard inherits its contexts.

**Regular expressions.** `re.fullmatch(pattern, x)`, or `re.match` with a pattern ending in `$` or `\Z`, is a guard for every context when:

- the pattern is a single character class of letters, digits, `_` and `-`, such as `[A-Za-z0-9_-]+` (such a value cannot hold a path separator, a scheme, a quote or a shell metacharacter);
- each range stays within lower-case letters, upper-case letters or digits (`[0-z]` and `[A-z]` also contain `; < > \ [ ] ^` and the backtick);
- no flags are passed (with `re.M`, `$` also matches before a newline, so `abc\nid` passes `[a-z]+$`).

A class that also allows `.` or `/`, a negated class, or an unanchored `re.match` is not a guard.

**Checks that look like guards but are not**, so the finding is still reported:

| Check | Why it is not enough |
|---|---|
| `return True`, `return bool(x)` | Decides nothing about the value |
| A check of a URL's scheme only | `https://evil.example` passes it |
| `return urlparse(u).netloc` or `urlparse(u).netloc != ""` | True exactly for external URLs, the dangerous case |
| `startswith` on a path that was not normalized | `/srv/files/../../etc/passwd` passes it |

**A guard for one context does not protect another:** a redirect check before `subprocess.run(x, shell=True)` is still a command injection.

These rules recognize the usual forms of these checks; they do not prove a check correct. A function that parses a URL and compares its host, but with the wrong value, would still be trusted. Every rule has positive and negative tests (see [Testing](#testing)).

### Analysis

- **Interprocedural propagation:** tracks tainted arguments into user-defined functions and tainted return values back to callers; analyzes sinks inside called functions. After module-level analysis, it also inspects uncalled function bodies once in a clean abstract environment (route handlers excepted, see [Sources](#sources)).
- **Cross-module calls:** a call that resolves through the caller's imports (absolute, relative, dotted or aliased, including `Class.method` and `Class(...).method`) to a function in another scanned file is analyzed in that file with the caller's argument taint, and a sink there is reported there. Module names follow packages (`__init__.py`), import cycles are handled, and a module that cannot be parsed is reported and skipped.
- **Lookups:** `table[key]`, `{...}.get(key, default)` and `store.data["items"].get(key)` take the taint of the container (and the default), not of the key: a user value can choose a stored value but does not change its content. ORM reads by key or filter return stored records for the same reason: `session.get(Model, key)`, `Model.query....first()` / `.get()` / `.all()` (and the `_or_404` forms), `Model.objects....get()`, `get_object_or_404()`. Raw SQL built inside such a call is still reported.
- **Function summaries:** call results are memoized per function, argument, module and closure taint. Functions that write globals cache their effect on the module environment too, so call trees stay linear even with `global` writers.
- **Control flow:** joins `if/else` states (narrowed by [guards](#guards); a branch that returns, raises or aborts does not reach the next statement, but still reaches the `except` and `finally` of an enclosing `try`), iterates loops to a fixed point (capped at 32 iterations), joins `try/except` and `try/except*` paths, analyzes every `match` case, and propagates taint through comprehensions and generator expressions.
- **Lambdas:** `f = lambda x: ...` is analyzed like `def f(x): return ...`, inside modules and functions.
- **Method calls:** the receiver of a method call is treated as an input, so taint survives string methods such as `value.strip()`, `input().lower()` and `template.format(...)`, and sinks nested in a receiver (`os.popen(x).read()`) are inspected.
- **Classes:** class-body statements, including nested class bodies, are executed and their bindings tracked as `Class.attr` / `Outer.Inner.attr`. Methods of module-level classes are registered as `Class.method`; calls through `self.method(...)` / `cls.method(...)` and explicit `Class.method(...)` are resolved with the receiver bound to the first parameter (respecting `@staticmethod` and `@classmethod`).
- **Imports and dynamic lookups:** `import x as y`, `from m import name [as alias]` and `from m import *` are resolved for known sources, sinks and sanitizers. `getattr(os, "system")`, `__import__("os").system` and `importlib.import_module("os")` with constant strings resolve to the real callee.
- **Scopes:** functions can read tainted module globals, and `global` declarations and `globals()["name"] = ...` write to the module environment. Nested functions read enclosing variables with late binding, as Python does: a closure called while its enclosing function is running sees that function's current values, and one that runs later sees the final values. `nonlocal` writes update the enclosing function's variable (as a weak update, since the write may be conditional).
- **Stores:** attribute stores (`o.cmd = input()`), `setattr(o, "cmd", x)`, subscript stores (`d["k"] = input()`), container mutators (`append`, `extend`, `insert`, `add`, `update`, `setdefault`, `appendleft`, `extendleft`) and walrus assignments (`:=`) propagate taint.

### Robustness and reporting

- A statement budget (default 1,000,000) and a recursion guard stop hostile or pathological inputs from hanging or crashing the analyzer. A truncated run is reported as incomplete instead of looking clean.
- Findings are printed in a human-readable format or as JSON with rule, per-rule severity, source, sink, filename and source location. Each finding carries a `trace`: the place its source was last read, the calls the analysis followed (across modules too) and the sink. `--explain` prints it, JSON includes it, and SARIF includes it as a `codeFlow`. The source step is the last read of that source before the sink, which is usually but not always the read that reached it. When several sources reach the same sink, they are merged into one finding. Multiple files and directories can be scanned in one run.

## AI-assisted investigation and verified remediation

`sentinel_ai.py` adds a language-model layer on top of the analyzer; the analyzer does not depend on it. The rule is that **the model proposes and the analyzer decides**:

- `investigate` annotates every finding with a verdict (`true_positive`, `false_positive` or `uncertain`), a short explanation and an example input. The verdict never hides a finding, because the analyzed code is untrusted input to the model and could contain a prompt injection.
- `fix` asks the model to rewrite only the function that contains the sink, then accepts the rewrite only if a deterministic verifier passes: the file parses, the function and an operation of the same kind are kept (deleting the query is not a fix), no new risky operation, risky argument or API outside an allowlist is added, CodeSentinel does not report the finding any more, no new finding appears anywhere in the file, and, with `--test-cmd`, the project's tests pass on a temporary copy. Files change only with `--apply`, and only for verified fixes.

```bash
ollama pull qwen2.5-coder:7b                        # or any OpenAI-compatible endpoint
python sentinel_ai.py investigate app.py
python sentinel_ai.py fix app.py --test-cmd "python -m pytest -q"
python sentinel_ai.py fix app.py --apply            # write verified fixes
```

The endpoint is set with `CODESENTINEL_LLM_URL`, `CODESENTINEL_LLM_MODEL` and `CODESENTINEL_LLM_API_KEY` (default: local Ollama, so code does not leave the machine). Like the analyzer, it uses only the standard library. The design and the verification rules are in [`docs/AI_DESIGN.md`](AI_DESIGN.md). "Verified" means verified against CodeSentinel and the given tests, not proven correct.

`benchmark/evaluate_ai.py` measures the layer on the labeled benchmark (how many of CodeSentinel's false positives the model recognizes, how many real vulnerabilities it wrongly dismisses, and how many fixes pass the verifier). With `qwen2.5-coder:7b` it dismissed none of the 24 real vulnerabilities (23 confirmed, 1 uncertain), and the verifier accepted 9 of 24 proposed fixes: 3 rejected fixes were real defects (vulnerability still reported, or function deleted), 1 added a command argument, and 11 used an API outside the allowlist, most often SQLAlchemy's `text()` (details in [AI layer design](AI_DESIGN.md#evaluation)). See [`benchmark/AI_RESULTS.md`](../benchmark/AI_RESULTS.md). `benchmark/evaluate_ai_real_world.py` asks the model about the 28 hand-reviewed alerts of the core analysis on four real projects, 24 of which are false alarms: with a prompt that states the analyzer's verdict it recognized 1, with the default neutral prompt (trace the value, list the checks, then decide) 12, plus 10 uncertain, still dismissing no real vulnerability on the samples ([discussion](REAL_WORLD.md#can-a-local-language-model-filter-these-false-alarms)). `--prompt report|neutral` selects the prompt in `sentinel_ai.py investigate` and both scripts.

## Testing

```bash
python -m unittest discover -s tests -v
```

The test suite contains 315 tests: 271 analyzer tests using vulnerable and safe snippets, and 44 tests of the AI layer that use a mock model (no network). It runs on every push to `main` and every pull request via GitHub Actions on Python 3.10, 3.12 and 3.13. It covers:

- direct and interprocedural flows, branch joins and loop fixed points;
- context-specific sanitization, including mixed and shadowed sanitizers and their scoping;
- guards (55 tests): recognized and rejected guard functions, early exits, nested conditions and branch merges, checks that must not leak into another branch or variable, incomplete or context-specific checks, functions that only read a host, guards in another module, character-class regular expressions (ranges and flags included), and the configuration file;
- traces (5 tests): within a module, across modules, route parameters, SARIF code flows;
- framework sources (15 tests): class-based views, Flask-RESTful `reqparse` (and `argparse` not being a source), aiohttp, Tornado and `http.server`, with the same names outside those classes staying clean, and records loaded by key;
- subprocess `shell` behavior, explicit shells and untrusted programs in argv lists, `os.exec*` / `os.spawn*`;
- environment, CLI and web sources and route parameters;
- dynamic-code, deserialization and path sinks;
- method-call receivers, container mutation, tuple unpacking, lambdas, class bodies (including nested ones) and methods;
- `globals()` writes, star imports and `getattr` lookups;
- closures (late binding) and `nonlocal` writes;
- analysis-cost bounds, the multi-file CLI and SARIF output;
- the AI layer: every verifier rule (including fake fixes that delete the sink, move the problem, break tests, or add a constant malicious command, replace the command or URL with another one, a network call, an unexpected import, a file write, a file move, an environment change, a signal, a call to a risky helper of the program or a `__dunder__` chain, which must be rejected before any test runs), label stripping, prompt-injection handling and the HTTP client.

## Known gaps and next steps

**Can cause missed vulnerabilities (false negatives):**

- Method calls on an object stored in a variable (`obj = Runner(); obj.run(...)`), inheritance, and lambdas passed directly as arguments are not resolved yet. This is the cause of the miss on [CVE-2024-2044](CVE_VALIDATION.md#why-codesentinel-missed-two).
- Flows are followed only into files that are part of the scan.
- Attribute taint is tracked per variable name rather than per object, so aliasing (two names for the same object) is not followed.
- Not yet sinks: `pathlib` file APIs, `send_file`, Flask route return values, `Markup`, `make_response` and non-shell `subprocess.run(cmd_string)`.
- `.execute()` is recognized as SQL by the receiver's name, so a database handle with an unusual name is missed.
- Route handlers are detected by decorator name only.

**Can cause false alarms (false positives):**

- Unpacking a value whose shape is unknown (`a, b = load_pair(input())`) taints all targets. Literal tuples (`a, b = "x", input()`) are handled element by element.
- An unrelated object whose name looks like a database (`db.execute(...)`) is treated as one.
- Conditions are used only through [guards](#guards): a check stored in a variable first (`ok = is_safe(x); if ok:`) is not followed, nor are facts that depend on two conditions together (`if x != 'internal' and not is_safe(x)` followed later by `if x != 'internal':`).
- There is no full control-flow graph.

**AI layer:**

- The model sees one function plus the module's imports, so its verdicts on flows across functions are less reliable.
- The fix verifier re-analyzes the whole project when the other files are known (the `fix` command and the benchmark). A single file given on its own is checked alone, so a fix that moves a problem into a module outside the scan is caught only by tests.
- "Verified" means verified against CodeSentinel and the given tests, not proven correct.
- Results depend on the model. So far one small local model (`qwen2.5-coder:7b`) has been measured, on the labeled samples and on 28 alerts from real projects.

## GitHub code scanning (SARIF)

`--sarif` writes a [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) log that validates against the official schema. Each rule carries its CWE (`external/cwe/cwe-78`, ...) and a `security-severity` score (8.0 for HIGH, 5.0 for MEDIUM), so GitHub ranks the alerts. Paths under the working directory are written relative to the repository root, and skipped or truncated files appear as tool notifications.

To show findings in a repository's **Security → Code scanning** tab, add a workflow step:

```yaml
permissions:
  security-events: write
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - name: Run CodeSentinel
    run: python codesentinel.py src/ --sarif > codesentinel.sarif || [ $? -eq 1 ]
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: codesentinel.sarif
      category: codesentinel
```

`|| [ $? -eq 1 ]` keeps the step green when there are findings (exit code 1), whose alerts appear in the Security tab, but still fails it for exit code 2 (a file could not be read or was only partly analyzed), as the bundled `action.yml` does.
