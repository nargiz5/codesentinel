# CodeSentinel v0.6

CodeSentinel is an educational Python static taint analyzer. It parses Python source with the built-in `ast` module and tracks untrusted data toward security-sensitive operations.

## Current capabilities (v0.6)

- **Sources:** `input()`, Flask-style `request.args`, `request.form`, `request.values`, `request.json`, common `.get()` accessors, `os.environ` (including `os.environ[...]`, `os.environ.get()` and `os.getenv()`), and `sys.argv`.
- **SQL injection rule (`CS-SQL-001`):** detects tainted query strings reaching `.execute()`, `.executemany()` and `.executescript()` on any receiver (for example `c.execute(...)` or `conn.cursor().execute(...)`) unless the call resolves to a user-defined function. It recognizes `int()` and `float()` numeric coercion as SQL-safe and retains parameterized-query handling.
- **Command injection rule (`CS-CMD-001`):** detects tainted values reaching `os.system()`, `os.popen()`, `subprocess.getoutput()` / `getstatusoutput()` (always shell), and `subprocess.run/call/check_call/check_output/Popen` when `shell=True`. The command may be passed positionally or as `args=`. It does not report ordinary argv-list calls using the default `shell=False`. It recognizes `shlex.quote()` and numeric coercion in command context.
- **Dynamic code rule (`CS-EVAL-001`):** detects tainted arguments passed to `eval()` and `exec()`.
- **HTML output rule (`CS-XSS-001`):** models the explicit `html_output()` and `response.write()` output APIs and recognizes `html.escape()` and numeric coercion as HTML-context sanitizers. HTML escaping does not suppress SQL or command-injection findings.
- **Interprocedural propagation:** tracks tainted arguments into user-defined functions and tainted return values back to callers; analyzes sinks inside called functions. After module-level analysis, it also inspects uncalled function bodies once in a clean abstract environment, so flows originating inside dormant functions are not silently skipped. Unknown parameters start untainted in this fallback pass.
- **Method calls:** the receiver of a method call is treated as an input, so taint survives string methods such as `value.strip()`, `input().lower()` and `template.format(...)`, and sinks nested in a receiver (`os.popen(x).read()`) are inspected. Context-specific sanitizer markers are preserved through such calls.
- **Class methods:** methods of module-level classes are registered as `Class.method`. Calls through `self.method(...)` / `cls.method(...)` inside the class and explicit `Class.method(...)` calls are resolved with the receiver bound to the first parameter (respecting `@staticmethod` and `@classmethod`). Methods that are never called are inspected by the uncalled-function pass.
- **Imports:** `import x as y` and `from m import name [as alias]` are resolved for known sources, sinks and sanitizers (`from os import system`, `import subprocess as sp`, `from shlex import quote`).
- **Scopes:** functions can read tainted module globals (unless the name is local to the function), `global` declarations write to the module environment, and nested functions are registered and analyzed with a snapshot of the enclosing scope for closure reads.
- **Stores:** attribute stores (`o.cmd = input()`) are tracked per dotted name, subscript stores (`d["k"] = input()`) taint the container, and walrus assignments (`:=`) bind taint.
- **Function summaries:** call results are memoized per function and argument taint, so analysis time stays linear for call trees that repeatedly call the same functions. Keyword, keyword-only, `*args` and `**kwargs` arguments are bound by name.
- **Control-flow analysis:** conservatively joins `if/else` states, handles missing `else` paths, performs bounded fixed-point iteration for loops, joins `try/except` and `try/except*` paths (handlers start from every intermediate state of the `try` body), analyzes every `match` case (binding capture patterns to the subject's taint), and propagates taint through list/set/dict comprehensions and generator expressions.
- **Reporting:** human-readable findings or JSON output with rule, source, sink, filename, and source location.

## Run

```bash
python codesentinel.py path/to/file.py
python codesentinel.py path/to/file.py --json
python -m unittest discover -s tests -v
```

## Tests

The test suite contains 84 hand-written regression tests using vulnerable and safe snippets. It covers direct and interprocedural flows, branch joins, loop propagation, context-specific sanitization, subprocess `shell` behavior, environment/CLI sources, dynamic-code sinks, method-call receivers, class methods, and analysis of uncalled functions. This is a focused regression suite, not an industry benchmark; its pass rate must not be presented as real-world detection accuracy.

## Limitations

This is a learning prototype, not a production SAST product. It uses a name-based abstract environment and bounded loop iteration. Attribute taint is tracked per variable name, not per object, so `self.x` written in one method is not seen by another method. Any non-user `.execute()` call is treated as a SQL sink, which may over-report for non-database APIs. It does not implement full alias analysis, path-sensitive symbolic execution, complete Python scope/global semantics, exception-flow precision, framework-specific source/sink models, or a full control-flow graph. Method calls on instances (`obj.run(...)` where `obj = Runner()`) are not resolved to their class, because the analyzer does not infer object types; inheritance and nested classes are not modeled. `subprocess` modeling handles literal `shell=True` / `shell=False` and does not infer dynamically computed values. The HTML output APIs are explicit demonstration sinks, not automatic discovery of every web framework response path. A clean result is not proof that code is secure.
