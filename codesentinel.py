"""CodeSentinel: an interprocedural taint analyzer for Python web applications.

The analyzer uses Python's AST, a conservative abstract environment, simple
function summaries evaluated at call sites (memoized per argument taint),
context-specific sanitizer rules, and bounded fixed-point iteration for loops.
It is a focused tool, not a replacement for mature SAST tools such as CodeQL.
"""
from __future__ import annotations

import argparse
import ast
import io
import json
import re
import sys
import tokenize
from dataclasses import asdict, dataclass, replace, field
from pathlib import Path
from typing import Iterable

if sys.version_info < (3, 10):
    raise SystemExit(f"CodeSentinel needs Python 3.10 or newer; this is Python "
                     f"{sys.version_info.major}.{sys.version_info.minor}.")

@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    source: str
    sink: str
    filename: str
    line: int
    column: int
    # "low" when every source is operator-controlled (environment, argv).
    confidence: str = "high"
    # How the data got there: ``{"kind": "source"|"call"|"sink", "file", "line", "name"}``
    # steps in order. The source step is the last place that source was read
    # before the sink; the call steps are the calls the analysis followed.
    trace: list = field(default_factory=list, compare=False)


RULE_SEVERITY = {
    "CS-SQL-001": "HIGH",
    "CS-CMD-001": "HIGH",
    "CS-EVAL-001": "HIGH",
    "CS-XSS-001": "MEDIUM",
    "CS-DESER-001": "HIGH",
    # File paths are often legitimately user-chosen (CLI tools), so this rule
    # is noisier than the injection rules.
    "CS-PATH-001": "MEDIUM",
    "CS-SSRF-001": "MEDIUM",
    "CS-SSTI-001": "HIGH",
    "CS-REDIRECT-001": "MEDIUM",
}

# Metadata used for SARIF output: (short name, description, CWE number).
RULE_INFO = {
    "CS-SQL-001": ("SqlInjection", "Untrusted data reaches a SQL query.", 89),
    "CS-CMD-001": ("CommandInjection", "Untrusted data reaches an OS command.", 78),
    "CS-EVAL-001": ("CodeInjection", "Untrusted data reaches eval/exec.", 95),
    "CS-XSS-001": ("CrossSiteScripting", "Unescaped data reaches HTML output.", 79),
    "CS-DESER-001": ("InsecureDeserialization",
                     "Untrusted data reaches a deserializer that can execute code.", 502),
    "CS-PATH-001": ("PathTraversal", "Untrusted data selects the file to open.", 22),
    "CS-SSRF-001": ("ServerSideRequestForgery",
                    "Untrusted data selects the URL of an outgoing request.", 918),
    "CS-SSTI-001": ("TemplateInjection",
                    "Untrusted data is compiled as a server-side template.", 1336),
    "CS-REDIRECT-001": ("OpenRedirect", "Untrusted data selects a redirect target.", 601),
}
# GitHub code scanning orders alerts by ``security-severity`` (0.0-10.0).
SARIF_SECURITY_SEVERITY = {"HIGH": "8.0", "MEDIUM": "5.0"}
SARIF_LEVEL = {"HIGH": "error", "MEDIUM": "warning"}
INFORMATION_URI = "https://github.com/nargiz5/codesentinel"

SQL_SINKS = {
    "cursor.execute", "connection.execute", "db.execute",
    "pandas.read_sql", "pandas.read_sql_query",
}
# Any ``<obj>.execute(...)``-style call that does not resolve to a user-defined
# function is treated as a DB-API query execution (``c.execute``,
# ``conn.cursor().execute``, ``sqlite3.connect(p).executescript`` ...).
SQL_METHODS = {"execute", "executemany", "executescript", "exec_driver_sql"}
SQL_ARG_KEYWORDS = {"sql", "query", "operation", "statement"}

COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec",
    "pty.spawn",
}
# ``os.exec*`` / ``os.posix_spawn*``: (path, argv-list) or (path, *argv).
EXEC_SINKS = {
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.execl", "os.execle", "os.execlp", "os.execlpe",
    "os.posix_spawn", "os.posix_spawnp",
}
# ``os.spawn*``: (mode, path, argv-list) or (mode, path, *argv).
SPAWN_SINKS = {
    "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe",
}
COMMAND_SINKS |= EXEC_SINKS | SPAWN_SINKS
# These always hand their argument to a shell, regardless of keywords.
ALWAYS_SHELL_SINKS = {
    "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "asyncio.create_subprocess_shell",
}
# ``subprocess.run(["sh", "-c", cmd])`` hands ``cmd`` to a shell even without
# ``shell=True``.
SHELL_PROGRAMS = {"sh", "bash", "zsh", "dash", "ksh", "cmd", "cmd.exe",
                  "powershell", "powershell.exe", "pwsh"}
SHELL_COMMAND_FLAGS = {"-c", "/c", "/C", "-Command", "-command"}
# Decorators whose functions receive request data as parameters.
ROUTE_DECORATOR_SUFFIXES = (".route", ".get", ".post", ".put", ".patch",
                            ".delete", ".api_route", ".websocket")
COMMAND_ARG_KEYWORDS = {"args", "cmd", "command"}

EVAL_SINKS = {"eval", "exec"}
# Deserializers that can execute code while loading untrusted data.
DESER_SINKS = {
    "pickle.loads", "pickle.load", "marshal.loads", "marshal.load",
    "dill.loads", "dill.load", "yaml.load", "yaml.unsafe_load",
}
SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
PATH_SINKS = {"open", "io.open"}
# Command-line arguments are not reported as path traversal: a CLI tool opening
# the file its user names is the normal case, and was most of this rule's noise.
PATH_IGNORED_SOURCES = {"sys.argv", "sys.argv[...]"}
HTML_SINKS = {"html_output", "response.write"}  # Explicit output APIs.

# Outgoing HTTP requests: (rule, sanitizer context, message, URL argument
# position, URL keyword names). ``requests.request(method, url)`` takes the
# URL second.
_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
_SSRF = ("CS-SSRF-001", "url",
         "Potential SSRF: untrusted data selects the URL of an outgoing request.")
_SSTI = ("CS-SSTI-001", "template",
         "Potential server-side template injection: untrusted data is compiled as a template.")
_REDIRECT = ("CS-REDIRECT-001", "redirect",
             "Potential open redirect: untrusted data selects the redirect target.")
EXTRA_SINKS: dict[str, tuple[str, str, str, int, set[str]]] = {}
for _lib in ("requests", "httpx"):
    for _m in _HTTP_METHODS:
        EXTRA_SINKS[f"{_lib}.{_m}"] = (*_SSRF, 0, {"url"})
    EXTRA_SINKS[f"{_lib}.request"] = (*_SSRF, 1, {"url"})
for _name in ("urllib.request.urlopen", "urllib.request.Request"):
    EXTRA_SINKS[_name] = (*_SSRF, 0, {"url"})
EXTRA_SINKS["urllib3.request"] = (*_SSRF, 1, {"url"})
for _name in ("flask.render_template_string", "jinja2.Template",
              "django.template.Template", "mako.template.Template"):
    EXTRA_SINKS[_name] = (*_SSTI, 0, {"source", "template_string", "text"})
for _name in ("flask.redirect", "django.shortcuts.redirect", "django.http.HttpResponseRedirect",
              "django.http.HttpResponsePermanentRedirect",
              "starlette.responses.RedirectResponse", "fastapi.responses.RedirectResponse"):
    EXTRA_SINKS[_name] = (*_REDIRECT, 0, {"location", "url", "to", "redirect_to"})

# Sources referenced without being called (attribute access).
SOURCES = {
    # Flask
    "request.args", "request.form", "request.values", "request.json",
    "request.cookies", "request.headers", "request.data", "request.files",
    # Django and Django REST framework (``request`` is the view's parameter)
    "request.GET", "request.POST", "request.COOKIES", "request.META", "request.FILES",
    "request.body", "request.query_params",
    # Starlette / FastAPI
    "request.path_params",
    # aiohttp (``request`` is the handler's parameter)
    "request.match_info", "request.query", "request.rel_url", "request.content",
    "os.environ", "sys.argv", "sys.stdin",
}
# Sources that produce untrusted data when called.
CALL_SOURCES = {"input"}
SOURCE_ACCESSORS = {
    "request.args.get", "request.form.get", "request.values.get",
    "request.json.get", "os.environ.get", "os.getenv",
    "request.get_json", "request.get_data",
    "request.GET.get", "request.POST.get", "request.COOKIES.get", "request.META.get",
    "request.query_params.get", "request.headers.get",
    # Starlette: ``await request.json()`` / ``body()`` / ``form()``
    "request.json", "request.body", "request.form",
    # aiohttp: ``await request.post()`` / ``text()`` / ``read()`` / ``multipart()``
    "request.post", "request.text", "request.read", "request.multipart",
    "request.match_info.get", "request.query.get",
}

# Class-based views: the HTTP-method handlers of these classes receive request
# data in their parameters (route parameters), like decorated route functions.
VIEW_BASE_CLASSES = {
    "flask.views.MethodView", "flask.views.View",
    "flask_restful.Resource", "flask_restx.Resource",
    "starlette.endpoints.HTTPEndpoint", "aiohttp.web.View",
    "django.views.View", "django.views.generic.View", "django.views.generic.base.View",
    "rest_framework.views.APIView", "tornado.web.RequestHandler",
}
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete", "head", "options"}
# Sources that exist only on ``self`` inside a request-handler class.
SELF_SOURCES = {
    "tornado.web.RequestHandler": {
        "calls": {"self.get_argument", "self.get_arguments", "self.get_query_argument",
                  "self.get_query_arguments", "self.get_body_argument",
                  "self.get_body_arguments", "self.get_cookie", "self.get_secure_cookie"},
        "attributes": {"self.request.body", "self.request.arguments",
                       "self.request.query_arguments", "self.request.body_arguments",
                       "self.request.query", "self.request.uri", "self.request.path",
                       "self.request.headers", "self.request.files"},
    },
    "http.server.BaseHTTPRequestHandler": {
        "calls": set(),
        "attributes": {"self.path", "self.headers", "self.rfile", "self.requestline"},
    },
}
SELF_SOURCE_BASES = {
    "tornado.web.RequestHandler": "tornado.web.RequestHandler",
    "http.server.BaseHTTPRequestHandler": "http.server.BaseHTTPRequestHandler",
    "http.server.SimpleHTTPRequestHandler": "http.server.BaseHTTPRequestHandler",
    "http.server.CGIHTTPRequestHandler": "http.server.BaseHTTPRequestHandler",
    "BaseHTTPServer.BaseHTTPRequestHandler": "http.server.BaseHTTPRequestHandler",
    "SimpleHTTPServer.SimpleHTTPRequestHandler": "http.server.BaseHTTPRequestHandler",
}
# Flask-RESTful / Flask-RESTX request parsers: ``parser.parse_args()``.
REQPARSE_MODULES = ("flask_restful.reqparse", "flask_restx.reqparse")
SUBSCRIPT_SOURCES = {"os.environ", "sys.argv"}
# Sanitizers are sink-context-specific. A command quoting function must not
# accidentally suppress a SQL finding, and vice versa. Numeric coercion is
# safe for SQL, command and HTML contexts because it restricts the value to a
# number.
SANITIZERS = {
    "command": {"shlex.quote", "int", "float"},
    "sql": {"int", "float"},
    "html": {"html.escape", "int", "float"},
    "path": {"os.path.basename", "werkzeug.utils.secure_filename", "int", "float"},
    "url": {"int", "float"},
    "template": {"int", "float"},
    # A URL built by the framework's router only points inside the application.
    "redirect": {"int", "float", "flask.url_for", "django.urls.reverse"},
}

# Guards are checks used in a condition: ``if is_safe_url(x): redirect(x)``.
# Inside the branch where the check passed, ``x`` is safe for these contexts.
# Library guards are listed here; a project's own functions are recognized by
# what they do (see ``infer_guard``), or declared in a configuration file.
GUARDS: dict[str, set[str]] = {
    "django.utils.http.url_has_allowed_host_and_scheme": {"redirect"},
    "django.utils.http.is_safe_url": {"redirect"},
}
# ``re.fullmatch(r"[A-Za-z0-9_-]+", x)``: a value made only of letters, digits,
# ``_`` and ``-`` cannot carry a path separator, a URL scheme, a quote or a
# shell metacharacter, so a match makes it safe in every context. A range must
# stay inside one kind of character: ``[0-z]`` or ``[A-z]`` also cover
# ``; < > \ [ ] ^`` and the backtick.
_SAFE_PATTERN = re.compile(
    r"^(?:\^|\\A)?\[-?(?:[a-z]-[a-z]|[A-Z]-[A-Z]|[0-9]-[0-9]|[A-Za-z0-9_]|\\-|\\w|\\d)+-?\]"
    r"(?:\+|\*|\{\d+(?:,\d*)?\})(?:\$|\\Z|\\z)?$")
REGEX_MATCHERS = {"re.fullmatch": False, "re.match": True}   # value: needs an end anchor
# ORM reads by key or filter return stored records: a user value can choose
# which record, but does not become its content (like ``table[key]``).
# ``db.session.get(Forum, forum_id)``, ``Forum.query.filter_by(id=x).first()``,
# ``Forum.objects.get(pk=x)``, ``get_object_or_404(Forum, pk=x)``.
ORM_RESULT_METHODS = {"get", "get_or_404", "first", "first_or_404", "one", "one_or_none",
                      "one_or_404", "all", "scalar", "count", "exists"}
ORM_LOOKUP_FUNCTIONS = {"django.shortcuts.get_object_or_404", "django.shortcuts.get_list_or_404"}
# Calls that end the current path, like ``return``: ``if not ok(x): abort(403)``.
EXIT_CALLS = {"abort", "flask.abort", "werkzeug.exceptions.abort", "sys.exit", "exit",
              "django.http.Http404", "django.core.exceptions.PermissionDenied"}
# What a guard must do with its argument, per context. A function counts as a
# guard only if it can return a false value and, for a context, does both
# halves of a real check: it parses or normalizes the value, and it decides
# on the part that matters. Checking only a URL's scheme does not stop an
# open redirect (``https://evil.example``), so a redirect guard must look at
# the host; normalizing a path without comparing it to a root proves nothing.
_URL_PARSE = {"urlparse", "urlsplit", "urljoin"}
_REDIRECT_DECIDE_ATTRS = {"netloc", "hostname"}
_HOST_RESOLVE = {"urlparse", "urlsplit", "ip_address", "ip_network", "getaddrinfo",
                 "gethostbyname"}
# Properties of a resolved address that are decisions by themselves.
_ADDRESS_DECIDE_ATTRS = {"is_private", "is_loopback", "is_reserved", "is_link_local",
                         "is_global"}
_PREFIX_TESTS = {"startswith", "endswith"}
_PATH_NORMALIZE = {"realpath", "abspath", "normpath", "resolve"}
_PATH_CONTAIN_CALLS = {"startswith", "commonpath", "commonprefix", "is_relative_to",
                       "relative_to"}
_PATH_CONTAIN_ATTRS = {"parents"}


def _uses(expr: ast.AST, attributes: set[str], names: set[str]) -> bool:
    """Whether ``expr`` reads one of ``attributes`` or one of ``names``."""
    return any((isinstance(n, ast.Attribute) and n.attr in attributes)
               or (isinstance(n, ast.Name) and n.id in names) for n in ast.walk(expr))


def _derived_names(fn: ast.AST, attributes: set[str]) -> set[str]:
    """Variables assigned, directly or indirectly, from one of ``attributes``
    (``host = urlparse(u).netloc``)."""
    derived: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and node.value \
                    is not None and _uses(node.value, attributes, derived):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for name in ast.walk(target):
                        if isinstance(name, ast.Name) and name.id not in derived:
                            derived.add(name.id)
                            changed = True
    return derived


def _is_empty(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and node.value in ("", b"", None, 0)


def _accepts_when_present(fn: ast.AST, attributes: set[str]) -> bool:
    """Whether ``fn`` can return true *because* one of ``attributes`` is set.

    ``return urlparse(u).netloc != ""`` and ``return bool(host)`` are true
    exactly for URLs that name another host, so they are the opposite of a
    redirect check even though they compare the host.
    """
    derived = _derived_names(fn, attributes)

    def present(expr: ast.AST) -> bool:
        if isinstance(expr, ast.BoolOp):
            # ``a or b`` is true whenever one operand is; ``a and b`` needs all.
            operands = expr.values
            return any(map(present, operands)) if isinstance(expr.op, ast.Or) \
                else all(map(present, operands))
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
            left, op, right = expr.left, expr.ops[0], expr.comparators[0]
            if isinstance(op, (ast.NotEq, ast.IsNot, ast.Gt)):
                if _is_empty(right) and _uses(left, attributes, derived):
                    return True
                if _is_empty(left) and _uses(right, attributes, derived):
                    return True
            return False
        if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Name) \
                and expr.func.id == "bool" and len(expr.args) == 1:
            return _uses(expr.args[0], attributes, derived)
        if isinstance(expr, (ast.Attribute, ast.Name)):
            return _uses(expr, attributes, derived)
        return False

    return any(isinstance(n, ast.Return) and n.value is not None and present(n.value)
               for n in ast.walk(fn))


def _compares(fn: ast.AST, attributes: set[str]) -> bool:
    """Whether ``fn`` compares one of ``attributes`` (``p.netloc == host``,
    ``host in allowed``, ``host.endswith(".example.com")``), directly or
    through a variable assigned from it (``host = urlparse(u).netloc``)."""
    nodes = list(ast.walk(fn))
    derived = _derived_names(fn, attributes)

    def uses(expr: ast.AST, names: set[str]) -> bool:
        return _uses(expr, attributes, names)

    def rejects(body: list[ast.stmt]) -> bool:
        last = body[-1] if body else None
        return isinstance(last, ast.Raise) or (
            isinstance(last, ast.Return) and (last.value is None or (
                isinstance(last.value, ast.Constant) and not last.value.value)))

    for node in nodes:
        if isinstance(node, ast.Compare) and uses(node, derived):
            return True
        # ``return not host`` and ``if parsed.netloc: return False`` decide on
        # the host; ``return parsed.netloc`` only reads it.
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not) \
                and uses(node.operand, derived):
            return True
        if isinstance(node, ast.If) and uses(node.test, derived) \
                and (rejects(node.body) or rejects(node.orelse)):
            return True
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in _PREFIX_TESTS and uses(node.func.value, derived)):
            return True
    return False


def register_config(config: dict) -> None:
    """Add a project's own sanitizers, guards and sources.

    ``config`` is the content of a ``.codesentinel.json`` file::

        {"sanitizers": {"myapp.urls.safe_next": ["redirect"]},
         "guards": {"myapp.security.is_allowed_path": ["path"]},
         "sources": ["myapp.http.current_request.payload"]}

    Contexts: command, sql, html, path, url, template, redirect.
    """
    known = set(SANITIZERS)
    for section in ("sanitizers", "guards"):
        for name, contexts in (config.get(section) or {}).items():
            bad = set(contexts) - known
            if bad:
                raise ValueError(f"{section}: {name}: unknown context(s) {sorted(bad)}")
            if section == "sanitizers":
                for context in contexts:
                    SANITIZERS[context].add(name)
            else:
                GUARDS.setdefault(name, set()).update(contexts)
            KNOWN_NAMES.add(name)
    for name in config.get("sources") or []:
        SOURCES.add(name)
        KNOWN_NAMES.add(name)


CONFIG_FILE = ".codesentinel.json"


def load_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


# Sources set by whoever runs the program (the operator), not by a remote
# user. Findings that only come from these are low confidence and hidden by
# default: in real projects they were mostly CLI and worker configuration.
OPERATOR_SOURCES = {
    "os.environ", "os.environ[...]", "os.environ.get", "os.getenv",
    "sys.argv", "sys.argv[...]",
}

# SQLAlchemy statement builders bind values as parameters, so data passed to
# them (``select(T).where(T.id.in_(ids))``) is not part of the SQL text.
# Raw-SQL constructors are the exception and stay dangerous.
_SQLA_PREFIXES = ("sqlalchemy.", "sqlalchemy.sql.", "sqlalchemy.sql.expression.")
SQLA_BUILDERS = {p + n for p in _SQLA_PREFIXES for n in ("select", "insert", "update", "delete")}
SQLA_BUILDERS |= {"db.select", "db.insert", "db.update", "db.delete"}  # Flask-SQLAlchemy
SQLA_RAW_SQL = {p + n for p in _SQLA_PREFIXES for n in ("text", "literal_column")}
ORM_CONTEXTS = {"SQL", "ORM"}
RAW_SQL_CONTEXT = "RAWSQL"   # a marker context no sink accepts

# Methods that store their arguments inside the receiver container.
CONTAINER_MUTATORS = {
    "append", "extend", "insert", "add", "update", "setdefault",
    "appendleft", "extendleft",
}

SAFE_MARKER = "__SAFE_"
KNOWN_NAMES = (
    SQL_SINKS | COMMAND_SINKS | EVAL_SINKS | DESER_SINKS | PATH_SINKS | HTML_SINKS | SOURCES | CALL_SOURCES
    | SOURCE_ACCESSORS | SUBSCRIPT_SOURCES
    | set().union(*SANITIZERS.values())
    | SQLA_BUILDERS | SQLA_RAW_SQL | set(EXTRA_SINKS) | set(GUARDS) | EXIT_CALLS | set(REGEX_MATCHERS) | ORM_LOOKUP_FUNCTIONS
    | VIEW_BASE_CLASSES | set(SELF_SOURCE_BASES) | {m + ".RequestParser" for m in REQPARSE_MODULES}
)

Env = dict[str, set[str]]


_SUPPRESSION = re.compile(r"codesentinel:\s*ignore(?:\[([A-Za-z0-9_,\s-]+)\])?")


def suppressions(source: str) -> dict[int, set[str] | None]:
    """Lines with a ``# codesentinel: ignore`` comment.

    ``# codesentinel: ignore`` silences every rule on that line;
    ``# codesentinel: ignore[CS-SQL-001, CS-CMD-001]`` only the listed rules.
    Only real comments count (a string containing the marker does not).
    """
    result: dict[int, set[str] | None] = {}
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return result
    for token in tokens:
        if token.type != tokenize.COMMENT:
            continue
        match = _SUPPRESSION.search(token.string)
        if not match:
            continue
        line = token.start[0]
        rules = ({r.strip().upper() for r in match.group(1).split(",") if r.strip()}
                 if match.group(1) else None)
        previous = result.get(line, set())
        result[line] = None if rules is None or previous is None else previous | rules
    return result


class AnalysisBudgetExceeded(Exception):
    """Raised when analysis exceeds its statement budget."""


def dotted_name(node: ast.AST) -> str | None:
    """Dotted name of a Name/Attribute chain; calls are looked through."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


def store_key(node: ast.AST) -> str | None:
    """Dotted key for a pure Name/Attribute chain (no calls), e.g. ``o.cmd``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = store_key(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    return None


def _is_known(full: str) -> bool:
    return full in KNOWN_NAMES or any(k.startswith(full + ".") for k in KNOWN_NAMES)


def _is_sanitizer_module(module: str) -> bool:
    """Whether ``module`` contains a sanitizer (``shlex``, ``os.path``, ...)."""
    return any(name.startswith(module + ".")
               for group in SANITIZERS.values() for name in group)


def import_bindings(statements: list[ast.stmt]) -> set[str]:
    """Names bound by import statements directly in one scope."""
    names: set[str] = set()
    stack: list[ast.AST] = list(statements)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name != "*":
                    names.add((alias.asname or alias.name).split(".")[0])
        stack.extend(_scope_children(node))
    return names


def scope_rebinds(statements: list[ast.stmt]) -> set[str]:
    """Names bound directly in one scope (nested function/class bodies excluded).

    Used to stop treating a builtin such as ``int`` as a sanitizer when that
    scope defines its own ``int``. Importing the real sanitizer does not count.
    """
    names: set[str] = set()
    stack: list[ast.AST] = list(statements)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                # ``import shlex as sh`` binds the real sanitizer module, so
                # ``sh.quote`` must stay trusted.
                if (alias.asname and alias.asname != alias.name
                        and not _is_sanitizer_module(alias.name)):
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                bound = alias.asname or alias.name
                full = f"{node.module}.{alias.name}"
                if bound != "*" and not any(full in group for group in SANITIZERS.values()):
                    names.add(bound)
        stack.extend(_scope_children(node))
    return names


def _scope_children(node: ast.AST) -> Iterable[ast.AST]:
    """Child nodes that belong to the same scope (nested scopes are skipped)."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # The def name itself is collected by the caller.
        if isinstance(child, (ast.Lambda, ast.ListComp, ast.SetComp,
                              ast.DictComp, ast.GeneratorExp)):
            # Walrus targets inside comprehensions bind in the enclosing scope.
            for sub in ast.walk(child):
                if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                    yield sub.target
            continue
        yield child


def function_scope(fn: ast.FunctionDef | ast.AsyncFunctionDef
                   ) -> tuple[set[str], set[str], set[str]]:
    """Return ``(local_names, global_names, nonlocal_names)`` for a function body."""
    params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    local_names = {p.arg for p in params}
    for extra in (fn.args.vararg, fn.args.kwarg):
        if extra:
            local_names.add(extra.arg)
    declared_global: set[str] = set()
    declared_nonlocal: set[str] = set()
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local_names.add(node.name)
            continue
        if isinstance(node, ast.Global):
            declared_global.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            declared_nonlocal.update(node.names)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            local_names.add(node.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                local_names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ExceptHandler) and node.name:
            local_names.add(node.name)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            local_names.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            local_names.add(node.rest)
        stack.extend(_scope_children(node))
    return (local_names - declared_global - declared_nonlocal,
            declared_global, declared_nonlocal)


@dataclass
class Frame:
    """Scope information for a function currently being analyzed."""
    name: str
    local_names: set[str]
    global_names: set[str]
    closure: Env | None = None
    nested: dict[str, str] = field(default_factory=dict)
    nonlocal_names: set[str] = field(default_factory=set)


def _freeze(env: Env | None) -> tuple:
    if not env:
        return ()
    return tuple(sorted((k, frozenset(v)) for k, v in env.items()))


class TaintAnalyzer:
    """Conservative name-based taint analysis with simple interprocedural calls."""

    def __init__(self, filename: str = "<memory>", max_loop_iterations: int = 32,
                 max_steps: int = 1_000_000, project: "Project | None" = None,
                 module: str = "", is_package: bool = False) -> None:
        self.filename = filename
        # Cross-module analysis: the project that owns this file, the file's
        # dotted module name, and names bound to project modules by imports
        # (local name -> ("module", "pkg.mod") or ("attr", "pkg.mod", "func")).
        self.project = project
        self.module = module
        self.is_package = is_package
        self.project_names: dict[str, tuple[str, ...]] = {}
        self.env: Env = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        # Qualified function name -> enclosing class name (None for module-level).
        self._function_class: dict[str, str | None] = {}
        self._class_stack: list[str | None] = []
        self.findings: list[Finding] = []
        self._seen: dict[tuple[str, int, int, str], int] = {}
        self._active_calls: set[str] = set()
        self._called_functions: set[str] = set()
        self._return_stack: list[set[str]] = []
        # Loops stop as soon as a fixed point is reached; this is only a cap.
        self.max_loop_iterations = max_loop_iterations
        # Upper bound on executed statements, so hostile inputs cannot hang
        # the analyzer (e.g. in CI). ``incomplete`` explains a stopped run.
        self.max_steps = max_steps
        self._steps = 0
        self.incomplete: str | None = None
        # Import aliases: local name -> canonical dotted name.
        self.aliases: dict[str, str] = {}
        # Environments of suspended callers; index 0 is the module environment.
        self._env_stack: list[Env] = []
        self._frames: list[Frame] = []
        # Nested function -> enclosing-scope taint recorded at its definition
        # and when the enclosing function finished (used when the enclosing
        # function is no longer running).
        self._closures: dict[str, Env] = {}
        # Nested function -> qualified name of the function that defines it.
        self._closure_owner: dict[str, str] = {}
        self._scopes: dict[str, tuple[set[str], set[str], set[str]]] = {}
        self._summary_cache: dict[tuple, tuple[set[str], Env | None]] = {}
        # Names rebound at module level, and per function (lazily).
        self._rebound: set[str] = set()
        self._function_rebinds: dict[str, set[str]] = {}
        # Per function: names bound by its own import statements.
        self._import_bindings: dict[str, set[str]] = {}
        # ``# codesentinel: ignore`` comments, and findings they silenced.
        self._suppressions: dict[int, set[str] | None] = {}
        self.suppressed: list[Finding] = []
        self._suppressed_keys: set[tuple[str, int, int, str]] = set()
        # Expressions a guard has checked on the current path, such as
        # ``request.args.get("next")`` after ``if is_safe_url(request.args.get("next"))``:
        # ``ast.dump`` of the expression -> contexts in which it is safe.
        self._refined: dict[str, set[str]] = {}
        # Guard contexts inferred per function definition (see ``infer_guard``).
        self._guard_cache: dict[int, set[str]] = {}
        # States of branches that left with ``raise``/``return``/``abort``
        # inside a ``try``: an ``except`` or ``finally`` can still see them.
        self._exit_states: list[Env] = []
        self._try_depth = 0           # ``try`` bodies being run in the current function
        # Module-level class -> its base-class expressions (for class-based views).
        self._class_bases: dict[str, list[ast.expr]] = {}
        self._class_kind_cache: dict[str, set[str]] = {}
        # Whether the module imports a Flask-RESTful/RESTX request parser.
        self._uses_reqparse = False
        # Calls being followed, and where each source was last read; shared by
        # every file of a project, so a trace can cross modules.
        self._trace: list[dict] = project.trace if project is not None else []
        self._source_sites: dict[str, dict] = project.source_sites if project is not None else {}

    # ------------------------------------------------------------------ setup
    def analyze(self, source: str) -> list[Finding]:
        tree = ast.parse(source, filename=self.filename)
        self._suppressions = suppressions(source)
        self._rebound = scope_rebinds(tree.body)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                names = {f"{node.module}.{a.name}" for a in node.names} | {node.module}
            elif isinstance(node, ast.Import):
                names = {a.name for a in node.names}
            else:
                continue
            if any(n.startswith(REQPARSE_MODULES) for n in names):
                self._uses_reqparse = True
        # Register functions before analyzing top-level statements so calls
        # can resolve functions declared later in the module.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._register_function(node.name, node, None)
            elif isinstance(node, ast.ClassDef):
                self._class_bases[node.name] = list(node.bases)
                # Methods are registered as ``Class.method``. They are reached
                # through ``self.method(...)`` / ``Class.method(...)`` calls or,
                # failing that, by the uncalled-function pass.
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._register_function(f"{node.name}.{item.name}", item, node.name)
        try:
            self._exec_block(tree.body)
            self._analyze_uncalled_functions()
        except AnalysisBudgetExceeded:
            self.incomplete = f"statement budget of {self.max_steps} exceeded"
        except RecursionError:
            self.incomplete = "code is nested too deeply to analyze"
        return list(self.findings)

    def _register_function(self, name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                           cls: str | None) -> None:
        self.functions[name] = fn
        self._function_class[name] = cls

    def _add_finding(self, node: ast.AST, rule_id: str, message: str,
                     sources: set[str], sink: str) -> None:
        """Record a finding once per rule and location.

        When several sources reach the same sink, they are merged into one
        finding (``source="os.environ.get, sys.argv[...]"``) instead of being
        reported twice.
        """
        line = getattr(node, "lineno", 1)
        column = getattr(node, "col_offset", 0) + 1
        key = (rule_id, line, column, sink)
        if self._is_suppressed(node, rule_id):
            if key not in self._suppressed_keys:
                self._suppressed_keys.add(key)
                self.suppressed.append(Finding(
                    rule_id, RULE_SEVERITY.get(rule_id, "HIGH"), message,
                    ", ".join(sorted(sources)), sink, self.filename, line, column,
                    self._confidence(sources)))
            return
        index = self._seen.get(key)
        if index is not None:
            existing = self.findings[index]
            merged = set(existing.source.split(", ")) | sources
            self.findings[index] = replace(existing, source=", ".join(sorted(merged)),
                                           confidence=self._confidence(merged))
            return
        self._seen[key] = len(self.findings)
        trace = [dict(self._source_sites[s]) for s in sorted(sources) if s in self._source_sites]
        trace += [dict(step) for step in self._trace]
        trace.append({"kind": "sink", "file": self.filename, "line": line, "name": sink})
        self.findings.append(Finding(
            rule_id, RULE_SEVERITY.get(rule_id, "HIGH"), message,
            ", ".join(sorted(sources)), sink, self.filename, line, column,
            self._confidence(sources), trace,
        ))

    def _is_suppressed(self, node: ast.AST, rule_id: str) -> bool:
        """A suppression comment on any line of the sink expression applies."""
        first = getattr(node, "lineno", 1)
        last = getattr(node, "end_lineno", None) or first
        for line in range(first, last + 1):
            if line in self._suppressions:
                rules = self._suppressions[line]
                if rules is None or rule_id in rules:
                    return True
        return False

    @staticmethod
    def _confidence(sources: set[str]) -> str:
        return "low" if sources and sources <= OPERATOR_SOURCES else "high"

    # ------------------------------------------------------- names and scopes
    def _canon(self, name: str | None) -> str | None:
        """Resolve import aliases: ``sp.run`` -> ``subprocess.run``."""
        if not name:
            return name
        head, sep, rest = name.partition(".")
        # A local name hides a module-level alias, unless the local binding
        # is itself an import (``def f(): import subprocess as sp``).
        if head in self.aliases and (not self._is_local(head)
                                     or self._is_local_import(head)):
            name = self.aliases[head] + sep + rest
        if name == "flask.request" or name.startswith("flask.request."):
            name = name[len("flask."):]
        for builtin_prefix in ("builtins.", "__builtins__."):
            if name.startswith(builtin_prefix) and "." not in name[len(builtin_prefix):]:
                name = name[len(builtin_prefix):]
        return name

    def _is_rebound(self, name: str) -> bool:
        """Whether ``name`` is rebound in the scope a call would resolve it in.

        Only the current function and the module are consulted, so a parameter
        named ``html`` in one function does not disable ``html.escape``
        elsewhere.
        """
        if self._frames:
            frame = self._frames[-1]
            if name not in frame.global_names:
                if frame.name not in self._function_rebinds:
                    fn = self.functions[frame.name]
                    params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
                    params += [a for a in (fn.args.vararg, fn.args.kwarg) if a]
                    self._function_rebinds[frame.name] = (
                        {a.arg for a in params} | scope_rebinds(fn.body))
                if name in self._function_rebinds[frame.name]:
                    return True
        return name in self._rebound

    def _is_local(self, name: str) -> bool:
        return bool(self._frames) and name in self._frames[-1].local_names

    def _is_local_import(self, name: str) -> bool:
        """Whether the current function binds ``name`` with an import."""
        if not self._frames:
            return False
        function = self._frames[-1].name
        if function not in self._import_bindings:
            self._import_bindings[function] = import_bindings(self.functions[function].body)
        return name in self._import_bindings[function]

    @property
    def _module_env(self) -> Env:
        return self._env_stack[0] if self._env_stack else self.env

    def _frame_env(self, index: int) -> Env:
        """Current environment of the active frame at ``index``."""
        if index == len(self._frames) - 1:
            return self.env
        # ``_env_stack[i + 1]`` was saved when frame ``i + 1`` was entered.
        return self._env_stack[index + 1]

    def _active_frame_index(self, name: str) -> int | None:
        for index in range(len(self._frames) - 1, -1, -1):
            if self._frames[index].name == name:
                return index
        return None

    def _nonlocal_env(self, head: str) -> Env | None:
        """Environment of the running enclosing function that owns ``head``.

        Returns None when that function is not running any more (for
        example a closure called after its factory returned).
        """
        owner = self._closure_owner.get(self._frames[-1].name)
        while owner is not None:
            index = self._active_frame_index(owner)
            if index is None:
                return None
            frame = self._frames[index]
            if head in frame.local_names:
                return self._frame_env(index)
            owner = self._closure_owner.get(owner)
        return None

    def _closure_for(self, name: str) -> Env | None:
        """Enclosing-scope taint for a call of nested function ``name``.

        Python closures read variables when they run, not when they are
        defined. If the defining function is still running, its current
        state is used; otherwise the recorded snapshot.
        """
        owner = self._closure_owner.get(name)
        if owner is None:
            return self._closures.get(name)
        index = self._active_frame_index(owner)
        if index is None:
            return self._closures.get(name)
        frame = self._frames[index]
        closure = {k: set(v) for k, v in (frame.closure or {}).items()
                   if k.split(".", 1)[0] not in frame.local_names}
        closure.update(self._copy_env(self._frame_env(index)))
        return closure

    def _lookup(self, key: str) -> set[str]:
        head = key.split(".", 1)[0]
        if not self._frames:
            return set(self.env.get(key, set()))
        frame = self._frames[-1]
        if head in frame.global_names:
            return set(self._module_env.get(key, set()))
        if head in frame.nonlocal_names:
            env = self._nonlocal_env(head)
            if env is None:
                env = frame.closure or {}
            return set(env.get(key, set()))
        if key in self.env or head in frame.local_names:
            return set(self.env.get(key, set()))
        if frame.closure is not None and key in frame.closure:
            return set(frame.closure[key])
        return set(self._module_env.get(key, set()))

    def _write(self, key: str, taint: set[str], weak: bool = False) -> None:
        head = key.split(".", 1)[0]
        env = self.env
        if self._frames and head in self._frames[-1].nonlocal_names:
            # ``nonlocal x``: write into the enclosing function's variable.
            # Weak update: the write may sit on a branch the enclosing
            # function does not always take.
            frame = self._frames[-1]
            if frame.closure is None:
                frame.closure = {}
            env = self._nonlocal_env(head)
            for target in ([env] if env is not None else []) + [frame.closure]:
                merged = taint | target.get(key, set())
                if merged:
                    target[key] = set(merged)
            return
        if self._frames and head in self._frames[-1].global_names:
            env = self._module_env
        if weak:
            taint = taint | env.get(key, set())
        if "." not in key:
            # Rebinding a name invalidates facts about its attributes.
            for stale in [k for k in env if k.startswith(key + ".")]:
                del env[stale]
        if taint:
            env[key] = set(taint)
        else:
            env.pop(key, None)

    # ---------------------------------------------------------------- sources
    def _class_kinds(self, cls: str | None, depth: int = 0) -> set[str]:
        """What a module-level class is: ``"view"`` for a class-based view, and
        the request-handler base whose ``self`` attributes are sources."""
        if cls is None or depth > 5 or cls not in self._class_bases:
            return set()
        if cls in self._class_kind_cache:
            return self._class_kind_cache[cls]
        self._class_kind_cache[cls] = set()          # cycles
        kinds: set[str] = set()
        for base in self._class_bases[cls]:
            name = self._canon(dotted_name(base))
            if not name:
                continue
            if name in VIEW_BASE_CLASSES:
                kinds.add("view")
            if name in SELF_SOURCE_BASES:
                kinds.add(SELF_SOURCE_BASES[name])
            if name in self._class_bases:
                kinds |= self._class_kinds(name, depth + 1)
        self._class_kind_cache[cls] = kinds
        return kinds

    def _self_source(self, name: str | None, call: bool) -> bool:
        if not name or not name.startswith("self.") or not self._class_stack:
            return False
        for kind in self._class_kinds(self._class_stack[-1]):
            if kind in SELF_SOURCES and name in SELF_SOURCES[kind]["calls" if call else "attributes"]:
                return True
        return False

    def _source_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call):
            func = self._canon(store_key(node.func))
            if func in CALL_SOURCES or func in SOURCE_ACCESSORS or self._self_source(func, True):
                return func
            if (self._uses_reqparse and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "parse_args"):
                return "reqparse.parse_args"
            return None
        if isinstance(node, ast.Subscript):
            base = self._canon(store_key(node.value))
            if base in SUBSCRIPT_SOURCES:
                return f"{base}[...]"
            return None
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = self._canon(store_key(node))
            if name in SOURCES or self._self_source(name, False):
                return name
        return None

    # ------------------------------------------------------- taint utilities
    @staticmethod
    def _raw_labels(taint: set[str]) -> set[str]:
        """Underlying source labels, unwrapping sanitizer markers."""
        labels: set[str] = set()
        for item in taint:
            if item.startswith(SAFE_MARKER):
                labels.update(l for l in item.split("|", 1)[1].split(",") if l)
            else:
                labels.add(item)
        return labels

    @staticmethod
    def _marker_contexts(item: str) -> set[str]:
        """Contexts in which a sanitizer marker is safe (empty for raw taint)."""
        if not item.startswith(SAFE_MARKER):
            return set()
        contexts = item[len(SAFE_MARKER):].split("__|", 1)[0]
        return {c for c in contexts.split("+") if c}

    @staticmethod
    def _make_marker(contexts: set[str], labels: set[str]) -> str:
        return (f"{SAFE_MARKER}{'+'.join(sorted(contexts))}__|"
                f"{','.join(sorted(labels))}")

    @classmethod
    def _labels_for_context(cls, taint: set[str], context: str) -> set[str]:
        # Each marker describes one sanitized value and lists every context in
        # which that value is safe. A marker for another context never cancels
        # a different value's taint, so ``html.escape(a) + shlex.quote(b)`` is
        # still unsafe in a shell even when ``a`` and ``b`` share a source.
        wanted = context.upper()
        unsafe: set[str] = set()
        for item in taint:
            if item.startswith(SAFE_MARKER):
                if wanted not in cls._marker_contexts(item):
                    unsafe.update(l for l in item.split("|", 1)[1].split(",") if l)
            else:
                unsafe.add(item)
        return unsafe

    @staticmethod
    def _sink_argument(node: ast.Call, arg_taints: list[set[str]],
                       kw_taints: list[set[str]], keywords: set[str]) -> set[str] | None:
        """Taint of the sink's primary argument (first positional or keyword)."""
        if node.args:
            if isinstance(node.args[0], ast.Starred):
                return set().union(*arg_taints)
            return arg_taints[0]
        for kw, taint in zip(node.keywords, kw_taints):
            if kw.arg in keywords or kw.arg is None:
                return taint
        return None

    # ------------------------------------------------------------ expressions
    def _eval(self, node: ast.AST | None) -> set[str]:
        """Evaluate an expression abstractly and return its taint labels."""
        if node is None:
            return set()
        source = self._source_name(node)
        if source:
            # Evaluate call arguments too (they may themselves contain sinks).
            if isinstance(node, ast.Call):
                for arg in node.args:
                    self._eval(arg)
                for kw in node.keywords:
                    self._eval(kw.value)
            elif isinstance(node, ast.Subscript):
                self._eval(node.slice)
            self._source_sites[source] = {"kind": "source", "file": self.filename,
                                          "line": getattr(node, "lineno", 0), "name": source}
            if self._refined:
                contexts = self._refined.get(ast.dump(node))
                if contexts:
                    return self._refine_taint({source}, contexts)
            return {source}

        if isinstance(node, ast.Name):
            return self._lookup(node.id)

        if isinstance(node, ast.NamedExpr):
            taint = self._eval(node.value)
            self._assign_target(node.target, taint)
            return taint

        if isinstance(node, ast.Call):
            taint = self._eval_call(node)
            if self._refined and taint:
                contexts = self._refined.get(ast.dump(node))
                if contexts:
                    return self._refine_taint(taint, contexts)
            return taint

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comprehension(node)

        if isinstance(node, ast.Attribute):
            key = store_key(node)
            stored = self._lookup(key) if key else set()
            return stored | self._eval(node.value)

        if isinstance(node, ast.Subscript):
            # ``table[key]`` returns something stored in ``table``: a tainted
            # key chooses *which* value, but does not make the value tainted
            # (``session[trans_id]``, ``ALLOWED[name]``). A slice of a tainted
            # value is still tainted through ``node.value``. The key is still
            # evaluated for sinks nested inside it.
            self._eval(node.slice)
            return self._eval(node.value)

        if isinstance(node, ast.IfExp):
            self._eval(node.test)
            return self._eval(node.body) | self._eval(node.orelse)

        if isinstance(node, ast.Dict):
            result: set[str] = set()
            for key_node in node.keys:
                result |= self._eval(key_node)
            for value in node.values:
                result |= self._eval(value)
            return result

        # BinOp, JoinedStr, FormattedValue, Tuple, List, Set, Starred, ...
        result = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                result |= self._eval(child)
        return result

    def _eval_comprehension(self, node: ast.ListComp | ast.SetComp | ast.GeneratorExp
                            | ast.DictComp) -> set[str]:
        saved = self.env
        self.env = self._copy_env(saved)
        try:
            for generator in node.generators:
                self._assign_target(generator.target, self._eval(generator.iter))
                for condition in generator.ifs:
                    self._eval(condition)
            if isinstance(node, ast.DictComp):
                return self._eval(node.key) | self._eval(node.value)
            return self._eval(node.elt)
        finally:
            self.env = saved

    @staticmethod
    def _static_callee(func: ast.AST) -> ast.AST:
        """Rewrite ``getattr(os, "system")`` / ``__import__("os").system``.

        Returns an equivalent Name/Attribute node when the target is spelled
        with constant strings, otherwise ``func`` unchanged.
        """
        def const_str(n: ast.AST) -> str | None:
            return n.value if isinstance(n, ast.Constant) and isinstance(n.value, str) else None

        def module_ref(n: ast.AST) -> ast.AST:
            if (isinstance(n, ast.Call) and n.args and not n.keywords
                    and dotted_name(n.func) in {"__import__", "importlib.import_module"}
                    and const_str(n.args[0])):
                return ast.copy_location(ast.Name(id=const_str(n.args[0]), ctx=ast.Load()), n)
            return n

        if (isinstance(func, ast.Call) and isinstance(func.func, ast.Name)
                and func.func.id == "getattr" and len(func.args) == 2
                and const_str(func.args[1])):
            base = module_ref(func.args[0])
            return ast.copy_location(
                ast.Attribute(value=base, attr=const_str(func.args[1]), ctx=ast.Load()), func)
        if isinstance(func, ast.Attribute):
            base = module_ref(func.value)
            if base is not func.value:
                return ast.copy_location(
                    ast.Attribute(value=base, attr=func.attr, ctx=ast.Load()), func)
        return func

    def _eval_call(self, node: ast.Call) -> set[str]:
        callee = self._static_callee(node.func)
        if callee is not node.func:
            node = ast.copy_location(
                ast.Call(func=callee, args=node.args, keywords=node.keywords), node)
        if isinstance(node.func, ast.Call):
            # ``factory()(x)``: evaluate the inner call, then treat the result
            # as an unknown callable.
            callee_taint = self._eval(node.func)
            arg_taints = [self._eval(arg) for arg in node.args]
            kw_taints = [self._eval(kw.value) for kw in node.keywords]
            return callee_taint.union(*arg_taints, *kw_taints)

        func_name = self._canon(dotted_name(node.func)) or "<dynamic-call>"
        # For method calls such as ``value.strip()`` or ``input().lower()``
        # the receiver object is an input to the call as well. Evaluating
        # it also inspects sinks nested inside it, e.g. ``os.popen(x).read()``.
        receiver_taint = (self._eval(node.func.value)
                          if isinstance(node.func, ast.Attribute) else set())
        arg_taints = [self._eval(arg) for arg in node.args]
        kw_taints = [self._eval(kw.value) for kw in node.keywords]
        all_arg_taints: set[str] = set().union(*arg_taints, *kw_taints)

        if func_name in ORM_LOOKUP_FUNCTIONS or self._is_orm_read(node):
            return set()

        if func_name in COMMAND_SINKS:
            command_arg = self._sink_argument(node, arg_taints, kw_taints, COMMAND_ARG_KEYWORDS)
            # os.system/os.popen/getoutput always invoke a shell. Other
            # subprocess APIs only do so when shell=True; argv-list calls with
            # the default shell=False are not shell-injection sinks.
            # A non-literal ``shell=`` value is conservatively treated as true.
            shell_enabled = func_name in ALWAYS_SHELL_SINKS or any(
                kw.arg == "shell" and not (isinstance(kw.value, ast.Constant)
                                           and not kw.value.value)
                for kw in node.keywords
            )
            if not shell_enabled:
                # argv-style execution: dangerous when the program itself is
                # untrusted or when argv explicitly starts a shell with ``-c``.
                command_arg = self._argv_command_taint(func_name, node)
                shell_enabled = bool(command_arg)
            if shell_enabled and command_arg is not None:
                command_taint = self._labels_for_context(command_arg, "command")
                if command_taint:
                    self._add_finding(
                        node, "CS-CMD-001",
                        "Potential command injection: untrusted data reaches a command execution sink.",
                        command_taint, func_name,
                    )
            return set()

        if func_name in EVAL_SINKS:
            code_arg = self._sink_argument(node, arg_taints, kw_taints, {"source"})
            if code_arg is not None:
                dynamic_code_taint = self._raw_labels(code_arg)
                if dynamic_code_taint:
                    self._add_finding(
                        node, "CS-EVAL-001",
                        "Potential code injection: untrusted data reaches eval/exec.",
                        dynamic_code_taint, func_name,
                    )
                # The value computed by eval() is derived from its input.
                return self._raw_labels(code_arg) if func_name == "eval" else set()
            return set()

        if func_name in DESER_SINKS:
            data_arg = self._sink_argument(node, arg_taints, kw_taints,
                                           {"data", "stream", "file"})
            loader = next((kw.value for kw in node.keywords if kw.arg == "Loader"),
                          node.args[1] if len(node.args) > 1 else None)
            safe_yaml = (func_name == "yaml.load" and loader is not None
                         and (dotted_name(loader) or "").rsplit(".", 1)[-1]
                         in SAFE_YAML_LOADERS)
            if data_arg is not None and not safe_yaml:
                deser_taint = self._raw_labels(data_arg)
                if deser_taint:
                    self._add_finding(
                        node, "CS-DESER-001",
                        "Potential insecure deserialization: untrusted data reaches "
                        "a deserializer that can execute code.",
                        deser_taint, func_name,
                    )
            return self._raw_labels(all_arg_taints)

        if func_name in PATH_SINKS:
            path_arg = self._sink_argument(node, arg_taints, kw_taints, {"file"})
            if path_arg is not None:
                path_taint = self._labels_for_context(path_arg, "path") - PATH_IGNORED_SOURCES
                if path_taint:
                    self._add_finding(
                        node, "CS-PATH-001",
                        "Potential path traversal: untrusted data selects the file to open.",
                        path_taint, func_name,
                    )
            return all_arg_taints

        if func_name in HTML_SINKS:
            html_arg = self._sink_argument(node, arg_taints, kw_taints, set())
            if html_arg is not None:
                html_taint = self._labels_for_context(html_arg, "html")
                if html_taint:
                    self._add_finding(
                        node, "CS-XSS-001",
                        "Potential cross-site scripting: unescaped data reaches an HTML output sink.",
                        html_taint, func_name,
                    )
            return set()

        if func_name in EXTRA_SINKS:
            rule_id, context, message, position, keywords = EXTRA_SINKS[func_name]
            if any(isinstance(a, ast.Starred) for a in node.args[:position + 1]):
                target_taint: set[str] | None = set().union(*arg_taints)
            elif len(node.args) > position:
                target_taint = arg_taints[position]
            else:
                target_taint = next((t for kw, t in zip(node.keywords, kw_taints)
                                     if kw.arg in keywords or kw.arg is None), None)
            if target_taint:
                labels = self._labels_for_context(target_taint, context)
                if labels:
                    self._add_finding(node, rule_id, message, labels, func_name)
            # The response or template object still carries its inputs' taint.
            return all_arg_taints | receiver_taint

        # A sanitizer only counts if the code has not rebound its name
        # (``def int(x): return x`` or ``int = str`` is not a coercion).
        raw_head = (dotted_name(node.func) or "").split(".", 1)[0]
        sanitizer_contexts = [] if self._is_rebound(raw_head) else [
            context for context, names in SANITIZERS.items() if func_name in names]
        if sanitizer_contexts:
            # Preserve the original source labels in a single marker listing
            # the contexts in which the returned value is safe. Contexts that
            # every input was already safe for (nested sanitizers) are kept.
            labels = self._raw_labels(all_arg_taints)
            if not labels:
                return set()
            inherited: set[str] | None = None
            for item in all_arg_taints:
                contexts = self._marker_contexts(item)
                inherited = contexts if inherited is None else inherited & contexts
            contexts = {c.upper() for c in sanitizer_contexts} | (inherited or set())
            return {self._make_marker(contexts, labels)}

        if func_name in SQLA_RAW_SQL:
            # ``text("... " + x)`` is SQL text: its taint must survive being
            # passed into a statement builder below.
            labels = self._raw_labels(all_arg_taints)
            return {self._make_marker({RAW_SQL_CONTEXT}, labels)} if labels else set()
        orm_chain = isinstance(node.func, ast.Attribute) and any(
            "ORM" in self._marker_contexts(item) for item in receiver_taint)
        table_statement = (isinstance(node.func, ast.Attribute)
                           and node.func.attr in {"select", "insert", "update", "delete"}
                           and (dotted_name(node.func.value) or "").endswith("__table__"))
        if func_name in SQLA_BUILDERS or orm_chain or table_statement:
            return self._orm_statement(receiver_taint | all_arg_taints)

        target, bound = self._resolve_function(func_name)
        on_instance = isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call)
        if target is not None and on_instance and self._function_class.get(target):
            # ``Runner(cfg).run(x)``: an instance method; the new object is ``self``.
            bound = "staticmethod" not in self._decorator_names(self.functions[target])

        if target is None and self.project is not None:
            external = self._resolve_project_call(dotted_name(node.func), on_instance)
            if external is not None:
                callee, name, callee_bound = external
                positional = [receiver_taint] + arg_taints if callee_bound else arg_taints
                self._trace.append({"kind": "call", "file": self.filename,
                                    "line": getattr(node, "lineno", 0),
                                    "name": f"{name} ({callee.filename})"})
                try:
                    return self.project.call(callee, name, node, positional, kw_taints)
                finally:
                    self._trace.pop()

        is_sql = func_name in SQL_SINKS or (
            target is None and isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_METHODS and _looks_like_db(node.func.value)
        )
        if is_sql:
            # Parameterized SQL keeps values outside the query string.
            query_arg = self._sink_argument(node, arg_taints, kw_taints, SQL_ARG_KEYWORDS)
            if query_arg is not None:
                query_taint = self._labels_for_context(query_arg, "sql")
                if query_taint:
                    self._add_finding(
                        node, "CS-SQL-001",
                        "Potential SQL injection: untrusted data reaches a SQL execution query.",
                        query_taint, func_name,
                    )
            return set()

        if target is not None:
            positional = [receiver_taint] + arg_taints if bound else arg_taints
            self._trace.append({"kind": "call", "file": self.filename,
                                "line": getattr(node, "lineno", 0), "name": target})
            try:
                return self._invoke_function(target, node, positional, kw_taints)
            finally:
                self._trace.pop()

        if isinstance(node.func, ast.Attribute) and node.func.attr == "hexdigest":
            # A hex digest only contains [0-9a-f], whatever was hashed.
            labels = self._raw_labels(receiver_taint | all_arg_taints)
            return {self._make_marker({c.upper() for c in SANITIZERS}, labels)} if labels else set()

        if (isinstance(node.func, ast.Attribute) and node.func.attr in {"get", "pop"}
                and isinstance(node.func.value, (ast.Dict, ast.DictComp, ast.Subscript))
                and 1 <= len(node.args) <= 2 and not node.keywords):
            # ``{"a": "a", "b": "b"}.get(user_value, "a")`` and
            # ``store.data["watching"].get(uuid)``: the result is one of the
            # mapping's values or the default; the key only selects it.
            return receiver_taint.union(*arg_taints[1:], *kw_taints)

        if (isinstance(node.func, ast.Attribute)
                and node.func.attr in CONTAINER_MUTATORS and all_arg_taints):
            # ``items.append(x)`` stores ``x`` in ``items`` (weak update, as
            # for ``d[k] = v``).
            key = store_key(node.func.value)
            if key:
                self._write(key, all_arg_taints, weak=True)
        elif func_name == "setattr" and len(node.args) >= 3:
            key = store_key(node.args[0])
            name = node.args[1]
            if key and isinstance(name, ast.Constant) and isinstance(name.value, str):
                self._write(f"{key}.{name.value}", arg_taints[2])
            elif key and arg_taints[2]:
                self._write(key, arg_taints[2], weak=True)
            return set()

        # Unknown calls (including methods on tainted objects, such as
        # str.strip/lower/split/format) conservatively preserve the taint
        # of both their arguments and their receiver.
        return all_arg_taints | receiver_taint

    @staticmethod
    def _is_orm_read(node: ast.Call) -> bool:
        """``X.query....first()``, ``X.objects....get()``, ``db.session.get(M, key)``."""
        names: list[str] = []
        current: ast.AST = node.func
        while True:
            if isinstance(current, ast.Attribute):
                names.append(current.attr)
                current = current.value
            elif isinstance(current, ast.Call):
                current = current.func
            else:
                if isinstance(current, ast.Name):
                    names.append(current.id)
                break
        names.reverse()
        if len(names) < 2 or names[-1] not in ORM_RESULT_METHODS:
            return False
        chain = names[:-1]
        return "query" in chain[1:] or "objects" in chain[1:] or (
            names[-2:] == ["session", "get"] and len(node.args) == 2)

    def _orm_statement(self, taint: set[str]) -> set[str]:
        """Taint of a SQLAlchemy statement built from values with ``taint``.

        Values become bound parameters, so their taint is wrapped in a marker
        that is safe for SQL. The marker is returned even without any taint,
        so a statement stored in a variable is still recognized when more
        clauses are chained onto it later. Raw SQL text (``text(...)``) keeps
        its own marker and is still reported at the sink.
        """
        raw_sql = {item for item in taint if RAW_SQL_CONTEXT in self._marker_contexts(item)}
        return raw_sql | {self._make_marker(ORM_CONTEXTS, self._raw_labels(taint - raw_sql))}

    def _argv_command_taint(self, func_name: str, node: ast.Call) -> set[str]:
        """Taint of the program and of ``sh -c`` payloads in argv-style calls."""
        args = node.args
        program: ast.expr | None = None
        argv_node: ast.expr | None = None
        elts: list[ast.expr] | None = None
        if func_name == "asyncio.create_subprocess_exec":
            elts = list(args)
            program = elts[0] if elts else None
        elif func_name in EXEC_SINKS or func_name in SPAWN_SINKS:
            offset = 1 if func_name in SPAWN_SINKS else 0
            if len(args) > offset:
                program = args[offset]
            short = func_name.rsplit(".", 1)[-1]
            if short.startswith(("execv", "spawnv", "posix_spawn")):
                argv_node = args[offset + 1] if len(args) > offset + 1 else None
            else:
                elts = list(args[offset + 1:])
        else:
            argv_node = args[0] if args else next(
                (kw.value for kw in node.keywords if kw.arg in COMMAND_ARG_KEYWORDS), None)
        if argv_node is not None and isinstance(argv_node, (ast.List, ast.Tuple)):
            elts = list(argv_node.elts)
            if func_name not in EXEC_SINKS and func_name not in SPAWN_SINKS:
                program = elts[0] if elts else None

        taint: set[str] = set()
        if program is not None:
            taint |= self._eval(program)
        if elts is not None:
            tail = self._shell_c_tail(elts)
            if tail is not None:
                taint = taint.union(*(self._eval(e) for e in tail))
        elif argv_node is not None:
            key = store_key(argv_node)
            if key:
                # Facts recorded when the list literal was assigned.
                taint |= self._lookup(f"{key}.<shell-c>")
                if func_name not in EXEC_SINKS and func_name not in SPAWN_SINKS:
                    taint |= self._lookup(f"{key}.<argv0>")
        return taint

    def _record_argv_literal(self, target: ast.AST, value: ast.AST) -> None:
        """Remember argv facts for ``cmd = ["sh", "-c", x]`` so a later
        ``subprocess.run(cmd)`` can be checked."""
        key = store_key(target)
        if not key or not isinstance(value, (ast.List, ast.Tuple)) or not value.elts:
            return
        tail = self._shell_c_tail(value.elts)
        if tail is not None:
            self._write(f"{key}.<shell-c>", set().union(*(self._eval(e) for e in tail)))
        self._write(f"{key}.<argv0>", self._eval(value.elts[0]))

    @staticmethod
    def _shell_c_tail(argv: list[ast.expr]) -> list[ast.expr] | None:
        """Arguments after ``-c`` when argv starts a shell (``["sh", "-c", x]``)."""
        if not argv or not isinstance(argv[0], ast.Constant) or not isinstance(argv[0].value, str):
            return None
        if argv[0].value.replace("\\", "/").rsplit("/", 1)[-1] not in SHELL_PROGRAMS:
            return None
        for index, element in enumerate(argv[1:], start=1):
            if isinstance(element, ast.Constant) and element.value in SHELL_COMMAND_FLAGS:
                return argv[index + 1:]
        return None

    # ------------------------------------------------------------- functions
    def _analyze_uncalled_functions(self) -> None:
        """Analyze function bodies that no call site reached.

        Call-site analysis supplies parameter taint, so an uncalled function
        has no known argument taint. Parameters therefore start clean, while
        sources and vulnerable flows originating inside its body are still
        inspected. Nested functions discovered along the way are analyzed too.
        """
        done: set[str] = set()
        while True:
            pending = [name for name in self.functions
                       if name not in self._called_functions and name not in done]
            if not pending:
                return
            for name in pending:
                done.add(name)
                if name in self._called_functions:
                    continue
                self._run_function(name, self._route_parameters(name))

    def _route_parameters(self, name: str) -> Env:
        """Web route handlers (``@app.route``, ``@router.get``) get request data
        in their parameters, so those start tainted instead of clean."""
        fn = self.functions[name]
        cls = self._function_class.get(name)
        view_method = (cls is not None and fn.name in HTTP_METHOD_NAMES
                       and "view" in self._class_kinds(cls))
        if not view_method and not any(d.endswith(ROUTE_DECORATOR_SUFFIXES)
                                       for d in self._decorator_names(fn)):
            return {}
        params = [p.arg for p in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs]
        if self._function_class.get(name) is not None and params:
            params = params[1:]  # ``self`` / ``cls``
        if view_method:
            # Django's ``get(self, request, pk)``: the request object itself is
            # not data; its sources (``request.GET`` ...) are tracked by name.
            params = [p for p in params if p != "request"]
        if params:
            self._source_sites["route.param"] = {
                "kind": "source", "file": self.filename, "line": fn.lineno,
                "name": f"route.param ({', '.join(params)} of {name})"}
        return {param: {"route.param"} for param in params}

    @staticmethod
    def _decorator_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
        return {name for name in (dotted_name(d) for d in fn.decorator_list) if name}

    def _resolve_function(self, func_name: str) -> tuple[str | None, bool]:
        """Map a call's dotted name to an analyzed function.

        Returns ``(qualified_name, bound)``. ``bound`` is True when the call's
        receiver must be passed as the implicit first parameter (``self`` or
        ``cls``), as in ``self.method(x)``.
        """
        for frame in reversed(self._frames):
            if func_name in frame.nested:
                return frame.nested[func_name], False
        if func_name in self.functions:
            # Module-level function, or an explicit ``Class.method(...)`` call.
            # ``Class.classmethod(...)`` still binds ``cls`` implicitly.
            fn = self.functions[func_name]
            bound = (self._function_class.get(func_name) is not None
                     and "classmethod" in self._decorator_names(fn))
            return func_name, bound
        current_class = self._class_stack[-1] if self._class_stack else None
        prefix, _, method = func_name.partition(".")
        if current_class and prefix in {"self", "cls"} and method and "." not in method:
            qualified = f"{current_class}.{method}"
            if qualified in self.functions:
                fn = self.functions[qualified]
                bound = "staticmethod" not in self._decorator_names(fn)
                return qualified, bound
        return None, False

    # ------------------------------------------------------ cross-module calls
    def _import_base(self, module: str | None, level: int) -> str | None:
        """Absolute module named by ``from <level dots><module> import ...``."""
        if not level:
            return module
        package = self.module if self.is_package else self.module.rpartition(".")[0]
        for _ in range(level - 1):
            if not package:
                return None
            package = package.rpartition(".")[0]
        if module:
            return f"{package}.{module}" if package else module
        return package or None

    def _record_project_import(self, node: ast.Import | ast.ImportFrom) -> None:
        if self.project is None:
            return
        here = Path(self.filename)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    if self.project.find_module(alias.name, here):
                        self.project_names[alias.asname] = ("module", alias.name)
                else:
                    head = alias.name.split(".", 1)[0]
                    if self.project.has_package(head, here):
                        self.project_names[head] = ("module", head)
            return
        base = self._import_base(node.module, node.level)
        if base is None:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            submodule = f"{base}.{alias.name}"
            if self.project.find_module(submodule, here):
                self.project_names[local] = ("module", submodule)
            elif self.project.find_module(base, here):
                self.project_names[local] = ("attr", base, alias.name)

    def _resolve_project_call(self, raw_name: str | None, on_instance: bool = False):
        """``(callee analyzer, function name, bound)`` for a call into a project module."""
        if not raw_name:
            return None
        parts = raw_name.split(".")
        head = parts[0]
        if head not in self.project_names or (self._is_local(head) and not self._is_local_import(head)):
            return None
        binding = self.project_names[head]
        here = Path(self.filename)
        if binding[0] == "attr":
            module, qualified = binding[1], ".".join([binding[2]] + parts[1:])
            candidates = [(module, qualified)]
        else:
            # ``pkg.sub.mod.func`` or ``mod.Class.method``: try the longest module prefix.
            rest = parts[1:]
            candidates = []
            for split in range(len(rest) - 1, -1, -1):
                module = ".".join([binding[1]] + rest[:split])
                qualified = ".".join(rest[split:])
                if qualified:
                    candidates.append((module, qualified))
        for module, qualified in candidates:
            path = self.project.find_module(module, here)
            if path is None:
                continue
            callee = self.project.analyzer(path)
            if callee is None:
                return None
            if qualified in callee.functions:
                fn = callee.functions[qualified]
                is_method = callee._function_class.get(qualified) is not None
                decorators = callee._decorator_names(fn)
                if on_instance:
                    if not is_method:
                        return None        # ``mod.factory().run()`` is not ``factory.run``
                    bound = "staticmethod" not in decorators
                else:
                    bound = is_method and "classmethod" in decorators
                return callee, qualified, bound
            return None
        return None

    def _scope_of(self, name: str) -> tuple[set[str], set[str], set[str]]:
        if name not in self._scopes:
            self._scopes[name] = function_scope(self.functions[name])
        return self._scopes[name]

    def _bind_arguments(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call,
                        positional_taints: list[set[str]],
                        keyword_taints: list[set[str]]) -> Env:
        params = [p.arg for p in fn.args.posonlyargs + fn.args.args]
        kwonly = [p.arg for p in fn.args.kwonlyargs]
        vararg = fn.args.vararg.arg if fn.args.vararg else None
        kwarg = fn.args.kwarg.arg if fn.args.kwarg else None
        bindings: dict[str, set[str]] = {}

        if any(isinstance(arg, ast.Starred) for arg in call.args):
            # ``f(*xs)``: positions are unknown, so every positional parameter
            # may receive any of the positional values.
            spread = set().union(*positional_taints)
            for name in params + ([vararg] if vararg else []):
                bindings[name] = set(spread)
        else:
            for index, name in enumerate(params):
                if index < len(positional_taints):
                    bindings[name] = set(positional_taints[index])
            if vararg:
                bindings[vararg] = set().union(*positional_taints[len(params):])

        unpacked: set[str] = set()
        for keyword, taint in zip(call.keywords, keyword_taints):
            if keyword.arg is None:
                unpacked |= taint  # ``f(**options)``
            elif keyword.arg in params or keyword.arg in kwonly:
                bindings[keyword.arg] = set(taint)
            elif kwarg:
                bindings[kwarg] = bindings.get(kwarg, set()) | taint
        if unpacked:
            for name in params + kwonly:
                bindings.setdefault(name, set()).update(unpacked)
            if kwarg:
                bindings.setdefault(kwarg, set()).update(unpacked)
        return {name: taint for name, taint in bindings.items() if taint}

    def _invoke_function(self, name: str, call: ast.Call,
                         positional_taints: list[set[str]],
                         keyword_taints: list[set[str]]) -> set[str]:
        self._called_functions.add(name)
        if name in self._active_calls:
            # Recursive call: conservatively return the union of argument taints.
            return set().union(*positional_taints, *keyword_taints)

        fn = self.functions[name]
        local_env = self._bind_arguments(fn, call, positional_taints, keyword_taints)
        _, global_names, nonlocal_names = self._scope_of(name)
        closure = self._closure_for(name)
        if nonlocal_names:
            # Writes to an enclosing function's variables are side effects a
            # summary cannot replay, so these functions are always re-run.
            return self._run_function(name, local_env, closure)
        # The summary depends only on argument, module and closure taint. For
        # functions that write globals the resulting module environment is
        # cached too and replayed on a hit, so ``global`` writers no longer
        # cause exponential re-analysis.
        cache_key = (name, _freeze(local_env), _freeze(self._module_env),
                     _freeze(closure))
        if cache_key in self._summary_cache:
            result, module_after = self._summary_cache[cache_key]
            if module_after is not None:
                module_env = self._module_env
                module_env.clear()
                module_env.update(self._copy_env(module_after))
            return set(result)
        result = self._run_function(name, local_env, closure)
        module_after = self._copy_env(self._module_env) if global_names else None
        self._summary_cache[cache_key] = (set(result), module_after)
        return result

    def _run_function(self, name: str, local_env: Env,
                      closure: Env | None = None) -> set[str]:
        fn = self.functions[name]
        local_names, global_names, nonlocal_names = self._scope_of(name)
        if closure is None:
            closure = self._closures.get(name)
        closure = self._copy_env(closure) if closure is not None else None
        self._env_stack.append(self.env)
        self.env = local_env
        frame = Frame(name, local_names, global_names, closure,
                      nonlocal_names=nonlocal_names)
        self._frames.append(frame)
        self._active_calls.add(name)
        self._return_stack.append(set())
        self._class_stack.append(self._function_class.get(name))
        refined_outside, self._refined = self._refined, {}
        # Paths that leave early inside this function belong to its own scope:
        # a caller's ``try`` must not join them into the caller's variables.
        exits_outside, self._exit_states = self._exit_states, []
        try_depth_outside, self._try_depth = self._try_depth, 0
        try:
            self._exec_block(fn.body)
            # Closures defined here may run after this function returns and
            # then see the final values of its variables (late binding).
            final = self._copy_env(frame.closure or {})
            final.update(self._copy_env())
            for qualified in frame.nested.values():
                self._closures[qualified] = self._join_envs(
                    self._closures.get(qualified, {}), final)
            return set(self._return_stack[-1])
        finally:
            self._refined = refined_outside
            self._exit_states = exits_outside
            self._try_depth = try_depth_outside
            self._class_stack.pop()
            self._return_stack.pop()
            self._active_calls.discard(name)
            self._frames.pop()
            self.env = self._env_stack.pop()

    # ---------------------------------------------------------------- guards
    def _refine_taint(self, taint: set[str], contexts: set[str]) -> set[str]:
        """``taint`` after a check made it safe for ``contexts`` (lower case)."""
        labels = self._raw_labels(taint)
        if not labels:
            return set()
        inherited: set[str] | None = None
        for item in taint:
            item_contexts = self._marker_contexts(item)
            inherited = item_contexts if inherited is None else inherited & item_contexts
        return {self._make_marker({c.upper() for c in contexts} | (inherited or set()), labels)}

    def _guard_function(self, call: ast.Call):
        """``(analyzer, function definition)`` of a project function called as a guard."""
        name = dotted_name(call.func)
        if not name:
            return None
        local, bound = self._resolve_function(name)
        if local is not None:
            return (None if bound else (self, self.functions[local]))
        on_instance = isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Call)
        external = self._resolve_project_call(name, on_instance)
        if external is not None:
            callee, qualified, bound = external
            return None if bound else (callee, callee.functions[qualified])
        return None

    def _guard_contexts(self, call: ast.Call) -> set[str]:
        """Contexts in which ``call``'s first argument is safe when the call is true."""
        name = self._canon(dotted_name(call.func))
        if name in GUARDS:
            return set(GUARDS[name])
        found = self._guard_function(call)
        if found is None:
            return set()
        analyzer, fn = found
        return analyzer.infer_guard(fn)

    def infer_guard(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, depth: int = 0) -> set[str]:
        """Contexts for which ``fn`` behaves like a check of its first parameter.

        The decision is made from what the function does, never from its
        name: it must be able to return a false value, and it must inspect
        the value the way a check for that context does (parse a URL and look
        at its host or scheme; resolve a path; look up an address). A function
        that only calls another guard inherits that guard's contexts.
        """
        key = id(fn)
        if key in self._guard_cache:
            return set(self._guard_cache[key])
        self._guard_cache[key] = set()             # recursion: not a guard
        params = [a.arg for a in fn.args.posonlyargs + fn.args.args]
        if not params or depth > 3:
            return set()
        body_nodes = [n for stmt in fn.body for n in ast.walk(stmt)]
        returns = [n for n in body_nodes if isinstance(n, ast.Return)]
        always_true = all(isinstance(r.value, ast.Constant) and r.value.value is True
                          for r in returns)
        if not returns or always_true:
            return set()
        if not any(isinstance(n, ast.Name) and n.id == params[0] for n in body_nodes):
            return set()
        contexts: set[str] = set()
        attrs = {n.attr for n in body_nodes if isinstance(n, ast.Attribute)}
        called: set[str] = set()
        for node in body_nodes:
            if not isinstance(node, ast.Call):
                continue
            full = self._canon(dotted_name(node.func))
            called.add((dotted_name(node.func) or "").rsplit(".", 1)[-1])
            if full in GUARDS:
                contexts |= GUARDS[full]
            else:
                found = self._guard_function(node)
                if found is not None:
                    analyzer, inner = found
                    contexts |= analyzer.infer_guard(inner, depth + 1)
        # Reading a URL's host is not a check: ``return urlparse(u).netloc`` is
        # truthy exactly for external URLs. The host must be compared.
        if called & _URL_PARSE and _compares(fn, _REDIRECT_DECIDE_ATTRS) \
                and not _accepts_when_present(fn, _REDIRECT_DECIDE_ATTRS):
            contexts.add("redirect")
        if called & _HOST_RESOLVE and (attrs & _ADDRESS_DECIDE_ATTRS
                                       or _compares(fn, {"hostname"})):
            contexts.add("url")
        if called & _PATH_NORMALIZE and (called & _PATH_CONTAIN_CALLS or attrs & _PATH_CONTAIN_ATTRS):
            contexts.add("path")
        self._guard_cache[key] = set(contexts)
        return contexts

    def _test_facts(self, test: ast.expr, truth: bool) -> list[tuple[ast.expr, set[str]]]:
        """Values made safe when ``test`` evaluates to ``truth``."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self._test_facts(test.operand, not truth)
        if isinstance(test, ast.BoolOp):
            # ``a and b`` true: both hold. ``a or b`` false: neither holds.
            if isinstance(test.op, ast.And) == truth:
                return [fact for value in test.values for fact in self._test_facts(value, truth)]
            return []
        if isinstance(test, ast.Call) and truth:
            regex = self._canon(dotted_name(test.func))
            if regex in REGEX_MATCHERS and len(test.args) >= 2 \
                    and isinstance(test.args[0], ast.Constant) and isinstance(test.args[0].value, str):
                pattern = test.args[0].value
                anchored = pattern.endswith(("$", "\\Z", "\\z")) or not REGEX_MATCHERS[regex]
                # Flags change what the pattern means (with ``re.M``, ``$`` also
                # matches before a newline), whether passed by keyword or position.
                if anchored and _SAFE_PATTERN.match(pattern) and len(test.args) == 2 \
                        and not test.keywords:
                    return [(test.args[1], set(SANITIZERS))]
                return []
        if isinstance(test, ast.Call) and truth and test.args \
                and not isinstance(test.args[0], ast.Starred):
            contexts = self._guard_contexts(test)
            return [(test.args[0], contexts)] if contexts else []
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, right = test.ops[0], test.comparators[0]
            # ``x in allowed`` / ``x == "literal"``: x is one of the program's
            # own values, so it is safe everywhere, if ``allowed`` is untainted.
            holds = ((isinstance(op, ast.In) and truth) or (isinstance(op, ast.NotIn) and not truth)
                     or (isinstance(op, ast.Eq) and truth and isinstance(right, ast.Constant))
                     or (isinstance(op, ast.NotEq) and not truth and isinstance(right, ast.Constant)))
            if holds and not self._raw_labels(self._eval(right)):
                return [(test.left, set(SANITIZERS))]
        return []

    def _apply_facts(self, facts: list[tuple[ast.expr, set[str]]]) -> None:
        for target, contexts in facts:
            if isinstance(target, (ast.Name, ast.Attribute)) and store_key(target):
                if self._source_name(target) is None:
                    taint = self._eval(target)
                    if taint:
                        self._assign_target(target, self._refine_taint(taint, contexts))
                    continue
            key = ast.dump(target)
            self._refined[key] = self._refined.get(key, set()) | contexts

    def _terminates(self, block: list[ast.stmt]) -> bool:
        """Whether running ``block`` never reaches the statement after it."""
        if not block:
            return False
        last = block[-1]
        # ``continue`` and ``break`` are not included: their state still
        # reaches the loop's next iteration or the code after the loop.
        if isinstance(last, (ast.Return, ast.Raise)):
            return True
        if isinstance(last, ast.Expr) and isinstance(last.value, ast.Call):
            return self._canon(dotted_name(last.value.func)) in EXIT_CALLS
        if isinstance(last, ast.If):
            return self._terminates(last.body) and self._terminates(last.orelse)
        return False

    # ------------------------------------------------------------ statements
    def _assign_target(self, target: ast.AST, taint: set[str]) -> None:
        if isinstance(target, ast.Name):
            self._write(target.id, taint)
        elif isinstance(target, ast.Attribute):
            key = store_key(target)
            if key:
                self._write(key, taint)
            else:
                self._eval(target.value)
        elif (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Call)
              and isinstance(target.value.func, ast.Name)
              and target.value.func.id == "globals" and not target.value.args
              and isinstance(target.slice, ast.Constant)
              and isinstance(target.slice.value, str)):
            # ``globals()["name"] = v`` binds a module global.
            module_env = self._module_env
            for stale in [k for k in module_env if k.startswith(target.slice.value + ".")]:
                del module_env[stale]
            if taint:
                module_env[target.slice.value] = set(taint)
            else:
                module_env.pop(target.slice.value, None)
        elif isinstance(target, ast.Subscript):
            # ``d[k] = v`` taints the container (weak update: other elements
            # may still be tainted, so existing taint is kept).
            self._eval(target.slice)
            key = store_key(target.value)
            if key:
                self._write(key, taint, weak=True)
            else:
                self._eval(target.value)
        elif isinstance(target, ast.Starred):
            self._assign_target(target.value, taint)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, taint)

    def _exec_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self._exec_stmt(statement)

    def _exec_stmt(self, node: ast.stmt) -> None:
        self._steps += 1
        if self._steps > self.max_steps:
            raise AnalysisBudgetExceeded()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._define_function(node)
            return
        if isinstance(node, ast.ClassDef):
            self._exec_class_body(node)
            return
        if isinstance(node, ast.Assign):
            if (isinstance(node.value, ast.Lambda) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)):
                # ``f = lambda x: ...`` is analyzed like ``def f(x): return ...``.
                lam = node.value
                fn = ast.FunctionDef(
                    name=node.targets[0].id, args=lam.args,
                    body=[ast.copy_location(ast.Return(value=lam.body), lam.body)],
                    decorator_list=[], returns=None, type_comment=None,
                    **({"type_params": []} if "type_params" in ast.FunctionDef._fields else {}),
                )
                ast.copy_location(fn, node)
                ast.fix_missing_locations(fn)
                self._write(fn.name, set())
                self._define_function(fn)
                return
            value = node.value
            if (isinstance(value, (ast.Tuple, ast.List))
                    and not any(isinstance(e, ast.Starred) for e in value.elts)):
                # ``a, b = x, y``: every element is evaluated first (so a swap
                # works), then each target gets only its own element's taint.
                parts = [self._eval(element) for element in value.elts]
                taint = set().union(*parts)
            else:
                parts = None
                taint = self._eval(value)
            for target in node.targets:
                if (parts is not None and isinstance(target, (ast.Tuple, ast.List))
                        and len(target.elts) == len(parts)
                        and not any(isinstance(e, ast.Starred) for e in target.elts)):
                    for element, part in zip(target.elts, parts):
                        self._assign_target(element, part)
                else:
                    self._assign_target(target, taint)
                self._record_argv_literal(target, value)
            return
        if isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._assign_target(node.target, self._eval(node.value))
            return
        if isinstance(node, ast.AugAssign):
            old = self._eval(node.target)
            self._assign_target(node.target, old | self._eval(node.value))
            return
        if isinstance(node, ast.Expr):
            self._eval(node.value)
            return
        if isinstance(node, ast.Return):
            value_taint = self._eval(node.value)
            if self._return_stack:
                self._return_stack[-1].update(value_taint)
            return
        if isinstance(node, ast.If):
            self._eval(node.test)
            incoming = self._copy_env()
            refined_in = dict(self._refined)
            # Each branch knows the outcome of the test: inside
            # ``if is_safe_url(x):`` the check passed, in its ``else`` it failed.
            self.env = self._copy_env(incoming)
            self._apply_facts(self._test_facts(node.test, True))
            self._exec_block(node.body)
            body_state, body_refined = self._copy_env(), dict(self._refined)
            self._refined = dict(refined_in)
            self.env = self._copy_env(incoming)
            self._apply_facts(self._test_facts(node.test, False))
            self._exec_block(node.orelse)
            else_state, else_refined = self._copy_env(), dict(self._refined)
            # A branch that returns, raises or aborts does not reach the next
            # statement, so ``if not ok(x): abort(403)`` leaves ``x`` checked.
            body_exits, else_exits = self._terminates(node.body), self._terminates(node.orelse)
            if body_exits and not else_exits:
                if self._try_depth:
                    self._exit_states.append(body_state)
                self.env, self._refined = else_state, else_refined
            elif else_exits and not body_exits:
                if self._try_depth:
                    self._exit_states.append(else_state)
                self.env, self._refined = body_state, body_refined
            else:
                self.env = self._join_envs(body_state, else_state)
                self._refined = {k: body_refined[k] & else_refined[k]
                                 for k in body_refined.keys() & else_refined.keys()
                                 if body_refined[k] & else_refined[k]}
            return
        if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            if isinstance(node, (ast.For, ast.AsyncFor)):
                iterable_taint = self._eval(node.iter)
                self._assign_target(node.target, iterable_taint)
            else:
                self._eval(node.test)
            entry = self._copy_env()
            state = self._copy_env(entry)
            for _ in range(self.max_loop_iterations):
                self.env = self._copy_env(state)
                self._exec_block(node.body)
                next_state = self._join_envs(entry, self._copy_env())
                if next_state == state:
                    break
                state = next_state
            self.env = state
            self._exec_block(node.orelse)
            return
        if isinstance(node, ast.Try) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
            self._exec_try(node)
            return
        if isinstance(node, ast.Match):
            self._exec_match(node)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._eval(item.context_expr)
                if item.optional_vars:
                    self._assign_target(item.optional_vars, set())
            self._exec_block(node.body)
            return
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname and alias.asname != alias.name:
                    self.aliases[alias.asname] = alias.name
            self._record_project_import(node)
            return
        if isinstance(node, ast.ImportFrom):
            self._record_project_import(node)
            if node.module and not node.level:
                for alias in node.names:
                    if alias.name == "*":
                        # ``from os import *`` binds every known ``os.<name>``.
                        prefix = node.module + "."
                        for known in KNOWN_NAMES:
                            if known.startswith(prefix):
                                first = known[len(prefix):].split(".", 1)[0]
                                self.aliases[first] = prefix + first
                        continue
                    full = f"{node.module}.{alias.name}"
                    if full == "flask.request" or _is_known(full):
                        self.aliases[alias.asname or alias.name] = full
            return
        # Generic fallback: evaluate expressions and recurse into statement blocks.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child)
            elif isinstance(child, ast.stmt):
                self._exec_stmt(child)

    def _define_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for default in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            self._eval(default)
        for decorator in node.decorator_list:
            self._eval(decorator)
        if self._frames:
            # Nested function: register it under a qualified name and keep a
            # snapshot of the enclosing scope for closure variable reads.
            frame = self._frames[-1]
            qualified = f"{frame.name}.<locals>.{node.name}"
            self._register_function(qualified, node, None)
            closure = self._copy_env(frame.closure or {})
            closure.update(self._copy_env())
            self._closures[qualified] = closure
            self._closure_owner[qualified] = frame.name
            self._scopes.pop(qualified, None)
            frame.nested[node.name] = qualified
        elif self.functions.get(node.name) is not node:
            # Conditionally defined module-level function (inside if/try).
            self._register_function(node.name, node, None)

    def _exec_class_body(self, node: ast.ClassDef) -> None:
        """Run class-level statements; their bindings become ``Class.attr``.

        Methods are pre-registered (module-level classes) and analyzed through
        calls or the uncalled-function pass, so only their defaults and
        decorators are evaluated here. Nested class bodies are executed, but
        methods of nested classes are not registered.
        """
        for expr in node.bases + [k.value for k in node.keywords] + node.decorator_list:
            self._eval(expr)
        outer = self.env
        self.env = self._copy_env(outer)
        try:
            for statement in node.body:
                if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for default in statement.args.defaults + [
                            d for d in statement.args.kw_defaults if d]:
                        self._eval(default)
                    for decorator in statement.decorator_list:
                        self._eval(decorator)
                else:
                    # Nested classes run too; their attributes end up as
                    # ``Outer.Inner.attr``.
                    self._exec_stmt(statement)
            body_env = self.env
        finally:
            self.env = outer
        self._write(node.name, set())
        for key, taint in body_env.items():
            if outer.get(key) != taint:
                self._write(f"{node.name}.{key}", taint)

    def _exec_try(self, node: ast.Try) -> None:
        incoming = self._copy_env()
        self.env = self._copy_env(incoming)
        # An exception may be raised after any statement of the body, so the
        # handlers start from the join of every intermediate state.
        snapshots = [self._copy_env()]
        exits_before = len(self._exit_states)
        self._try_depth += 1
        try:
            for statement in node.body:
                self._exec_stmt(statement)
                snapshots.append(self._copy_env())
        finally:
            self._try_depth -= 1
        # Branches that raised or returned inside the body reach the
        # handlers and ``finally`` with their own state.
        left_early = self._exit_states[exits_before:]
        del self._exit_states[exits_before:]
        self._exec_block(node.orelse)
        paths = [self._copy_env(), *left_early]
        handler_entry = self._join_many(snapshots + left_early)
        for handler in node.handlers:
            self.env = self._copy_env(handler_entry)
            if handler.type is not None:
                self._eval(handler.type)
            if handler.name:
                self._write(handler.name, set())
            self._exec_block(handler.body)
            paths.append(self._copy_env())
        self.env = self._join_many(paths)
        self._exec_block(node.finalbody)

    def _exec_match(self, node: ast.Match) -> None:
        subject_taint = self._eval(node.subject)
        incoming = self._copy_env()
        paths = [incoming]  # No case may match.
        for case in node.cases:
            self.env = self._copy_env(incoming)
            for pattern in ast.walk(case.pattern):
                if isinstance(pattern, (ast.MatchAs, ast.MatchStar)) and pattern.name:
                    self._write(pattern.name, subject_taint)
                elif isinstance(pattern, ast.MatchMapping) and pattern.rest:
                    self._write(pattern.rest, subject_taint)
                elif isinstance(pattern, ast.MatchValue):
                    self._eval(pattern.value)
            if case.guard is not None:
                self._eval(case.guard)
            self._exec_block(case.body)
            paths.append(self._copy_env())
        self.env = self._join_many(paths)

    # ------------------------------------------------------------ env helpers
    def _copy_env(self, env: Env | None = None) -> Env:
        source = env if env is not None else self.env
        return {name: set(taint) for name, taint in source.items()}

    @staticmethod
    def _join_envs(left: Env, right: Env) -> Env:
        joined: Env = {}
        for name in set(left) | set(right):
            taint = left.get(name, set()) | right.get(name, set())
            if taint:
                joined[name] = set(taint)
        return joined

    def _join_many(self, envs: list[Env]) -> Env:
        result: Env = {}
        for env in envs:
            result = self._join_envs(result, env)
        return result


SKIPPED_DIRECTORIES = {"__pycache__", "venv", "node_modules", "site-packages"}


_DB_HINTS = ("cur", "conn", "db", "session", "sess", "engine", "database", "sql",
             "tx", "trans", "pg", "mysql")


def _looks_like_db(receiver: ast.AST) -> bool:
    """Whether ``receiver.execute(...)`` is plausibly a database call.

    Any ``x.execute()`` used to count as SQL; in real projects that flagged
    task pipelines and command objects. Receivers that are calls
    (``conn.cursor().execute``) or whose name hints at a database still count.
    """
    if isinstance(receiver, ast.Call) or not isinstance(receiver, (ast.Name, ast.Attribute)):
        return True
    name = (receiver.id if isinstance(receiver, ast.Name) else receiver.attr).lower()
    return name in {"c", "cr", "con", "s", "self", "cls"} or any(h in name for h in _DB_HINTS)


def module_name(path: Path) -> tuple[str, bool]:
    """Dotted module name of ``path`` and whether it is a package ``__init__``.

    The name starts at the outermost directory that still has an
    ``__init__.py``, so ``app/models/user.py`` in package ``app`` is
    ``app.models.user`` wherever the scan was started.
    """
    path = path.resolve()
    is_package = path.stem == "__init__"
    parts = [] if is_package else [path.stem]
    parent = path.parent
    while (parent / "__init__.py").is_file():
        parts.insert(0, parent.name)
        parent = parent.parent
    return ".".join(parts) or path.parent.name, is_package


class Project:
    """Analyzes files together, so calls into other project modules are followed.

    Each file keeps its own analyzer. When a call resolves, through the
    caller's imports, to a function in another scanned file, that file is
    analyzed (once) and the function is run there with the caller's argument
    taint, so a sink in a helper module is reported in the helper module.
    """

    def __init__(self, files: Iterable[Path], overrides: dict[Path, str] | None = None) -> None:
        self.files = list(files)
        # Source to analyze instead of the file on disk (used to check a patch).
        self.overrides = dict(overrides or {})
        self.modules: dict[str, list[Path]] = {}
        self.packages: set[str] = set()
        self._module_of: dict[Path, tuple[str, bool]] = {}
        for path in self.files:
            name, is_package = module_name(path)
            self._module_of[path] = (name, is_package)
            self.modules.setdefault(name, []).append(path)
            parts = name.split(".")
            self.packages.update(".".join(parts[:i]) for i in range(1, len(parts) + 1))
        self.analyzers: dict[Path, TaintAnalyzer] = {}
        self.errors: dict[Path, str] = {}
        self._active: set[tuple[str, str]] = set()
        self.trace: list[dict] = []
        self.source_sites: dict[str, dict] = {}

    def find_module(self, name: str, importer: Path) -> Path | None:
        paths = self.modules.get(name, [])
        if len(paths) == 1:
            return paths[0]
        # Several top-level scripts with the same name: prefer the importer's directory.
        for path in paths:
            if path.parent.resolve() == importer.parent.resolve():
                return path
        return None

    def has_package(self, name: str, importer: Path) -> bool:
        return name in self.packages

    def analyzer(self, path: Path) -> "TaintAnalyzer | None":
        if path in self.analyzers:
            return self.analyzers[path]
        if path in self.errors:
            return None
        module, is_package = self._module_of.get(path) or module_name(path)
        analyzer = TaintAnalyzer(str(path), project=self, module=module, is_package=is_package)
        self.analyzers[path] = analyzer       # registered first: import cycles
        try:
            source = self.overrides.get(path)
            analyzer.analyze(source if source is not None else read_source(path))
        except (OSError, SyntaxError, UnicodeDecodeError, RecursionError,
                MemoryError, ValueError) as exc:
            del self.analyzers[path]
            self.errors[path] = f"{path}: skipped: {type(exc).__name__}: {exc}"
            return None
        return analyzer

    def call(self, callee: "TaintAnalyzer", name: str, node: ast.Call,
             positional: list[set[str]], keywords: list[set[str]]) -> set[str]:
        key = (callee.filename, name)
        if key in self._active:
            # Recursion across modules: same conservative answer as within one.
            return set().union(*positional, *keywords)
        self._active.add(key)
        try:
            return callee._invoke_function(name, node, positional, keywords)
        except AnalysisBudgetExceeded:
            callee.incomplete = f"statement budget of {callee.max_steps} exceeded"
            return set().union(*positional, *keywords)
        finally:
            self._active.discard(key)

    def run(self) -> list[Finding]:
        for path in self.files:
            self.analyzer(path)
        # Collected at the end: callers in later files add findings to helpers.
        return [f for path in self.files if path in self.analyzers
                for f in self.analyzers[path].findings]


def read_source(path: Path) -> str:
    """A Python file's text in the encoding it declares (PEP 263), UTF-8 by default."""
    with tokenize.open(path) as handle:
        return handle.read()


def analyze_file(path: Path) -> list[Finding]:
    return TaintAnalyzer(str(path)).analyze(read_source(path))


def _sarif_uri(filename: str) -> tuple[str, bool]:
    """``(uri, relative)``: paths under the working directory become
    relative URIs, so code scanning can match them to repository files."""
    path = Path(filename)
    if path.is_absolute():
        try:
            path = path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            return path.as_uri(), False
    return path.as_posix(), True


def to_sarif(findings: list[Finding], problems: list[str] | None = None) -> dict:
    """Render findings as a SARIF 2.1.0 log (for GitHub code scanning)."""
    rule_ids = list(RULE_INFO)
    rules = []
    for rule_id in rule_ids:
        name, description, cwe = RULE_INFO[rule_id]
        severity = RULE_SEVERITY[rule_id]
        rules.append({
            "id": rule_id,
            "name": name,
            "shortDescription": {"text": description},
            "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe}.html",
            "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
            "properties": {
                "tags": ["security", f"external/cwe/cwe-{cwe}"],
                "security-severity": SARIF_SECURITY_SEVERITY[severity],
            },
        })
    results = []
    for finding in findings:
        uri, relative = _sarif_uri(finding.filename)
        artifact = {"uri": uri}
        if relative:
            artifact["uriBaseId"] = "%SRCROOT%"
        results.append({
            "ruleId": finding.rule_id,
            "ruleIndex": rule_ids.index(finding.rule_id),
            "level": SARIF_LEVEL.get(finding.severity, "error"),
            "message": {"text": f"{finding.message} Source: {finding.source}. "
                                f"Sink: {finding.sink}."},
            "locations": [{"physicalLocation": {
                "artifactLocation": artifact,
                "region": {"startLine": finding.line, "startColumn": finding.column},
            }}],
            "properties": {"source": finding.source, "sink": finding.sink,
                           "confidence": finding.confidence},
        })
        if len(finding.trace) > 1:
            steps = []
            for step in finding.trace:
                step_uri, step_relative = _sarif_uri(step["file"])
                step_artifact = {"uri": step_uri}
                if step_relative:
                    step_artifact["uriBaseId"] = "%SRCROOT%"
                steps.append({"location": {
                    "physicalLocation": {"artifactLocation": step_artifact,
                                         "region": {"startLine": max(1, step["line"])}},
                    "message": {"text": f"{step['kind']}: {step['name']}"}}})
            results[-1]["codeFlows"] = [{"threadFlows": [{"locations": steps}]}]
    # The run itself completed; skipped or truncated files are reported as
    # warnings rather than as a failed run.
    invocation: dict = {"executionSuccessful": True}
    if problems:
        invocation["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": problem}} for problem in problems]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "CodeSentinel",
                "informationUri": INFORMATION_URI,
                "rules": rules,
            }},
            "invocations": [invocation],
            "results": results,
        }],
    }


def collect_python_files(paths: Iterable[Path]) -> list[Path]:
    """Expand directories to the ``*.py`` files inside them (sorted).

    Hidden directories (``.git``, ``.venv``) and common dependency folders
    are skipped. Explicit file arguments are kept as given.
    """
    files: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*.py")):
                parts = candidate.relative_to(path).parts[:-1]
                if any(p.startswith(".") or p in SKIPPED_DIRECTORIES for p in parts):
                    continue
                files.append(candidate)
        else:
            files.append(path)
    return files


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CodeSentinel Python static taint analyzer")
    parser.add_argument("paths", nargs="+", type=Path, metavar="path",
                        help="Python source files or directories to analyze")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Emit JSON findings")
    output.add_argument("--sarif", action="store_true",
                        help="Emit a SARIF 2.1.0 log (for GitHub code scanning)")
    parser.add_argument("--include-low-confidence", action="store_true",
                        help="Also report findings whose only sources are environment "
                             "variables or command-line arguments")
    parser.add_argument("--config", type=Path, metavar="FILE",
                        help="Project sanitizers, guards and sources (JSON). Default: "
                             f"{CONFIG_FILE} in the current directory, if present")
    parser.add_argument("--explain", action="store_true",
                        help="Show how the data reached each sink: source, calls followed, sink")
    args = parser.parse_args(argv)

    config_path = args.config or (Path(CONFIG_FILE) if Path(CONFIG_FILE).is_file() else None)
    if config_path is not None:
        try:
            register_config(load_config(config_path))
        except (OSError, ValueError) as exc:
            print(f"codesentinel: {config_path}: {exc}", file=sys.stderr)
            return 2

    files = collect_python_files(args.paths)
    project = Project(files)
    findings = project.run()
    problems: list[str] = []
    analyzed = 0
    suppressed = 0
    for path in files:
        analyzer = project.analyzers.get(path)
        if analyzer is None:
            problems.append(project.errors[path])
            continue
        analyzed += 1
        suppressed += len(analyzer.suppressed)
        if analyzer.incomplete:
            problems.append(f"{path}: analysis incomplete: {analyzer.incomplete}")

    hidden = 0
    if not args.include_low_confidence:
        shown = [f for f in findings if f.confidence != "low"]
        hidden = len(findings) - len(shown)
        findings = shown

    if files and not analyzed and len(files) == 1:
        # A single unreadable file is a usage error, as before.
        parser.error(problems[0])
    for problem in problems:
        print(f"warning: {problem}", file=sys.stderr)

    if args.sarif:
        print(json.dumps(to_sarif(findings, problems), indent=2))
    elif args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif findings:
        for finding in findings:
            print(f"{finding.filename}:{finding.line}:{finding.column}: {finding.severity} "
                  f"{finding.rule_id}: {finding.message} [source={finding.source}, sink={finding.sink}]")
            if args.explain:
                for step in finding.trace:
                    print(f"    {step['kind']:<6} {step['file']}:{step['line']}  {step['name']}")
    else:
        print(f"No findings ({analyzed} file{'s' if analyzed != 1 else ''} analyzed).")
    if suppressed:
        print(f"note: {suppressed} finding{'s' if suppressed != 1 else ''} silenced by "
              "'# codesentinel: ignore' comments", file=sys.stderr)
    if hidden:
        print(f"note: {hidden} low-confidence finding{'s' if hidden != 1 else ''} from "
              "environment variables or command-line arguments hidden; "
              "use --include-low-confidence to show", file=sys.stderr)
    if findings:
        return 1
    # Skipped or truncated files must not pass silently in CI.
    return 2 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
