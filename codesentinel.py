"""CodeSentinel: an educational, interprocedural Python taint analyzer.

The analyzer uses Python's AST, a conservative abstract environment, simple
function summaries evaluated at call sites (memoized per argument taint),
context-specific sanitizer rules, and bounded fixed-point iteration for loops.
It is intentionally not a replacement for mature SAST tools.
"""
from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable


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


SQL_SINKS = {"cursor.execute", "connection.execute", "db.execute"}
# Any ``<obj>.execute(...)``-style call that does not resolve to a user-defined
# function is treated as a DB-API query execution (``c.execute``,
# ``conn.cursor().execute``, ``sqlite3.connect(p).executescript`` ...).
SQL_METHODS = {"execute", "executemany", "executescript"}
SQL_ARG_KEYWORDS = {"sql", "query", "operation", "statement"}

COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput",
}
# These always hand their argument to a shell, regardless of keywords.
ALWAYS_SHELL_SINKS = {
    "os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
}
COMMAND_ARG_KEYWORDS = {"args", "cmd", "command"}

EVAL_SINKS = {"eval", "exec"}
HTML_SINKS = {"html_output", "response.write"}  # Explicit output APIs.

# Sources referenced without being called (attribute access).
SOURCES = {
    "request.args", "request.form", "request.values", "request.json",
    "os.environ", "sys.argv",
}
# Sources that produce untrusted data when called.
CALL_SOURCES = {"input"}
SOURCE_ACCESSORS = {
    "request.args.get", "request.form.get", "request.values.get",
    "request.json.get", "os.environ.get", "os.getenv",
}
SUBSCRIPT_SOURCES = {"os.environ", "sys.argv"}
# Sanitizers are sink-context-specific. A command quoting function must not
# accidentally suppress a SQL finding, and vice versa. Numeric coercion is
# safe for SQL, command and HTML contexts because it restricts the value to a
# number.
SANITIZERS = {
    "command": {"shlex.quote", "int", "float"},
    "sql": {"int", "float"},
    "html": {"html.escape", "int", "float"},
}

SAFE_MARKER = "__SAFE_"
KNOWN_NAMES = (
    SQL_SINKS | COMMAND_SINKS | EVAL_SINKS | HTML_SINKS | SOURCES | CALL_SOURCES
    | SOURCE_ACCESSORS | SUBSCRIPT_SOURCES
    | set().union(*SANITIZERS.values())
)

Env = dict[str, set[str]]


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


def function_scope(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[set[str], set[str]]:
    """Return ``(local_names, global_names)`` for a function body."""
    params = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    local_names = {p.arg for p in params}
    for extra in (fn.args.vararg, fn.args.kwarg):
        if extra:
            local_names.add(extra.arg)
    declared_global: set[str] = set()
    stack: list[ast.AST] = list(fn.body)
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            local_names.add(node.name)
            continue
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            declared_global.update(node.names)
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
    return local_names - declared_global, declared_global


@dataclass
class Frame:
    """Scope information for a function currently being analyzed."""
    name: str
    local_names: set[str]
    global_names: set[str]
    closure: Env | None = None
    nested: dict[str, str] = field(default_factory=dict)


def _freeze(env: Env | None) -> tuple:
    if not env:
        return ()
    return tuple(sorted((k, frozenset(v)) for k, v in env.items()))


class TaintAnalyzer:
    """Conservative name-based taint analysis with simple interprocedural calls."""

    def __init__(self, filename: str = "<memory>", max_loop_iterations: int = 4) -> None:
        self.filename = filename
        self.env: Env = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        # Qualified function name -> enclosing class name (None for module-level).
        self._function_class: dict[str, str | None] = {}
        self._class_stack: list[str | None] = []
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int, int, str, str]] = set()
        self._active_calls: set[str] = set()
        self._called_functions: set[str] = set()
        self._return_stack: list[set[str]] = []
        self.max_loop_iterations = max_loop_iterations
        # Import aliases: local name -> canonical dotted name.
        self.aliases: dict[str, str] = {}
        # Environments of suspended callers; index 0 is the module environment.
        self._env_stack: list[Env] = []
        self._frames: list[Frame] = []
        self._closures: dict[str, Env] = {}
        self._scopes: dict[str, tuple[set[str], set[str]]] = {}
        self._summary_cache: dict[tuple, set[str]] = {}

    # ------------------------------------------------------------------ setup
    def analyze(self, source: str) -> list[Finding]:
        tree = ast.parse(source, filename=self.filename)
        # Register functions before analyzing top-level statements so calls
        # can resolve functions declared later in the module.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._register_function(node.name, node, None)
            elif isinstance(node, ast.ClassDef):
                # Methods are registered as ``Class.method``. They are reached
                # through ``self.method(...)`` / ``Class.method(...)`` calls or,
                # failing that, by the uncalled-function pass.
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        self._register_function(f"{node.name}.{item.name}", item, node.name)
        self._exec_block(tree.body)
        self._analyze_uncalled_functions()
        return list(self.findings)

    def _register_function(self, name: str, fn: ast.FunctionDef | ast.AsyncFunctionDef,
                           cls: str | None) -> None:
        self.functions[name] = fn
        self._function_class[name] = cls

    def _add_finding(self, node: ast.AST, rule_id: str, message: str,
                     sources: set[str], sink: str) -> None:
        source_label = ", ".join(sorted(sources))
        key = (rule_id, getattr(node, "lineno", 1),
               getattr(node, "col_offset", 0), source_label, sink)
        if key in self._seen:
            return
        self._seen.add(key)
        self.findings.append(Finding(
            rule_id, "HIGH", message, source_label, sink, self.filename,
            getattr(node, "lineno", 1), getattr(node, "col_offset", 0) + 1,
        ))

    # ------------------------------------------------------- names and scopes
    def _canon(self, name: str | None) -> str | None:
        """Resolve import aliases: ``sp.run`` -> ``subprocess.run``."""
        if not name:
            return name
        head, sep, rest = name.partition(".")
        if head in self.aliases and not self._is_local(head):
            return self.aliases[head] + sep + rest
        return name

    def _is_local(self, name: str) -> bool:
        return bool(self._frames) and name in self._frames[-1].local_names

    @property
    def _module_env(self) -> Env:
        return self._env_stack[0] if self._env_stack else self.env

    def _lookup(self, key: str) -> set[str]:
        head = key.split(".", 1)[0]
        if not self._frames:
            return set(self.env.get(key, set()))
        frame = self._frames[-1]
        if head in frame.global_names:
            return set(self._module_env.get(key, set()))
        if key in self.env or head in frame.local_names:
            return set(self.env.get(key, set()))
        if frame.closure is not None and key in frame.closure:
            return set(frame.closure[key])
        return set(self._module_env.get(key, set()))

    def _write(self, key: str, taint: set[str], weak: bool = False) -> None:
        head = key.split(".", 1)[0]
        env = self.env
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
    def _source_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Call):
            func = self._canon(store_key(node.func))
            if func in CALL_SOURCES or func in SOURCE_ACCESSORS:
                return func
            return None
        if isinstance(node, ast.Subscript):
            base = self._canon(store_key(node.value))
            if base in SUBSCRIPT_SOURCES:
                return f"{base}[...]"
            return None
        if isinstance(node, (ast.Name, ast.Attribute)):
            name = self._canon(store_key(node))
            if name in SOURCES:
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
    def _labels_for_context(taint: set[str], context: str) -> set[str]:
        safe_prefix = f"{SAFE_MARKER}{context.upper()}__|"
        raw_labels: set[str] = set()
        other_context_labels: set[str] = set()
        safe_labels: set[str] = set()
        for item in taint:
            if item.startswith(SAFE_MARKER):
                labels = {label for label in item.split("|", 1)[1].split(",") if label}
                if item.startswith(safe_prefix):
                    safe_labels.update(labels)
                else:
                    other_context_labels.update(labels)
            else:
                raw_labels.add(item)
        # A value may carry multiple context markers (e.g. numeric coercion is
        # safe for SQL and shell contexts). A matching safe marker cancels the
        # corresponding other-context marker, but never an unsanitized raw flow.
        return raw_labels | (other_context_labels - safe_labels)

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
            return {source}

        if isinstance(node, ast.Name):
            return self._lookup(node.id)

        if isinstance(node, ast.NamedExpr):
            taint = self._eval(node.value)
            self._assign_target(node.target, taint)
            return taint

        if isinstance(node, ast.Call):
            return self._eval_call(node)

        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return self._eval_comprehension(node)

        if isinstance(node, ast.Attribute):
            key = store_key(node)
            stored = self._lookup(key) if key else set()
            return stored | self._eval(node.value)

        if isinstance(node, ast.Subscript):
            return self._eval(node.value) | self._eval(node.slice)

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

    def _eval_call(self, node: ast.Call) -> set[str]:
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

        if func_name in COMMAND_SINKS:
            command_arg = self._sink_argument(node, arg_taints, kw_taints, COMMAND_ARG_KEYWORDS)
            # os.system/os.popen/getoutput always invoke a shell. Other
            # subprocess APIs only do so when shell=True; argv-list calls with
            # the default shell=False are not shell-injection sinks.
            shell_enabled = func_name in ALWAYS_SHELL_SINKS or any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                and kw.value.value is True for kw in node.keywords
            )
            if shell_enabled and command_arg is not None:
                command_taint = self._labels_for_context(command_arg, "command")
                if command_taint:
                    self._add_finding(
                        node, "CS-CMD-001",
                        "Potential command injection: untrusted data reaches a shell command sink.",
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

        sanitizer_contexts = [context for context, names in SANITIZERS.items()
                              if func_name in names]
        if sanitizer_contexts:
            # Preserve the original source labels but mark the contexts in
            # which the returned value is safe. Markers from earlier
            # sanitizers stay attached.
            labels = self._raw_labels(all_arg_taints)
            if not labels:
                return set()
            joined = ",".join(sorted(labels))
            markers = {item for item in all_arg_taints if item.startswith(SAFE_MARKER)}
            for context in sanitizer_contexts:
                markers.add(f"{SAFE_MARKER}{context.upper()}__|{joined}")
            return markers

        target, bound = self._resolve_function(func_name)

        is_sql = func_name in SQL_SINKS or (
            target is None and isinstance(node.func, ast.Attribute)
            and node.func.attr in SQL_METHODS
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
            return self._invoke_function(target, node, positional, kw_taints)

        # Unknown calls (including methods on tainted objects, such as
        # str.strip/lower/split/format) conservatively preserve the taint
        # of both their arguments and their receiver.
        return all_arg_taints | receiver_taint

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
                self._run_function(name, {})

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

    def _scope_of(self, name: str) -> tuple[set[str], set[str]]:
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
        _, global_names = self._scope_of(name)
        cache_key = None
        if not global_names:
            # Functions that write module globals have side effects that a
            # cached summary would skip, so they are always re-analyzed.
            cache_key = (name, _freeze(local_env), _freeze(self._module_env),
                         _freeze(self._closures.get(name)))
            if cache_key in self._summary_cache:
                return set(self._summary_cache[cache_key])
        result = self._run_function(name, local_env)
        if cache_key is not None:
            self._summary_cache[cache_key] = set(result)
        return result

    def _run_function(self, name: str, local_env: Env) -> set[str]:
        fn = self.functions[name]
        local_names, global_names = self._scope_of(name)
        self._env_stack.append(self.env)
        self.env = local_env
        self._frames.append(Frame(name, local_names, global_names, self._closures.get(name)))
        self._active_calls.add(name)
        self._return_stack.append(set())
        self._class_stack.append(self._function_class.get(name))
        try:
            self._exec_block(fn.body)
            return set(self._return_stack[-1])
        finally:
            self._class_stack.pop()
            self._return_stack.pop()
            self._active_calls.discard(name)
            self._frames.pop()
            self.env = self._env_stack.pop()

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
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._define_function(node)
            return
        if isinstance(node, ast.ClassDef):
            # Module-level class methods are pre-registered; nested classes
            # are not modeled.
            return
        if isinstance(node, ast.Assign):
            taint = self._eval(node.value)
            for target in node.targets:
                self._assign_target(target, taint)
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
            self.env = self._copy_env(incoming)
            self._exec_block(node.body)
            body_state = self._copy_env()
            self.env = self._copy_env(incoming)
            self._exec_block(node.orelse)
            else_state = self._copy_env()
            self.env = self._join_envs(body_state, else_state)
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
            return
        if isinstance(node, ast.ImportFrom):
            if node.module and not node.level:
                for alias in node.names:
                    full = f"{node.module}.{alias.name}"
                    if _is_known(full):
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
            self._scopes.pop(qualified, None)
            frame.nested[node.name] = qualified
        elif self.functions.get(node.name) is not node:
            # Conditionally defined module-level function (inside if/try).
            self._register_function(node.name, node, None)

    def _exec_try(self, node: ast.Try) -> None:
        incoming = self._copy_env()
        self.env = self._copy_env(incoming)
        # An exception may be raised after any statement of the body, so the
        # handlers start from the join of every intermediate state.
        snapshots = [self._copy_env()]
        for statement in node.body:
            self._exec_stmt(statement)
            snapshots.append(self._copy_env())
        self._exec_block(node.orelse)
        paths = [self._copy_env()]
        handler_entry = self._join_many(snapshots)
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


def analyze_file(path: Path) -> list[Finding]:
    return TaintAnalyzer(str(path)).analyze(path.read_text(encoding="utf-8"))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CodeSentinel Python static taint analyzer")
    parser.add_argument("file", type=Path, help="Python source file to analyze")
    parser.add_argument("--json", action="store_true", help="Emit JSON findings")
    args = parser.parse_args(argv)
    try:
        findings = analyze_file(args.file)
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        parser.error(f"{args.file}: {exc}")
    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    elif findings:
        for finding in findings:
            print(f"{finding.filename}:{finding.line}:{finding.column}: {finding.severity} "
                  f"{finding.rule_id}: {finding.message} [source={finding.source}, sink={finding.sink}]")
    else:
        print("No findings.")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
