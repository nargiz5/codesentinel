"""CodeSentinel: an educational, interprocedural Python taint analyzer.

The analyzer uses Python's AST, a conservative abstract environment, simple
function summaries evaluated at call sites, context-specific sanitizer rules,
and bounded fixed-point iteration for loops. It is intentionally not a
replacement for mature SAST tools.
"""
from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
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
COMMAND_SINKS = {
    "os.system", "os.popen", "subprocess.run", "subprocess.call",
    "subprocess.Popen",
}
EVAL_SINKS = {"eval", "exec"}
HTML_SINKS = {"html_output", "response.write"}  # Explicit output APIs.
SOURCES = {
    "input", "request.args", "request.form", "request.values", "request.json",
}
SOURCE_ACCESSORS = {
    "request.args.get", "request.form.get", "request.values.get",
    "request.json.get",
}
SUBSCRIPT_SOURCES = {"os.environ", "sys.argv"}
# Sanitizers are sink-context-specific. A command quoting function must not
# accidentally suppress a SQL finding, and vice versa. Numeric coercion is
# safe for SQL/command injection because it restricts the value to a number.
SANITIZERS = {
    "command": {"shlex.quote", "int", "float"},
    "sql": {"int", "float"},
    "html": {"html.escape"},
}


def dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else None
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


class TaintAnalyzer:
    """Conservative name-based taint analysis with simple interprocedural calls."""

    def __init__(self, filename: str = "<memory>", max_loop_iterations: int = 4) -> None:
        self.filename = filename
        self.env: dict[str, set[str]] = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int, int, str, str]] = set()
        self._active_calls: set[str] = set()
        self._called_functions: set[str] = set()
        self._return_stack: list[set[str]] = []
        self.max_loop_iterations = max_loop_iterations

    def analyze(self, source: str) -> list[Finding]:
        tree = ast.parse(source, filename=self.filename)
        # Register functions before analyzing top-level statements so calls
        # can resolve functions declared later in the module.
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
        self._exec_block(tree.body)
        self._analyze_uncalled_functions()
        return list(self.findings)

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

    @staticmethod
    def _source_name(node: ast.AST) -> str | None:
        name = dotted_name(node)
        if name in SOURCES:
            return name
        if isinstance(node, ast.Call) and dotted_name(node.func) in SOURCE_ACCESSORS:
            return dotted_name(node.func)
        if isinstance(node, ast.Subscript):
            base = dotted_name(node.value)
            if base in SUBSCRIPT_SOURCES:
                return f"{base}[...]"
        return None

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
            return {source}

        if isinstance(node, ast.Name):
            return set(self.env.get(node.id, set()))

        if isinstance(node, ast.Call):
            func_name = dotted_name(node.func) or "<dynamic-call>"
            arg_taints = [self._eval(arg) for arg in node.args]
            kw_taints = [self._eval(kw.value) for kw in node.keywords]
            all_arg_taints = set().union(*arg_taints, *kw_taints) if (arg_taints or kw_taints) else set()

            if func_name in COMMAND_SINKS and node.args:
                # os.system/os.popen always invoke a shell. subprocess APIs only
                # invoke shell parsing when shell=True; argv-list calls with the
                # default shell=False are not shell-injection sinks.
                shell_enabled = func_name in {"os.system", "os.popen"} or any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True for kw in node.keywords
                )
                if shell_enabled:
                    command_taint = self._labels_for_context(arg_taints[0], "command")
                    if command_taint:
                        self._add_finding(
                            node, "CS-CMD-001",
                            "Potential command injection: untrusted data reaches a shell command sink.",
                            command_taint, func_name,
                        )
                return set()

            if func_name in SQL_SINKS and node.args:
                # Parameterized SQL keeps values outside the query string.
                query_taint = self._labels_for_context(arg_taints[0], "sql")
                if query_taint:
                    self._add_finding(
                        node, "CS-SQL-001",
                        "Potential SQL injection: untrusted data reaches a SQL execution query.",
                        query_taint, func_name,
                    )
                return set()

            if func_name in EVAL_SINKS and node.args:
                dynamic_code_taint = self._without_safe_markers(arg_taints[0])
                if dynamic_code_taint:
                    self._add_finding(
                        node, "CS-EVAL-001",
                        "Potential code injection: untrusted data reaches eval/exec.",
                        dynamic_code_taint, func_name,
                    )
                return set()

            if func_name in HTML_SINKS and node.args:
                html_taint = self._labels_for_context(arg_taints[0], "html")
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
                # which the returned value is safe.
                raw_labels = self._without_safe_markers(all_arg_taints)
                if not raw_labels:
                    return set()
                markers = set()
                for context in sanitizer_contexts:
                    markers.add(f"__SAFE_{context.upper()}__|" + ",".join(sorted(raw_labels)))
                return markers

            if func_name in self.functions:
                return self._invoke_function(func_name, node, arg_taints, kw_taints)

            # Unknown calls conservatively preserve taint, except known safe
            # command-quoted values which are not treated as raw taint.
            return set(all_arg_taints)

        if isinstance(node, ast.BinOp):
            left = self._eval(node.left)
            right = self._eval(node.right)
            return self._without_safe_markers(left | right)

        if isinstance(node, ast.JoinedStr):
            result: set[str] = set()
            for value in node.values:
                result |= self._eval(value)
            return self._without_safe_markers(result)

        if isinstance(node, ast.FormattedValue):
            return self._eval(node.value)

        if isinstance(node, ast.IfExp):
            self._eval(node.test)
            return self._without_safe_markers(self._eval(node.body) | self._eval(node.orelse))

        if isinstance(node, ast.Attribute):
            name = dotted_name(node)
            if name in SOURCES:
                return {name}
            return self._eval(node.value)

        if isinstance(node, ast.Subscript):
            return self._without_safe_markers(self._eval(node.value) | self._eval(node.slice))

        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            result: set[str] = set()
            for elt in node.elts:
                result |= self._eval(elt)
            return self._without_safe_markers(result)

        if isinstance(node, ast.Dict):
            result: set[str] = set()
            for key in node.keys:
                result |= self._eval(key)
            for value in node.values:
                result |= self._eval(value)
            return self._without_safe_markers(result)

        result: set[str] = set()
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                result |= self._eval(child)
        return self._without_safe_markers(result)

    @staticmethod
    def _without_safe_markers(taint: set[str]) -> set[str]:
        # Keep context-tagged sanitizer facts through assignments and branches;
        # the relevant sink decides whether that sanitizer is applicable.
        return set(taint)

    @staticmethod
    def _labels_for_context(taint: set[str], context: str) -> set[str]:
        safe_prefix = f"__SAFE_{context.upper()}__|"
        raw_labels: set[str] = set()
        other_context_labels: set[str] = set()
        safe_labels: set[str] = set()
        for item in taint:
            if item.startswith("__SAFE_"):
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

    def _analyze_uncalled_functions(self) -> None:
        """Analyze function bodies that no call site reached.

        Call-site analysis supplies parameter taint, so an uncalled function
        has no known argument taint. Parameters therefore start clean, while
        sources and vulnerable flows originating inside its body are still
        inspected.
        """
        for name, fn in self.functions.items():
            if name in self._called_functions:
                continue
            caller_env = self.env
            self.env = {}
            self._active_calls.add(name)
            self._return_stack.append(set())
            try:
                self._exec_block(fn.body)
            finally:
                self._return_stack.pop()
                self._active_calls.discard(name)
                self.env = caller_env

    def _invoke_function(self, name: str, call: ast.Call,
                         positional_taints: list[set[str]],
                         keyword_taints: list[set[str]]) -> set[str]:
        fn = self.functions[name]
        if name in self._active_calls:
            # Recursive call: conservatively return the union of argument taints.
            return set().union(*positional_taints, *keyword_taints) if (positional_taints or keyword_taints) else set()

        args = list(fn.args.posonlyargs) + list(fn.args.args)
        local_env: dict[str, set[str]] = {}
        for index, parameter in enumerate(args):
            local_env[parameter.arg] = set(positional_taints[index]) if index < len(positional_taints) else set()
        for parameter, taint in zip(fn.args.kwonlyargs, keyword_taints):
            local_env[parameter.arg] = set(taint)
        for keyword in call.keywords:
            if keyword.arg:
                local_env[keyword.arg] = self._eval(keyword.value)

        caller_env = self.env
        self.env = local_env
        self._called_functions.add(name)
        self._active_calls.add(name)
        self._return_stack.append(set())
        try:
            self._exec_block(fn.body)
            result = set(self._return_stack[-1])
        finally:
            self._return_stack.pop()
            self._active_calls.remove(name)
            self.env = caller_env
        return self._without_safe_markers(result)

    def _assign_target(self, target: ast.AST, taint: set[str]) -> None:
        clean_taint = self._without_safe_markers(taint)
        if isinstance(target, ast.Name):
            if clean_taint:
                self.env[target.id] = set(clean_taint)
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._assign_target(element, clean_taint)

    def _exec_block(self, statements: list[ast.stmt]) -> None:
        for statement in statements:
            self._exec_stmt(statement)

    def _exec_stmt(self, node: ast.stmt) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            # Function bodies are analyzed with call-site arguments.
            return
        if isinstance(node, ast.Assign):
            taint = self._eval(node.value)
            for target in node.targets:
                self._assign_target(target, taint)
            return
        if isinstance(node, ast.AnnAssign):
            self._assign_target(node.target, self._eval(node.value))
            return
        if isinstance(node, ast.AugAssign):
            old = self._target_taint(node.target)
            self._assign_target(node.target, old | self._eval(node.value))
            return
        if isinstance(node, ast.Expr):
            self._eval(node.value)
            return
        if isinstance(node, ast.Return):
            value_taint = self._eval(node.value)
            if self._return_stack:
                self._return_stack[-1].update(self._without_safe_markers(value_taint))
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
        if isinstance(node, ast.Try):
            incoming = self._copy_env()
            paths: list[dict[str, set[str]]] = []
            self.env = self._copy_env(incoming)
            self._exec_block(node.body)
            self._exec_block(node.orelse)
            paths.append(self._copy_env())
            for handler in node.handlers:
                self.env = self._copy_env(incoming)
                self._exec_block(handler.body)
                paths.append(self._copy_env())
            self.env = self._join_many(paths)
            self._exec_block(node.finalbody)
            return
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                self._eval(item.context_expr)
                if item.optional_vars:
                    self._assign_target(item.optional_vars, set())
            self._exec_block(node.body)
            return
        if isinstance(node, ast.Import):
            return
        if isinstance(node, ast.ImportFrom):
            return
        # Generic fallback: evaluate expressions and recurse into statement blocks.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._eval(child)
            elif isinstance(child, ast.stmt):
                self._exec_stmt(child)

    def _target_taint(self, target: ast.AST) -> set[str]:
        if isinstance(target, ast.Name):
            return set(self.env.get(target.id, set()))
        return set()

    def _copy_env(self, env: dict[str, set[str]] | None = None) -> dict[str, set[str]]:
        source = env if env is not None else self.env
        return {name: set(taint) for name, taint in source.items()}

    @staticmethod
    def _join_envs(left: dict[str, set[str]], right: dict[str, set[str]]) -> dict[str, set[str]]:
        joined: dict[str, set[str]] = {}
        for name in set(left) | set(right):
            taint = left.get(name, set()) | right.get(name, set())
            if taint:
                joined[name] = set(taint)
        return joined

    def _join_many(self, envs: list[dict[str, set[str]]]) -> dict[str, set[str]]:
        result: dict[str, set[str]] = {}
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
    except (OSError, SyntaxError) as exc:
        parser.error(str(exc))
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
