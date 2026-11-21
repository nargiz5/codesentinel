import unittest
from codesentinel import TaintAnalyzer


class AnalyzerTests(unittest.TestCase):
    def analyze(self, code):
        return TaintAnalyzer("sample.py").analyze(code)

    def test_input_to_sql_sink_is_detected(self):
        findings = self.analyze("""
user = input()
query = "SELECT * FROM users WHERE name='" + user
cursor.execute(query)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_request_args_to_sql_sink_is_detected(self):
        findings = self.analyze("""
from flask import request
cursor.execute("SELECT * FROM users WHERE id=" + request.args.get("id"))
""")
        self.assertEqual(len(findings), 1)

    def test_input_to_command_sink_is_detected(self):
        findings = self.analyze("""
import os
value = input()
os.system("echo " + value)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_clean_constant_query_is_not_flagged(self):
        self.assertEqual(self.analyze('cursor.execute("SELECT * FROM users")'), [])

    def test_reassignment_to_constant_clears_taint(self):
        findings = self.analyze("""
value = input()
value = "safe constant"
cursor.execute(value)
""")
        self.assertEqual(findings, [])

    def test_taint_survives_if_else_join(self):
        findings = self.analyze("""
value = "safe"
if condition:
    value = input()
else:
    value = "constant"
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)

    def test_taint_survives_missing_else_path(self):
        findings = self.analyze("""
value = "safe"
if condition:
    value = input()
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)

    def test_secure_parameterized_query_not_flagged(self):
        findings = self.analyze("""
value = input()
cursor.execute("SELECT * FROM users WHERE name = ?", (value,))
""")
        self.assertEqual(findings, [])

    def test_tainted_command_argument_detected(self):
        findings = self.analyze("""
import subprocess
cmd = input()
subprocess.run(cmd, shell=True)
""")
        self.assertEqual(len(findings), 1)

    # Interprocedural propagation: taint passed into a function and returned.
    def test_function_return_propagates_taint_to_sql_sink(self):
        findings = self.analyze("""
def build_query(value):
    return "SELECT * FROM users WHERE name='" + value
user = input()
query = build_query(user)
cursor.execute(query)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    # A function that contains a sink is analyzed with call-site arguments.
    def test_function_parameter_reaching_command_sink(self):
        findings = self.analyze("""
import os
def run_command(command):
    os.system(command)
run_command(input())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_function_with_clean_argument_does_not_flag(self):
        findings = self.analyze("""
import os
def run_command(command):
    os.system(command)
run_command("echo hello")
""")
        self.assertEqual(findings, [])

    def test_shlex_quote_sanitizes_command_context(self):
        findings = self.analyze("""
import os
import shlex
value = input()
os.system("echo " + shlex.quote(value))
""")
        self.assertEqual(findings, [])

    def test_shlex_quote_does_not_sanitize_sql_context(self):
        findings = self.analyze("""
import shlex
value = input()
cursor.execute("SELECT * FROM users WHERE name='" + shlex.quote(value))
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_branch_join_preserves_taint_from_either_path(self):
        findings = self.analyze("""
value = "safe"
if condition:
    value = "safe too"
else:
    value = input()
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)

    def test_loop_body_taint_survives_fixed_point_join(self):
        findings = self.analyze("""
value = "safe"
while condition:
    value = input()
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)

    def test_taint_flows_through_multiple_function_calls(self):
        findings = self.analyze("""
def identity(value):
    return value
def wrap(value):
    return identity(value)
user = input()
cursor.execute(wrap(user))
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_untainted_reassignment_inside_function(self):
        findings = self.analyze("""
def make_query(value):
    value = "SELECT 1"
    return value
user = input()
cursor.execute(make_query(user))
""")
        self.assertEqual(findings, [])

    def test_sanitizer_returned_from_helper_remains_contextual(self):
        findings = self.analyze("""
import os
import shlex
def quote(value):
    return shlex.quote(value)
user = input()
os.system("echo " + quote(user))
""")
        self.assertEqual(findings, [])

    def test_try_except_paths_are_joined(self):
        findings = self.analyze("""
value = "safe"
try:
    value = input()
except Exception:
    value = "fallback"
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)

    def test_if_expression_propagates_taint(self):
        findings = self.analyze("""
value = input() if condition else "safe"
cursor.execute(value)
""")
        self.assertEqual(len(findings), 1)


    # Regression coverage for v0.3: numeric coercion is SQL-safe.
    def test_int_coercion_sanitizes_sql_value(self):
        self.assertEqual(self.analyze("""
value = input()
cursor.execute("SELECT * FROM users WHERE id=" + str(int(value)))
"""), [])

    def test_float_coercion_sanitizes_sql_value(self):
        self.assertEqual(self.analyze("""
value = input()
cursor.execute(f"SELECT * FROM metrics WHERE score={float(value)}")
"""), [])

    def test_html_escape_sanitizes_html_output(self):
        self.assertEqual(self.analyze("""
import html
value = input()
html_output(html.escape(value))
"""), [])

    def test_html_escape_does_not_sanitize_sql(self):
        findings = self.analyze("""
import html
value = input()
cursor.execute("SELECT * FROM users WHERE name='" + html.escape(value))
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_subprocess_shell_true_is_detected(self):
        findings = self.analyze("""
import subprocess
value = input()
subprocess.run("echo " + value, shell=True)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_subprocess_argv_list_without_shell_is_not_detected(self):
        findings = self.analyze("""
import subprocess
value = input()
subprocess.run(["echo", value])
""")
        self.assertEqual(findings, [])

    def test_subprocess_shell_false_is_not_detected(self):
        findings = self.analyze("""
import subprocess
value = input()
subprocess.run("echo " + value, shell=False)
""")
        self.assertEqual(findings, [])

    def test_os_environ_subscript_is_source(self):
        findings = self.analyze("""
import os
cursor.execute("SELECT * FROM users WHERE name='" + os.environ["USER_FILTER"])
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_sys_argv_subscript_is_source(self):
        findings = self.analyze("""
import sys
os.system("echo " + sys.argv[1])
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_eval_tainted_argument_is_detected(self):
        findings = self.analyze("""
value = input()
eval(value)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-EVAL-001"])

    def test_exec_tainted_argument_is_detected(self):
        findings = self.analyze("""
import sys
exec(sys.argv[1])
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-EVAL-001"])

    def test_eval_constant_is_not_detected(self):
        self.assertEqual(self.analyze('eval("1 + 1")'), [])


    def test_uncalled_function_body_is_analyzed_for_internal_source(self):
        findings = self.analyze("""
def dormant():
    value = input()
    cursor.execute("SELECT * FROM users WHERE name='" + value)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_uncalled_function_parameter_starts_clean(self):
        findings = self.analyze("""
def dormant(value):
    cursor.execute(value)
""")
        self.assertEqual(findings, [])

    def test_called_function_is_not_reanalyzed_as_uncalled(self):
        findings = self.analyze("""
def run(value):
    cursor.execute(value)
run("SELECT 1")
""")
        self.assertEqual(findings, [])

    def test_uncalled_function_can_call_another_function(self):
        findings = self.analyze("""
def helper():
    value = input()
    cursor.execute(value)
def dormant():
    helper()
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    # Method calls: the receiver object carries taint.
    def test_method_on_tainted_variable_preserves_taint(self):
        findings = self.analyze("""
import os
value = input()
os.system(value.strip())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_method_chained_on_source_preserves_taint(self):
        findings = self.analyze("""
value = input().strip().lower()
cursor.execute("SELECT * FROM users WHERE name='" + value)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_str_format_on_tainted_template_preserves_taint(self):
        findings = self.analyze("""
template = input()
cursor.execute(template.format("x"))
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_method_on_clean_value_is_not_flagged(self):
        self.assertEqual(self.analyze("""
import os
value = "hello"
os.system("echo " + value.upper())
"""), [])

    def test_method_on_sanitized_value_stays_sanitized(self):
        self.assertEqual(self.analyze("""
import os
import shlex
value = input()
os.system("echo " + shlex.quote(value).strip())
"""), [])

    def test_sink_nested_in_method_receiver_is_detected(self):
        findings = self.analyze("""
import os
output = os.popen(input()).read()
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    # Class methods.
    def test_source_inside_uncalled_method_is_detected(self):
        findings = self.analyze("""
import os
class Runner:
    def run(self):
        os.system(input())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_self_method_call_propagates_argument_taint(self):
        findings = self.analyze("""
import os
class Runner:
    def handle(self):
        self.execute(input())
    def execute(self, command):
        os.system(command)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_self_method_return_propagates_taint(self):
        findings = self.analyze("""
class Repo:
    def read_name(self):
        return input()
    def find(self):
        cursor.execute("SELECT * FROM users WHERE name='" + self.read_name())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-SQL-001"])

    def test_self_method_with_clean_argument_is_not_flagged(self):
        self.assertEqual(self.analyze("""
import os
class Runner:
    def handle(self):
        self.execute("echo hello")
    def execute(self, command):
        os.system(command)
"""), [])

    def test_staticmethod_called_via_self_does_not_shift_arguments(self):
        findings = self.analyze("""
import os
class Runner:
    def handle(self):
        self.execute(input())
    @staticmethod
    def execute(command):
        os.system(command)
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_explicit_class_method_call_from_module_level(self):
        findings = self.analyze("""
import os
class Tools:
    @staticmethod
    def run(command):
        os.system(command)
Tools.run(input())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])


    # --- v0.6 regression tests -------------------------------------------

    def rules(self, code):
        return [f.rule_id for f in self.analyze(code)]

    def test_match_case_body_is_analyzed(self):
        self.assertEqual(self.rules("""
import os
x = input()
match x:
    case "a":
        pass
    case other:
        os.system(other)
"""), ["CS-CMD-001"])

    def test_try_star_handler_is_analyzed(self):
        import sys
        if sys.version_info < (3, 11):
            self.skipTest("except* needs Python 3.11+")
        self.assertEqual(self.rules("""
import os
try:
    pass
except* ValueError:
    os.system(input())
"""), ["CS-CMD-001"])

    def test_except_handler_sees_partial_try_body_state(self):
        self.assertEqual(self.rules("""
import os
try:
    x = input()
    risky()
except Exception:
    os.system(x)
"""), ["CS-CMD-001"])

    def test_list_comprehension_propagates_iterable_taint(self):
        self.assertEqual(self.rules("""
import os, sys
os.system(" ".join([a for a in sys.argv[1:]]))
"""), ["CS-CMD-001"])

    def test_dict_comprehension_and_generator_propagate_taint(self):
        self.assertEqual(self.rules("""
data = {k: v for k, v in request.args.items()}
cursor.execute("SELECT " + ",".join(x for x in data))
"""), ["CS-SQL-001"])

    def test_comprehension_variable_does_not_leak(self):
        self.assertEqual(self.rules("""
import os
a = "ls"
values = [a for a in input().split()]
os.system(a)
"""), [])

    def test_walrus_assignment_propagates_taint(self):
        self.assertEqual(self.rules("""
import os
if (cmd := input()):
    os.system(cmd)
"""), ["CS-CMD-001"])

    def test_attribute_store_propagates_taint(self):
        self.assertEqual(self.rules("""
import os
o = Config()
o.cmd = input()
os.system(o.cmd)
"""), ["CS-CMD-001"])

    def test_attribute_rebinding_clears_attribute_taint(self):
        self.assertEqual(self.rules("""
import os
o = Config()
o.cmd = input()
o = Config()
os.system(o.cmd)
"""), [])

    def test_subscript_store_taints_container(self):
        self.assertEqual(self.rules("""
import os
d = {}
d["k"] = input()
os.system(d["k"])
"""), ["CS-CMD-001"])

    def test_from_import_alias_is_resolved(self):
        self.assertEqual(self.rules("""
from os import system
system(input())
"""), ["CS-CMD-001"])

    def test_module_alias_is_resolved(self):
        self.assertEqual(self.rules("""
import subprocess as sp
sp.run(input(), shell=True)
"""), ["CS-CMD-001"])

    def test_aliased_sanitizer_is_resolved(self):
        self.assertEqual(self.rules("""
import os
from shlex import quote as q
os.system("echo " + q(input()))
"""), [])

    def test_from_import_source_alias(self):
        self.assertEqual(self.rules("""
import os
from sys import argv
os.system(argv[1])
"""), ["CS-CMD-001"])

    def test_subprocess_getoutput_always_uses_shell(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.getoutput(input())
"""), ["CS-CMD-001"])

    def test_subprocess_check_output_with_shell(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.check_output(input(), shell=True)
"""), ["CS-CMD-001"])

    def test_command_passed_as_keyword_argument(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.run(args=input(), shell=True)
"""), ["CS-CMD-001"])

    def test_execute_on_arbitrary_cursor_variable(self):
        self.assertEqual(self.rules("""
import sqlite3
c = sqlite3.connect("app.db").cursor()
c.execute("SELECT * FROM t WHERE id=" + input())
"""), ["CS-SQL-001"])

    def test_execute_on_chained_cursor_call(self):
        self.assertEqual(self.rules("""
conn.cursor().executemany("DELETE FROM t WHERE n='" + input() + "'", [])
"""), ["CS-SQL-001"])

    def test_parameterized_query_on_arbitrary_cursor_is_safe(self):
        self.assertEqual(self.rules("""
c = conn.cursor()
c.execute("SELECT * FROM t WHERE id = ?", (input(),))
"""), [])

    def test_user_defined_execute_method_is_not_sql_sink(self):
        self.assertEqual(self.rules("""
class Job:
    def start(self):
        self.execute(input())
    def execute(self, value):
        return value
"""), [])

    def test_module_global_is_visible_inside_function(self):
        self.assertEqual(self.rules("""
import os
CMD = input()
def run():
    os.system(CMD)
run()
"""), ["CS-CMD-001"])

    def test_local_assignment_shadows_tainted_global(self):
        self.assertEqual(self.rules("""
import os
CMD = input()
def run():
    CMD = "ls"
    os.system(CMD)
run()
"""), [])

    def test_global_statement_writes_module_taint(self):
        self.assertEqual(self.rules("""
import os
CMD = "ls"
def load():
    global CMD
    CMD = input()
load()
os.system(CMD)
"""), ["CS-CMD-001"])

    def test_nested_function_body_is_analyzed(self):
        self.assertEqual(self.rules("""
import os
def outer():
    def inner():
        os.system(input())
    inner()
outer()
"""), ["CS-CMD-001"])

    def test_nested_function_reads_closure_variable(self):
        self.assertEqual(self.rules("""
import os
def outer():
    cmd = input()
    def inner():
        os.system(cmd)
    return inner
outer()
"""), ["CS-CMD-001"])

    def test_os_getenv_and_environ_get_are_sources(self):
        findings = self.analyze("""
import os
os.system(os.getenv("A"))
os.system(os.environ.get("B"))
""")
        self.assertEqual([f.source for f in findings], ["os.getenv", "os.environ.get"])

    def test_eval_result_remains_tainted(self):
        self.assertEqual(self.rules("""
import os
y = eval(input())
os.system(y)
"""), ["CS-EVAL-001", "CS-CMD-001"])

    def test_sanitizer_markers_do_not_leak_into_report(self):
        findings = self.analyze("eval(int(input()))")
        self.assertEqual([f.source for f in findings], ["input"])

    def test_numeric_coercion_sanitizes_html(self):
        self.assertEqual(self.rules("html_output(int(input()))"), [])

    def test_keyword_only_parameter_binding_is_by_name(self):
        self.assertEqual(self.rules("""
import os
def f(a, *, b=""):
    os.system(b)
f(a=input())
"""), [])

    def test_keyword_only_parameter_receives_keyword_taint(self):
        self.assertEqual(self.rules("""
import os
def f(a, *, b=""):
    os.system(b)
f("x", b=input())
"""), ["CS-CMD-001"])

    def test_varargs_and_kwargs_receive_taint(self):
        self.assertEqual(self.rules("""
import os
def f(*parts, **opts):
    os.system(parts[0])
    os.system(opts["c"])
f(input(), c=input())
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_function_summaries_avoid_exponential_reanalysis(self):
        import time
        n = 24
        code = "import os\n" + "".join(
            f"def f{i}(x):\n    f{i + 1}(x)\n    f{i + 1}(x)\n" for i in range(n)
        ) + f"def f{n}(x):\n    os.system(x)\nf0(input())\n"
        start = time.perf_counter()
        self.assertEqual(self.rules(code), ["CS-CMD-001"])
        self.assertLess(time.perf_counter() - start, 2.0)

    def test_cli_reports_undecodable_file_without_traceback(self):
        import contextlib, io, os, tempfile
        from codesentinel import main
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as handle:
            handle.write(b"\xff\xfe")
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    main([handle.name])
            self.assertEqual(ctx.exception.code, 2)
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
