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

    def test_tuple_unpacking_taints_only_matching_target(self):
        findings = self.analyze("""
import os
host, command = input(), "uptime"
os.system(command)
os.system("ping " + host)
""")
        self.assertEqual([f.line for f in findings], [5])

    def test_tuple_swap_moves_taint(self):
        findings = self.analyze("""
import os
a, b = input(), "uptime"
a, b = b, a
os.system(a)
os.system(b)
""")
        self.assertEqual([f.line for f in findings], [6])

    def test_tuple_unpacking_with_star_or_unknown_shape_stays_conservative(self):
        findings = self.analyze("""
import os
first, *rest = input(), "a", "b"
os.system(first)
x, y = pair_from(input())
os.system(y)
""")
        self.assertEqual([f.line for f in findings], [4, 6])

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


    # Regression coverage: numeric coercion is SQL-safe.
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


    # --- regression tests -----------------------------------------------

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

    def test_closure_reads_variable_assigned_after_definition(self):
        # Closures are late-binding: ``cmd`` is read when ``inner`` runs.
        self.assertEqual(self.rules("""
import os
def outer():
    def inner():
        os.system(cmd)
    cmd = input()
    inner()
outer()
"""), ["CS-CMD-001"])

    def test_closure_sees_variable_cleaned_before_call(self):
        self.assertEqual(self.rules("""
import os
def outer():
    cmd = input()
    def inner():
        os.system(cmd)
    cmd = "ls"
    inner()
outer()
"""), [])

    def test_returned_closure_sees_final_enclosing_values(self):
        self.assertEqual(self.rules("""
import os
def make():
    cmd = "ls"
    def run():
        os.system(cmd)
    cmd = input()
    return run
make()
"""), ["CS-CMD-001"])

    def test_nonlocal_write_taints_enclosing_variable(self):
        self.assertEqual(self.rules("""
import os
def outer():
    x = "a"
    def inner():
        nonlocal x
        x = input()
    inner()
    os.system(x)
outer()
"""), ["CS-CMD-001"])

    def test_nonlocal_write_does_not_touch_module_global(self):
        self.assertEqual(self.rules("""
import os
x = "safe"
def outer():
    x = "a"
    def inner():
        nonlocal x
        x = input()
    inner()
outer()
os.system(x)
"""), [])

    def test_nonlocal_through_two_levels_of_nesting(self):
        self.assertEqual(self.rules("""
import os
def a():
    x = "s"
    def b():
        def c():
            nonlocal x
            x = input()
        c()
    b()
    os.system(x)
a()
"""), ["CS-CMD-001"])

    def test_conditional_nonlocal_clean_write_keeps_taint(self):
        self.assertEqual(self.rules("""
import os
def outer(flag):
    x = input()
    def inner():
        nonlocal x
        if flag:
            x = "safe"
    inner()
    os.system(x)
outer(True)
"""), ["CS-CMD-001"])

    def test_nonlocal_setter_called_twice_is_not_cached_away(self):
        self.assertEqual(self.rules("""
import os
def outer():
    x = "a"
    def set_it(v):
        nonlocal x
        x = v
    set_it("b")
    set_it(input())
    os.system(x)
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


class SanitizerAndSinkRegressionTests(unittest.TestCase):
    def rules(self, code):
        return [f.rule_id for f in TaintAnalyzer("sample.py").analyze(code)]

    def test_html_escaped_value_is_not_shell_safe_next_to_quoted_value(self):
        self.assertEqual(self.rules("""
import os, html, shlex
a = html.escape(input())
b = shlex.quote(input())
os.system("echo " + a + " " + b)
"""), ["CS-CMD-001"])

    def test_same_source_sanitized_for_different_contexts(self):
        self.assertEqual(self.rules("""
import os, html, shlex
v = input()
os.system("echo " + html.escape(v) + shlex.quote(v))
"""), ["CS-CMD-001"])

    def test_nested_sanitizers_remain_safe_for_both_contexts(self):
        self.assertEqual(self.rules("""
import os, html, shlex
v = shlex.quote(html.escape(input()))
os.system("echo " + v)
html_output(v)
"""), [])

    def test_user_defined_int_is_not_a_sanitizer(self):
        self.assertEqual(self.rules("""
import os
def int(x):
    return x
os.system("echo " + int(input()))
"""), ["CS-CMD-001"])

    def test_rebinding_sanitizer_name_disables_it(self):
        self.assertEqual(self.rules("""
import os
int = str
os.system("echo " + int(input()))
"""), ["CS-CMD-001"])

    def test_imported_quote_alias_is_still_a_sanitizer(self):
        self.assertEqual(self.rules("""
import os
from shlex import quote as q
os.system("echo " + q(input()))
"""), [])

    def test_sink_in_class_body_is_detected(self):
        self.assertEqual(self.rules("""
import os
class A:
    os.system(input())
"""), ["CS-CMD-001"])

    def test_tainted_class_attribute_reaches_sink(self):
        self.assertEqual(self.rules("""
import os
class Config:
    cmd = input()
    safe = "ls"
os.system(Config.cmd)
os.system(Config.safe)
"""), ["CS-CMD-001"])

    def test_list_append_taints_container(self):
        self.assertEqual(self.rules("""
import os
cmds = []
cmds.append(input())
os.system(cmds[0])
"""), ["CS-CMD-001"])

    def test_append_of_constant_stays_clean(self):
        self.assertEqual(self.rules("""
import os
cmds = []
cmds.append("ls")
os.system(cmds[0])
"""), [])

    def test_dict_update_and_set_add_taint_container(self):
        self.assertEqual(self.rules("""
import os
d = {}
d.update({"c": input()})
s = set()
s.add(input())
os.system(d["c"])
os.system(s.pop())
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_setattr_with_constant_name_taints_attribute(self):
        self.assertEqual(self.rules("""
import os
class O:
    pass
o = O()
setattr(o, "cmd", input())
os.system(o.cmd)
"""), ["CS-CMD-001"])

    def test_lambda_assigned_to_name_is_analyzed_as_function(self):
        self.assertEqual(self.rules("""
import os
run = lambda c: os.system(c)
run(input())
"""), ["CS-CMD-001"])

    def test_lambda_return_value_carries_taint(self):
        self.assertEqual(self.rules("""
import os
wrap = lambda c: "echo " + c
os.system(wrap(input()))
os.system(wrap("hi"))
"""), ["CS-CMD-001"])

    def test_lambda_inside_function_is_analyzed(self):
        self.assertEqual(self.rules("""
import os
def main():
    run = lambda c: os.system(c)
    run(input())
"""), ["CS-CMD-001"])

    def test_star_import_resolves_known_sinks_and_sources(self):
        self.assertEqual(self.rules("""
from os import *
from subprocess import *
system(getenv("CMD"))
run(input(), shell=True)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_global_writers_do_not_cause_exponential_reanalysis(self):
        import time
        n = 24
        code = "import os\ng = ''\n" + "".join(
            f"def f{i}():\n    global g\n    g = g\n    f{i + 1}()\n    f{i + 1}()\n"
            for i in range(n)
        ) + f"def f{n}():\n    global g\n    g = input()\nf0()\nos.system(g)\n"
        start = time.perf_counter()
        self.assertEqual(self.rules(code), ["CS-CMD-001"])
        self.assertLess(time.perf_counter() - start, 2.0)

    def test_deeply_nested_code_marks_analysis_incomplete(self):
        import sys
        code = "x = " + "+".join(["1"] * (sys.getrecursionlimit() * 3)) + "\n"
        analyzer = TaintAnalyzer("sample.py")
        try:
            analyzer.analyze(code)
        except (RecursionError, SyntaxError, MemoryError):
            self.skipTest("parser itself rejected the input")
        self.assertIsNotNone(analyzer.incomplete)

    def test_statement_budget_stops_analysis(self):
        analyzer = TaintAnalyzer("sample.py", max_steps=10)
        analyzer.analyze("x = 1\n" * 50)
        self.assertIn("budget", analyzer.incomplete)

    def test_long_assignment_chain_in_loop_reaches_fixed_point(self):
        self.assertEqual(self.rules("""
import os
a = b = c = d = e = ""
while True:
    a = b
    b = c
    c = d
    d = e
    e = input()
    os.system(a)
"""), ["CS-CMD-001"])

    def test_non_literal_shell_flag_is_treated_as_enabled(self):
        self.assertEqual(self.rules("""
import subprocess
use_shell = True
subprocess.run(input(), shell=use_shell)
subprocess.run(input(), shell=False)
"""), ["CS-CMD-001"])

    def test_explicit_shell_in_argv_list_is_a_command_sink(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.run(["sh", "-c", input()])
subprocess.run(["/bin/bash", "-c", "ls"])
subprocess.run(["ls", input()])
"""), ["CS-CMD-001"])

    def test_asyncio_subprocess_shell_and_exec(self):
        self.assertEqual(self.rules("""
import asyncio
async def main():
    await asyncio.create_subprocess_shell(input())
    await asyncio.create_subprocess_exec("bash", "-c", input())
    await asyncio.create_subprocess_exec("ls", input())
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_getattr_and_dunder_import_resolve_sinks(self):
        self.assertEqual(self.rules("""
import os, builtins
getattr(os, "system")(input())
__import__("os").system(input())
builtins.exec(input())
"""), ["CS-CMD-001", "CS-CMD-001", "CS-EVAL-001"])

    def test_more_flask_and_stdin_sources(self):
        self.assertEqual(self.rules("""
import os, sys
from flask import request as req
os.system(req.args.get("a"))
os.system(req.cookies.get("b"))
os.system(req.headers["c"])
os.system(req.get_json()["d"])
os.system(sys.stdin.read())
"""), ["CS-CMD-001"] * 5)

    def test_route_handler_parameters_are_tainted(self):
        self.assertEqual(self.rules("""
import os
from flask import Flask
app = Flask(__name__)

@app.route("/ping/<host>")
def ping(host):
    os.system("ping " + host)

def helper(host):
    os.system("ping " + host)
"""), ["CS-CMD-001"])

    def test_findings_carry_rule_specific_severity(self):
        findings = TaintAnalyzer("sample.py").analyze(
            "import os\nos.system(input())\nhtml_output(input())\n")
        self.assertEqual([(f.rule_id, f.severity) for f in findings],
                         [("CS-CMD-001", "HIGH"), ("CS-XSS-001", "MEDIUM")])

    def test_untrusted_pickle_marshal_and_yaml_are_reported(self):
        self.assertEqual(self.rules("""
import pickle, marshal, yaml
from flask import request
pickle.loads(request.data)
marshal.loads(request.data)
yaml.load(request.data)
yaml.load(request.data, Loader=yaml.Loader)
"""), ["CS-DESER-001"] * 4)

    def test_safe_yaml_loader_and_constant_data_are_not_reported(self):
        self.assertEqual(self.rules("""
import pickle, yaml
from flask import request
yaml.load(request.data, Loader=yaml.SafeLoader)
yaml.load(request.data, yaml.CSafeLoader)
yaml.safe_load(request.data)
pickle.loads(b"constant")
"""), [])

    def test_untrusted_path_reaching_open_is_reported_as_medium(self):
        findings = TaintAnalyzer("sample.py").analyze("""
from flask import request
with open("/srv/files/" + request.args.get("name")) as handle:
    handle.read()
open(file=request.args.get("name"))
""")
        self.assertEqual([(f.rule_id, f.severity) for f in findings],
                         [("CS-PATH-001", "MEDIUM")] * 2)

    def test_basename_and_secure_filename_sanitize_paths(self):
        self.assertEqual(self.rules("""
import os
from flask import request
from werkzeug.utils import secure_filename
open("/srv/" + os.path.basename(request.args.get("a")))
open("/srv/" + secure_filename(request.args.get("b")))
open("/srv/static.txt")
"""), [])

    def test_basename_does_not_sanitize_shell_commands(self):
        self.assertEqual(self.rules("""
import os
os.system("cat " + os.path.basename(input()))
"""), ["CS-CMD-001"])

    def run_cli(self, *argv):
        import contextlib, io
        from codesentinel import main
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_cli_scans_directories_recursively(self):
        import json, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "pkg" / "bad.py").write_text("import os\nos.system(input())\n")
            (root / "clean.py").write_text("print('hello')\n")
            (root / ".venv").mkdir()
            (root / ".venv" / "dep.py").write_text("import os\nos.system(input())\n")
            code, out, _ = self.run_cli(str(root), "--json")
        self.assertEqual(code, 1)
        findings = json.loads(out)
        self.assertEqual([f["rule_id"] for f in findings], ["CS-CMD-001"])
        self.assertTrue(findings[0]["filename"].endswith("bad.py"))

    def test_cli_continues_after_syntax_error(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken.py").write_text("def (:\n")
            (root / "bad.py").write_text("import os\nos.system(input())\n")
            code, out, err = self.run_cli(str(root / "broken.py"), str(root / "bad.py"))
        self.assertEqual(code, 1)
        self.assertIn("CS-CMD-001", out)
        self.assertIn("broken.py: skipped", err)

    def test_cli_sarif_output(self):
        import json, os, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text(
                "import os\nos.system(input())\nopen(input())\n")
            Path(tmp, "broken.py").write_text("def (:\n")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                code, out, _ = self.run_cli("app.py", "broken.py", "--sarif")
            finally:
                os.chdir(cwd)
        self.assertEqual(code, 1)
        log = json.loads(out)
        self.assertEqual(log["version"], "2.1.0")
        run = log["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        results = run["results"]
        self.assertEqual([r["ruleId"] for r in results], ["CS-CMD-001", "CS-PATH-001"])
        for result in results:
            self.assertEqual(rules[result["ruleIndex"]]["id"], result["ruleId"])
        self.assertEqual([r["level"] for r in results], ["error", "warning"])
        location = results[0]["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"],
                         {"uri": "app.py", "uriBaseId": "%SRCROOT%"})
        self.assertEqual(location["region"], {"startLine": 2, "startColumn": 1})
        cmd_rule = next(r for r in rules if r["id"] == "CS-CMD-001")
        self.assertIn("external/cwe/cwe-78", cmd_rule["properties"]["tags"])
        self.assertEqual(cmd_rule["properties"]["security-severity"], "8.0")
        notes = run["invocations"][0]["toolExecutionNotifications"]
        self.assertIn("broken.py: skipped", notes[0]["message"]["text"])

    def test_cli_sarif_absolute_path_is_made_relative(self):
        import json, os, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "pkg", "bad.py")
            target.parent.mkdir()
            target.write_text("import os\nos.system(input())\n")
            cwd = os.getcwd()
            os.chdir(tmp)
            try:
                _, out, _ = self.run_cli(str(target.resolve()), "--sarif")
            finally:
                os.chdir(cwd)
        uri = json.loads(out)["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"]["artifactLocation"]["uri"]
        self.assertEqual(uri, "pkg/bad.py")

    def test_cli_sarif_with_no_findings_has_empty_results(self):
        import json, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text("x = 1\n")
            code, out, _ = self.run_cli(tmp, "--sarif")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["runs"][0]["results"], [])

    def test_cli_clean_directory_exits_zero(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text("x = 1\n")
            code, out, _ = self.run_cli(tmp)
        self.assertEqual(code, 0)
        self.assertIn("No findings", out)

    def test_pandas_read_sql_and_exec_driver_sql_are_sql_sinks(self):
        self.assertEqual(self.rules("""
import pandas as pd
q = "SELECT * FROM users WHERE name = '" + input() + "'"
pd.read_sql(q, conn)
engine.exec_driver_sql(q)
pd.read_sql("SELECT * FROM users WHERE id = ?", conn, params=[input()])
"""), ["CS-SQL-001", "CS-SQL-001"])

    def test_parameter_named_like_sanitizer_only_affects_its_function(self):
        self.assertEqual(self.rules("""
import html
def render(html):
    return html
def cast(int):
    return int
html_output(html.escape(input()))
cursor.execute("SELECT * FROM t WHERE id=" + str(int(input())))
"""), [])

    def test_sanitizer_rebound_inside_function_is_not_trusted_there(self):
        self.assertEqual(self.rules("""
import os
def handler():
    int = str
    os.system("echo " + int(input()))
os.system("echo " + str(int(input())))
"""), ["CS-CMD-001"])

    def test_os_exec_and_spawn_with_shell_or_untrusted_program(self):
        self.assertEqual(self.rules("""
import os
os.execv("/bin/sh", ["sh", "-c", input()])
os.execlp("sh", "sh", "-c", input())
os.spawnlp(os.P_WAIT, "sh", "sh", "-c", input())
os.spawnv(os.P_WAIT, input(), ["tool"])
os.execv("/usr/bin/ls", ["ls", input()])
"""), ["CS-CMD-001"] * 4)

    def test_shell_argv_passed_as_keyword_or_variable(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.run(args=["sh", "-c", input()])
cmd = ["bash", "-c", input()]
subprocess.run(cmd)
safe = ["ping", "-c", "1", input()]
subprocess.run(safe)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_untrusted_program_in_argv_list_is_reported(self):
        self.assertEqual(self.rules("""
import subprocess
subprocess.run([input(), "--version"])
prog = [input()]
subprocess.call(prog)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_reassigning_argv_variable_clears_recorded_facts(self):
        self.assertEqual(self.rules("""
import subprocess
cmd = ["sh", "-c", input()]
cmd = ["ls", "-l"]
subprocess.run(cmd)
"""), [])

    def test_globals_subscript_assignment_binds_module_global(self):
        self.assertEqual(self.rules("""
import os
globals()["cmd"] = input()
os.system(cmd)
def f():
    globals()["other"] = input()
f()
os.system(other)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_nested_class_body_is_analyzed(self):
        self.assertEqual(self.rules("""
import os
class Outer:
    class Inner:
        os.system(input())
        cmd = input()
os.system(Outer.Inner.cmd)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_hexdigest_of_untrusted_data_is_safe(self):
        self.assertEqual(self.rules("""
import hashlib, os
h = hashlib.sha256()
h.update(input().encode())
os.system("echo " + h.hexdigest())
cursor.execute("SELECT 1 WHERE h='" + hashlib.md5(input().encode()).hexdigest() + "'")
eval(h.hexdigest())
"""), ["CS-EVAL-001"])

    def test_several_sources_at_one_sink_give_one_finding(self):
        findings = TaintAnalyzer("sample.py").analyze("""
import os
def run(cmd):
    os.system(cmd)
run(input())
run(os.getenv("CMD"))
""")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].source, "input, os.getenv")

    def test_command_line_paths_are_not_path_traversal(self):
        self.assertEqual(self.rules("""
import sys
from flask import request
open(sys.argv[1])
open("/srv/" + sys.argv[1] + request.args.get("name"))
"""), ["CS-PATH-001"])

    def test_command_line_arguments_still_reach_other_sinks(self):
        self.assertEqual(self.rules("""
import os, sys
os.system("cat " + sys.argv[1])
"""), ["CS-CMD-001"])

    def test_aliased_sanitizer_modules_stay_trusted(self):
        self.assertEqual(self.rules("""
import os
import shlex as sh
import os.path as osp
import html as h
x = input()
os.system("ls " + sh.quote(x))
open(osp.basename(x))
html_output(h.escape(x))
"""), [])

    def test_aliased_sanitizer_module_inside_function(self):
        self.assertEqual(self.rules("""
import os
def run(x):
    import shlex as sh
    os.system("ls " + sh.quote(x))
run(input())
"""), [])

    def test_alias_of_unrelated_module_still_hides_sanitizer_name(self):
        self.assertEqual(self.rules("""
import os
import json as int
os.system("ls " + int(input()))
"""), ["CS-CMD-001"])

    def test_imports_inside_functions_resolve_sinks(self):
        self.assertEqual(self.rules("""
def f():
    import subprocess as sp
    sp.run(input(), shell=True)
def g():
    from os import system
    system(input())
f()
g()
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_local_variable_still_hides_module_alias(self):
        self.assertEqual(self.rules("""
import subprocess as sp
def f(sp):
    sp.run(input(), shell=True)
f(object())
"""), [])


class RealWorldFalsePositiveTests(unittest.TestCase):
    """Patterns that caused false positives in real Flask projects (see docs/REAL_WORLD.md)."""

    def findings(self, code):
        return TaintAnalyzer("sample.py").analyze(code)

    def rules(self, code):
        return sorted(f.rule_id for f in self.findings(code))

    # --- a tainted key selects a value but does not taint it
    def test_session_lookup_with_tainted_key_is_not_tainted(self):
        self.assertEqual(self.rules("""
import pickle
from flask import session
@app.route("/q/<trans_id>")
def poll(trans_id):
    obj = pickle.loads(session["grid"][str(trans_id)]["command"])
"""), [])

    def test_tainted_container_lookup_is_still_tainted(self):
        self.assertEqual(self.rules("""
import pickle
from flask import request
pickle.loads(request.form["blob"])
data = {"blob": request.get_data()}
pickle.loads(data["blob"])
"""), ["CS-DESER-001", "CS-DESER-001"])

    def test_slice_of_tainted_value_is_tainted(self):
        self.assertEqual(self.rules("""
import os
os.system(input()[1:])
"""), ["CS-CMD-001"])

    def test_sink_inside_subscript_key_is_still_analyzed(self):
        self.assertEqual(self.rules("""
import os
table = {}
x = table[os.system(input())]
"""), ["CS-CMD-001"])

    def test_dict_literal_whitelist_get(self):
        self.assertEqual(self.rules("""
from flask import request
column = {"name": "name", "age": "age"}.get(request.args["sort"], "name")
conn.execute("SELECT * FROM users ORDER BY " + column)
"""), [])

    def test_dict_literal_get_with_tainted_default_is_reported(self):
        self.assertEqual(self.rules("""
from flask import request
column = {"name": "name"}.get("x", request.args["sort"])
conn.execute("SELECT * FROM users ORDER BY " + column)
"""), ["CS-SQL-001"])

    # --- operator-controlled sources are low confidence
    def test_environment_only_finding_is_low_confidence(self):
        [finding] = self.findings("""
import os, subprocess
subprocess.Popen(os.environ["WORKER_CMD"], shell=True)
""")
        self.assertEqual(finding.confidence, "low")

    def test_mixed_sources_are_high_confidence(self):
        [finding] = self.findings("""
import os
os.system(os.environ.get("BIN", "") + input())
""")
        self.assertEqual(finding.confidence, "high")

    def test_cli_hides_low_confidence_by_default(self):
        import contextlib, io, tempfile, pathlib
        from codesentinel import main
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "worker.py"
            path.write_text('import os\nos.system(os.getenv("CMD"))\n')
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(main([str(path)]), 0)
            self.assertIn("1 low-confidence finding", err.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path), "--include-low-confidence"]), 1)

    # --- SQLAlchemy statement builders use bound parameters
    def test_sqlalchemy_select_with_tainted_values_is_safe(self):
        self.assertEqual(self.rules("""
import sqlalchemy as sa
from flask import request
ids = request.form.getlist("rowid")
db.session.execute(sa.select(Topic).filter(Topic.id.in_(ids))).scalars().all()
"""), [])

    def test_statement_in_variable_with_later_clauses_is_safe(self):
        self.assertEqual(self.rules("""
from sqlalchemy import select
from flask import request
stmt = select(User)
stmt = stmt.where(User.name == request.args["name"]).order_by(User.id)
db.session.execute(stmt)
"""), [])

    def test_raw_text_inside_builder_is_still_reported(self):
        self.assertEqual(self.rules("""
import sqlalchemy as sa
from flask import request
stmt = sa.select(User).where(sa.text("name = '" + request.args["name"] + "'"))
db.session.execute(stmt)
"""), ["CS-SQL-001"])

    def test_text_in_variable_is_still_reported(self):
        self.assertEqual(self.rules("""
from sqlalchemy import text, select
clause = text("id = " + input())
db.session.execute(select(User).where(clause))
"""), ["CS-SQL-001"])

    def test_table_select_is_an_orm_statement(self):
        self.assertEqual(self.rules("""
from flask import request
db.session.execute(Pages.__table__.select().where(Pages.route == request.args["r"]))
"""), [])

    def test_execute_on_non_database_object_is_not_sql(self):
        self.assertEqual(self.rules("""
from flask import request
pipeline.execute(request.args["ctx"])
task_runner.execute("x" + request.args["ctx"])
"""), [])

    def test_execute_on_database_like_receivers_is_sql(self):
        self.assertEqual(self.rules("""
q = "SELECT * FROM t WHERE id = " + input()
cur.execute(q)
conn.cursor().execute(q)
self.db.execute(q)
get_connection().execute(q)
"""), ["CS-SQL-001"] * 4)

    def test_same_module_instance_call_binds_self(self):
        self.assertEqual(self.rules("""
import os
class Runner:
    def run(self, cmd, safe):
        os.system(safe)
Runner().run(input(), "uptime")
"""), [])

    def test_plain_string_query_is_still_reported(self):
        self.assertEqual(self.rules("""
from flask import request
db.session.execute("SELECT * FROM t WHERE id = " + request.args["id"])
"""), ["CS-SQL-001"])


class SuppressionTests(unittest.TestCase):
    def analyzer(self, code):
        analyzer = TaintAnalyzer("sample.py")
        return analyzer, analyzer.analyze(code)

    def test_ignore_all_rules_on_line(self):
        analyzer, findings = self.analyzer("""
import os
os.system(input())  # codesentinel: ignore
""")
        self.assertEqual(findings, [])
        self.assertEqual([f.rule_id for f in analyzer.suppressed], ["CS-CMD-001"])

    def test_ignore_only_listed_rule(self):
        _, findings = self.analyzer("""
import os
os.system(input())  # codesentinel: ignore[CS-SQL-001]
cursor.execute(input())  # codesentinel: ignore[cs-sql-001, CS-PATH-001]
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_comment_on_any_line_of_multiline_sink(self):
        _, findings = self.analyzer("""
import os
os.system(
    "ping " + input()  # codesentinel: ignore
)
""")
        self.assertEqual(findings, [])

    def test_marker_inside_string_does_not_suppress(self):
        _, findings = self.analyzer("""
import os
os.system(input() + "# codesentinel: ignore")
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_comment_on_other_line_does_not_suppress(self):
        _, findings = self.analyzer("""
import os
# codesentinel: ignore
os.system(input())
""")
        self.assertEqual([f.rule_id for f in findings], ["CS-CMD-001"])

    def test_suppression_inside_called_function(self):
        _, findings = self.analyzer("""
import os
def run(cmd):
    os.system(cmd)  # codesentinel: ignore[CS-CMD-001]
run(input())
""")
        self.assertEqual(findings, [])


class CrossModuleTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = __import__("pathlib").Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, rel, code):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
        return path

    def run_project(self):
        from codesentinel import Project, collect_python_files
        project = Project(collect_python_files([self.root]))
        return project, sorted((self.relative(f.filename), f.line, f.rule_id) for f in project.run())

    def relative(self, filename):
        return __import__("pathlib").Path(filename).relative_to(self.root).as_posix()

    def test_sibling_script_import(self):
        self.write("main.py", "from helpers import restart\nrestart(input())\n")
        self.write("helpers.py", "import os\ndef restart(s):\n    os.system('systemctl restart ' + s)\n")
        _, found = self.run_project()
        self.assertEqual(found, [("helpers.py", 3, "CS-CMD-001")])

    def test_clean_argument_is_not_reported(self):
        self.write("main.py", "from helpers import restart\nrestart('nginx')\n")
        self.write("helpers.py", "import os\ndef restart(s):\n    os.system('systemctl restart ' + s)\n")
        self.assertEqual(self.run_project()[1], [])

    def test_package_relative_and_absolute_imports(self):
        self.write("app/__init__.py", "")
        self.write("app/svc/__init__.py", "")
        self.write("app/svc/runner.py",
                   "import os\ndef ping(h):\n    os.system('ping ' + h)\n"
                   "class Runner:\n    @staticmethod\n    def go(x):\n        os.system(x)\n")
        self.write("app/views.py",
                   "from flask import request\n"
                   "from .svc import runner\n"
                   "from .svc.runner import Runner\n"
                   "@bp.route('/a')\n"
                   "def a():\n"
                   "    runner.ping(request.args['h'])\n"
                   "    Runner.go(request.args['g'])\n")
        _, found = self.run_project()
        self.assertEqual(found, [("app/svc/runner.py", 3, "CS-CMD-001"),
                                 ("app/svc/runner.py", 7, "CS-CMD-001")])

    def test_dotted_module_import(self):
        self.write("app/__init__.py", "")
        self.write("app/db.py", "def run(q):\n    cursor.execute(q)\n")
        self.write("main.py", "import app.db\nimport app.db as database\n"
                              "app.db.run('SELECT ' + input())\n")
        self.assertEqual(self.run_project()[1], [("app/db.py", 2, "CS-SQL-001")])

    def test_tainted_return_value_flows_back(self):
        self.write("main.py", "import os\nfrom helpers import read\nos.system(read())\n")
        self.write("helpers.py", "def read():\n    return input()\n")
        self.assertEqual(self.run_project()[1], [("main.py", 3, "CS-CMD-001")])

    def test_sanitizer_in_other_module_is_respected(self):
        self.write("main.py", "import os\nfrom helpers import clean\nos.system('ping ' + clean(input()))\n")
        self.write("helpers.py", "import shlex\ndef clean(v):\n    return shlex.quote(v)\n")
        self.assertEqual(self.run_project()[1], [])

    def test_import_cycle_terminates(self):
        self.write("a.py", "import os\nfrom b import g\ndef f(x):\n    return g(x)\nos.system(f(input()))\n")
        self.write("b.py", "from a import f\ndef g(x):\n    return f(x)\n")
        _, found = self.run_project()
        self.assertEqual(found, [("a.py", 5, "CS-CMD-001")])

    def test_local_name_shadows_imported_module(self):
        self.write("helpers.py", "import os\ndef run(s):\n    os.system(s)\n")
        self.write("main.py", "import helpers\ndef f(helpers):\n    helpers.run(input())\nf(object())\n")
        self.assertEqual(self.run_project()[1], [])

    def test_instance_method_call_binds_self(self):
        self.write("runner.py", "import os\nclass Runner:\n    def __init__(self, cfg):\n        pass\n"
                                "    def run(self, cmd, safe):\n        os.system(safe)\n")
        self.write("main.py", "from runner import Runner\nRunner({}).run(input(), 'uptime')\n")
        self.assertEqual(self.run_project()[1], [])
        self.write("main.py", "from runner import Runner\nRunner({}).run('x', input())\n")
        self.assertEqual(self.run_project()[1], [("runner.py", 6, "CS-CMD-001")])

    def test_unparsable_module_is_reported_not_fatal(self):
        self.write("main.py", "from broken import run\nrun(input())\n")
        self.write("broken.py", "def run(:\n")
        project, found = self.run_project()
        self.assertEqual(found, [])
        self.assertEqual(len(project.errors), 1)


class FrameworkAndNewRuleTests(unittest.TestCase):
    def rules(self, code):
        return sorted(f.rule_id for f in TaintAnalyzer("sample.py").analyze(code))

    # --- Django, DRF, Starlette sources
    def test_django_request_sources(self):
        self.assertEqual(self.rules("""
import os
def view(request):
    os.system("ping " + request.GET["h"])
    os.system("ping " + request.POST.get("h"))
    cursor.execute("SELECT * FROM t WHERE id = " + request.COOKIES["id"])
"""), ["CS-CMD-001", "CS-CMD-001", "CS-SQL-001"])

    def test_drf_and_starlette_sources(self):
        self.assertEqual(self.rules("""
import os
def view(request):
    os.system(request.query_params["h"])
async def endpoint(request):
    data = await request.json()
    os.system(data["cmd"])
    os.system(request.path_params["p"])
"""), ["CS-CMD-001", "CS-CMD-001", "CS-CMD-001"])

    # --- SSRF
    def test_ssrf(self):
        self.assertEqual(self.rules("""
import requests, httpx, urllib.request
from flask import request
requests.get(request.args["url"])
httpx.post(url=request.args["url"])
requests.request("GET", request.args["url"])
urllib.request.urlopen(request.args["url"])
"""), ["CS-SSRF-001"] * 4)

    def test_ssrf_fixed_url_with_user_data_in_params_is_safe(self):
        self.assertEqual(self.rules("""
import requests
from flask import request
requests.get("https://api.example.com/search", params={"q": request.args["q"]})
requests.request(request.args["method"], "https://api.example.com/")
"""), [])

    def test_response_of_attacker_url_stays_tainted(self):
        self.assertEqual(self.rules("""
import pickle, requests
from flask import request
pickle.loads(requests.get(request.args["url"]).content)
"""), ["CS-DESER-001", "CS-SSRF-001"])

    # --- SSTI
    def test_ssti(self):
        self.assertEqual(self.rules("""
from flask import request, render_template_string
import jinja2
render_template_string(request.args["t"])
jinja2.Template(request.args["t"])
render_template_string("Hello {{ name }}", name=request.args["name"])
"""), ["CS-SSTI-001", "CS-SSTI-001"])

    def test_html_escape_does_not_stop_ssti(self):
        self.assertEqual(self.rules("""
import html
from flask import request, render_template_string
render_template_string(html.escape(request.args["t"]))
"""), ["CS-SSTI-001"])

    # --- open redirect
    def test_open_redirect(self):
        self.assertEqual(self.rules("""
from flask import request, redirect, url_for
from django.shortcuts import redirect as dj_redirect
redirect(request.args["next"])
dj_redirect(request.args["next"])
redirect(url_for("profile", user=request.args["u"]))
redirect("/home")
"""), ["CS-REDIRECT-001", "CS-REDIRECT-001"])

    def test_environment_only_ssrf_is_low_confidence(self):
        [finding] = TaintAnalyzer("s.py").analyze('''
import os, requests
requests.get(os.environ["API_URL"])
''')
        self.assertEqual((finding.rule_id, finding.confidence), ("CS-SSRF-001", "low"))



GUARD_HELPERS = """
from flask import request, redirect, abort
import os, subprocess
from urllib.parse import urlparse

def is_safe_url(target):
    ref = urlparse("http://example.com/")
    test = urlparse(target)
    return test.scheme in ("http", "https") and ref.netloc == test.netloc

def inside_root(path):
    return os.path.realpath(path).startswith("/srv/files/")
"""


class GuardTests(unittest.TestCase):
    """Checks in conditions (``if is_safe_url(x):``) make values safe on that path."""

    def rules(self, code):
        return [f.rule_id for f in TaintAnalyzer("g.py").analyze(GUARD_HELPERS + code)]

    # --- checks that are recognized
    def test_guard_in_condition_protects_the_branch(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        return redirect(n)
"""), [])

    def test_guard_on_a_repeated_source_expression(self):
        # CTFd: the source call is repeated in the test and in the sink.
        self.assertEqual(self.rules("""
def view():
    if request.args.get("next") and is_safe_url(request.args.get("next")):
        return redirect(request.args.get("next"))
"""), [])

    def test_failed_check_replaced_by_a_safe_value(self):
        # pgAdmin: ``if bad or not is_safe(x): x = default``.
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if n is None or not is_safe_url(n):
        n = "/"
    return redirect(n)
"""), [])

    def test_early_exit_with_abort(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if not is_safe_url(n):
        abort(400)
    return redirect(n)
"""), [])

    def test_early_exit_with_raise_and_allow_list(self):
        self.assertEqual(self.rules("""
def view():
    p = request.args.get("plugin")
    if p not in ("a", "b"):
        raise ValueError(p)
    return open(p).read()
"""), [])

    def test_membership_in_an_untainted_list(self):
        self.assertEqual(self.rules("""
def view():
    p = request.args.get("plugin")
    if p in os.listdir("plugins"):
        return open(os.path.join("plugins", p)).read()
"""), [])

    def test_guard_function_that_returns_a_checked_value(self):
        # Redash ``get_next_path``: every return is constant or checked.
        self.assertEqual(self.rules("""
def next_path(value):
    if not value:
        return ""
    if is_safe_url(value):
        return value
    return "/"

def view():
    return redirect(next_path(request.args.get("next")))
"""), [])

    def test_guard_that_delegates_to_another_guard(self):
        self.assertEqual(self.rules("""
def check(target):
    if not target:
        return False
    return is_safe_url(target)

def view():
    n = request.args.get("next")
    if check(n):
        return redirect(n)
"""), [])

    def test_path_guard(self):
        self.assertEqual(self.rules("""
def view():
    p = request.args.get("file")
    if inside_root(p):
        return open(p).read()
"""), [])

    def test_library_guard(self):
        self.assertEqual(TaintAnalyzer("g.py").analyze("""
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
def view(request):
    n = request.GET.get("next")
    if url_has_allowed_host_and_scheme(n, allowed_hosts={"example.com"}):
        return redirect(n)
"""), [])

    # --- checks that must not be trusted
    def test_check_that_always_returns_true_is_not_a_guard(self):
        self.assertEqual(self.rules("""
def is_safe_redirect(target):
    return True

def view():
    n = request.args.get("next")
    if is_safe_redirect(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_check_that_does_not_inspect_the_url_is_not_a_guard(self):
        self.assertEqual(self.rules("""
def is_safe_redirect(target):
    return bool(target)

def view():
    n = request.args.get("next")
    if is_safe_redirect(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_redirect_guard_does_not_protect_a_command(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        subprocess.run(n, shell=True)
"""), ["CS-CMD-001"])

    def test_path_guard_does_not_protect_a_redirect(self):
        self.assertEqual(self.rules("""
def view():
    p = request.args.get("next")
    if inside_root(p):
        return redirect(p)
"""), ["CS-REDIRECT-001"])

    def test_value_after_the_branch_is_not_checked(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        pass
    return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_else_branch_of_a_check_is_not_safe(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        pass
    else:
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_reassignment_inside_the_branch_is_not_safe(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        n = request.args.get("other")
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_membership_in_a_tainted_list_is_not_a_check(self):
        self.assertEqual(self.rules("""
def view():
    p = request.args.get("file")
    if p in request.args.getlist("allowed"):
        return open(p).read()
"""), ["CS-PATH-001"])

    def test_or_does_not_prove_either_side(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if n == "internal" or is_safe_url(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_raise_inside_try_still_reaches_the_handler(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    try:
        if not is_safe_url(n):
            raise ValueError()
    except ValueError:
        return redirect(n)
"""), ["CS-REDIRECT-001"])


    # --- early returns
    def test_early_return(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if not is_safe_url(n):
        return redirect("/")
    return redirect(n)
"""), [])

    def test_early_return_inside_a_nested_condition(self):
        self.assertEqual(self.rules("""
def view(strict):
    n = request.args.get("next")
    if strict:
        if not is_safe_url(n):
            return redirect("/")
    return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_return_in_only_one_branch_of_an_inner_if_does_not_exit(self):
        self.assertEqual(self.rules("""
def view(flag):
    n = request.args.get("next")
    if not is_safe_url(n):
        if flag:
            return redirect("/")
    return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_both_inner_branches_exit(self):
        self.assertEqual(self.rules("""
def view(flag):
    n = request.args.get("next")
    if not is_safe_url(n):
        if flag:
            return redirect("/")
        else:
            abort(400)
    return redirect(n)
"""), [])

    # --- merging and nesting
    def test_checked_in_both_branches_stays_checked_after_the_merge(self):
        self.assertEqual(self.rules("""
def view(flag):
    n = request.args.get("next")
    if flag:
        if not is_safe_url(n):
            n = "/"
    else:
        if not is_safe_url(n):
            n = "/home"
    return redirect(n)
"""), [])

    def test_checked_in_one_branch_only_is_not_checked_after_the_merge(self):
        self.assertEqual(self.rules("""
def view(flag):
    n = request.args.get("next")
    if flag:
        if not is_safe_url(n):
            n = "/"
    return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_nested_check_inside_a_check(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    p = request.args.get("file")
    if is_safe_url(n):
        if inside_root(p):
            redirect(n)
            open(p)
        open(p)
"""), ["CS-PATH-001"])

    def test_elif_chain(self):
        self.assertEqual(self.rules("""
def view(mode):
    n = request.args.get("next")
    if mode == 1:
        return redirect(n)
    elif is_safe_url(n):
        return redirect(n)
    else:
        return redirect(n)
"""), ["CS-REDIRECT-001", "CS-REDIRECT-001"])

    def test_check_inside_a_loop(self):
        # FlaskBB: return the first candidate that passes the check.
        self.assertEqual(self.rules("""
def first_safe(*targets):
    for t in targets:
        if t and is_safe_url(t):
            return t
    return "/"

def view():
    return redirect(first_safe(request.args.get("next"), request.referrer))
"""), [])

    def test_unchecked_loop_value_is_still_reported(self):
        self.assertEqual(self.rules("""
def first(*targets):
    for t in targets:
        if t:
            return t
    return "/"

def view():
    return redirect(first(request.args.get("next")))
"""), ["CS-REDIRECT-001"])

    # --- one branch must not affect another
    def test_check_does_not_leak_into_the_else_branch(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        return redirect(n)
    else:
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_check_of_one_variable_does_not_cover_another(self):
        self.assertEqual(self.rules("""
def view():
    a = request.args.get("a")
    b = request.args.get("b")
    if is_safe_url(a):
        return redirect(b)
"""), ["CS-REDIRECT-001"])

    def test_check_of_one_source_call_does_not_cover_another(self):
        self.assertEqual(self.rules("""
def view():
    if is_safe_url(request.args.get("a")):
        return redirect(request.args.get("b"))
"""), ["CS-REDIRECT-001"])

    def test_check_inside_a_called_function_does_not_cover_the_caller(self):
        self.assertEqual(self.rules("""
def log_if_safe(x):
    if is_safe_url(x):
        print(x)

def view():
    n = request.args.get("next")
    log_if_safe(n)
    return redirect(n)
"""), ["CS-REDIRECT-001"])

    # --- incomplete and context-specific checks
    def test_scheme_only_check_is_not_a_redirect_guard(self):
        self.assertEqual(self.rules("""
def is_https(target):
    return urlparse(target).scheme == "https"

def view():
    n = request.args.get("next")
    if is_https(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_normalizing_a_path_without_comparing_it_is_not_a_guard(self):
        self.assertEqual(self.rules("""
def looks_ok(path):
    return os.path.realpath(path) != ""

def view():
    p = request.args.get("file")
    if looks_ok(p):
        return open(p).read()
"""), ["CS-PATH-001"])

    def test_prefix_check_without_normalizing_is_not_a_guard(self):
        # ``/srv/files/../../etc/passwd`` starts with the root.
        self.assertEqual(self.rules("""
def under_root(path):
    return path.startswith("/srv/files/")

def view():
    p = request.args.get("file")
    if under_root(p):
        return open(p).read()
"""), ["CS-PATH-001"])

    def test_a_check_that_ignores_its_argument_is_not_a_guard(self):
        self.assertEqual(self.rules("""
def is_safe_redirect(target):
    return urlparse("http://example.com/").netloc == "example.com"

def view():
    n = request.args.get("next")
    if is_safe_redirect(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_check_result_stored_in_a_variable_is_not_followed(self):
        # A known limitation: the analysis reads the condition itself.
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    ok = is_safe_url(n)
    if ok:
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_redirect_guard_does_not_protect_sql(self):
        self.assertEqual(self.rules("""
def view():
    n = request.args.get("next")
    if is_safe_url(n):
        cursor.execute("SELECT * FROM t WHERE u='" + n + "'")
"""), ["CS-SQL-001"])

    def test_ssrf_guard_by_address_check(self):
        self.assertEqual(self.rules("""
import ipaddress, socket, requests
def public_host(url):
    host = urlparse(url).hostname
    return not ipaddress.ip_address(socket.gethostbyname(host)).is_private

def view():
    u = request.args.get("url")
    if public_host(u):
        requests.get(u)
    requests.get(u)
"""), ["CS-SSRF-001"])


    # --- character-class regular expressions
    def test_fullmatch_with_a_safe_character_class(self):
        # changedetection.io: the name becomes a file name.
        self.assertEqual(self.rules("""
import re
def view():
    name = request.args.get("processor")
    if re.fullmatch(r"[A-Za-z0-9_-]+", name):
        return open(os.path.join("/data", name + ".json")).read()
"""), [])

    def test_regex_allowing_dots_or_slashes_is_not_a_guard(self):
        self.assertEqual(self.rules("""
import re
def view():
    name = request.args.get("file")
    if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        open(name)
    if re.fullmatch(r"[^/]+", name):
        open(name)
"""), ["CS-PATH-001", "CS-PATH-001"])

    def test_unanchored_match_is_not_a_guard(self):
        # ``re.match`` only checks the start: ``abc/../../etc/passwd`` matches.
        self.assertEqual(self.rules("""
import re
def view():
    name = request.args.get("file")
    if re.match(r"[a-z]+", name):
        open(name)
    if re.match(r"[a-z]+$", name):
        open(name)
"""), ["CS-PATH-001"])

    def test_range_across_character_kinds_is_not_a_guard(self):
        # ``[0-z]`` and ``[A-z]`` also match ``; < > \\ [ ] ^`` and the backtick.
        self.assertEqual(self.rules("""
import re
def view():
    host = request.args.get("host")
    if re.fullmatch(r"[0-z]+", host):
        os.system("ping " + host)
    if re.fullmatch(r"[A-z]+", host):
        os.system("ping " + host)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_narrow_ranges_are_still_a_guard(self):
        self.assertEqual(self.rules("""
import re
def view():
    h = request.args.get("id")
    if re.fullmatch(r"[a-f0-9]+", h):
        os.system("show " + h)
"""), [])

    def test_regex_with_flags_is_not_a_guard(self):
        # With ``re.M`` the ``$`` also matches before a newline: ``abc\\nid`` passes.
        self.assertEqual(self.rules("""
import re
def view():
    host = request.args.get("host")
    if re.match(r"[a-z]+$", host, re.M):
        os.system("ping " + host)
    if re.fullmatch(r"[a-z]+", host, flags=re.I):
        os.system("ping " + host)
"""), ["CS-CMD-001", "CS-CMD-001"])

    def test_check_that_reads_the_host_without_comparing_it_is_not_a_guard(self):
        # ``urlparse(u).netloc`` is truthy exactly for absolute, external URLs.
        self.assertEqual(self.rules("""
def get_host(url):
    return urlparse(url).netloc

def view():
    n = request.args.get("next")
    if get_host(n):
        return redirect(n)
"""), ["CS-REDIRECT-001"])

    def test_host_compared_through_a_variable_is_a_guard(self):
        self.assertEqual(self.rules("""
def same_host(url):
    host = urlparse(url).netloc
    return not host or host == "example.com"

def view():
    n = request.args.get("next")
    if same_host(n):
        return redirect(n)
"""), [])

    def test_rejecting_any_host_is_a_guard(self):
        # Redash ``_is_safe_next_url``: a URL with a host is refused.
        self.assertEqual(self.rules("""
def is_local(url):
    parsed = urlparse(url)
    if parsed.netloc:
        return False
    return True

def view():
    n = request.args.get("next")
    if is_local(n):
        return redirect(n)
"""), [])

    def test_resolving_a_host_without_checking_the_address_is_not_a_guard(self):
        self.assertEqual(self.rules("""
import socket, requests
def resolves(url):
    return socket.gethostbyname(urlparse(url).hostname)

def view():
    u = request.args.get("url")
    if resolves(u):
        requests.get(u)
"""), ["CS-SSRF-001"])

class GuardAcrossModulesAndConfigTests(unittest.TestCase):
    # The file helpers of CrossModuleTests, without inheriting its tests.
    setUp = CrossModuleTests.setUp
    tearDown = CrossModuleTests.tearDown
    write = CrossModuleTests.write
    run_project = CrossModuleTests.run_project
    relative = CrossModuleTests.relative

    def test_guard_defined_in_another_module(self):
        self.write("security.py", (
            "from urllib.parse import urlparse\n"
            "def is_safe(target):\n"
            "    return urlparse(target).netloc in ('', 'example.com')\n"))
        self.write("views.py", (
            "from flask import request, redirect\n"
            "from security import is_safe\n"
            "def view():\n"
            "    n = request.args.get('next')\n"
            "    if is_safe(n):\n"
            "        return redirect(n)\n"
            "    return redirect(n)\n"))
        _, found = self.run_project()
        self.assertEqual(found, [("views.py", 7, "CS-REDIRECT-001")])

    def test_configured_guard_and_sanitizer(self):
        import codesentinel
        saved_guards = {k: set(v) for k, v in codesentinel.GUARDS.items()}
        saved_sanitizers = {k: set(v) for k, v in codesentinel.SANITIZERS.items()}
        try:
            codesentinel.register_config({
                "guards": {"policy.allowed": ["path"]},
                "sanitizers": {"policy.clean_url": ["redirect"]}})
            findings = TaintAnalyzer("c.py").analyze(
                "from flask import request, redirect\n"
                "import policy\n"
                "p = request.args['p']\n"
                "if policy.allowed(p):\n"
                "    open(p)\n"
                "redirect(policy.clean_url(request.args['n']))\n"
                "open(p)\n")
            self.assertEqual([(f.line, f.rule_id) for f in findings], [(7, "CS-PATH-001")])
            with self.assertRaises(ValueError):
                codesentinel.register_config({"guards": {"x.y": ["nosuchcontext"]}})
        finally:
            codesentinel.GUARDS.clear()
            codesentinel.GUARDS.update(saved_guards)
            for k, v in saved_sanitizers.items():
                codesentinel.SANITIZERS[k] = v



class FrameworkSourceTests(unittest.TestCase):
    """Class-based views, Flask-RESTful, aiohttp, Tornado and http.server."""

    def rules(self, code):
        return [f.rule_id for f in TaintAnalyzer("fw.py").analyze(code)]

    def test_flask_methodview_route_parameter(self):
        self.assertEqual(self.rules("""
import os
from flask.views import MethodView
class Files(MethodView):
    def get(self, name):
        return open(os.path.join("/data", name)).read()
    def helper(self, name):
        return open(name).read()
"""), ["CS-PATH-001"])

    def test_flask_restful_resource_and_subclass(self):
        self.assertEqual(self.rules("""
import os
from flask_restful import Resource
class Base(Resource):
    pass
class Run(Base):
    def post(self, host):
        os.system("ping " + host)
"""), ["CS-CMD-001"])

    def test_flask_restful_reqparse(self):
        self.assertEqual(self.rules("""
import os
from flask_restful import Resource, reqparse
parser = reqparse.RequestParser()
parser.add_argument("host")
class Run(Resource):
    def post(self):
        args = parser.parse_args()
        os.system("ping " + args["host"])
"""), ["CS-CMD-001"])

    def test_argparse_parse_args_is_not_a_web_source(self):
        self.assertEqual(self.rules("""
import argparse, os
parser = argparse.ArgumentParser()
args = parser.parse_args()
os.system("ping " + args.host)
"""), [])

    def test_django_class_view_request_object_is_not_data(self):
        self.assertEqual(self.rules("""
from django.views import View
from django.shortcuts import redirect
class Profile(View):
    def get(self, request, pk):
        redirect(request.user.get_absolute_url())
        redirect(request.GET["next"])
"""), ["CS-REDIRECT-001"])

    def test_plain_class_get_method_is_not_a_view(self):
        self.assertEqual(self.rules("""
import os
class Cache:
    def get(self, key):
        return open(key).read()
"""), [])

    def test_aiohttp_sources(self):
        self.assertEqual(self.rules("""
import os, subprocess
from aiohttp import web
async def handler(request):
    name = request.match_info["name"]
    open(os.path.join("/data", name))
    data = await request.post()
    subprocess.run("echo " + data["x"], shell=True)
    q = request.query.get("q")
    cursor.execute("SELECT * FROM t WHERE q='" + q + "'")
"""), ["CS-PATH-001", "CS-CMD-001", "CS-SQL-001"])

    def test_tornado_handler_sources(self):
        self.assertEqual(self.rules("""
import os
import tornado.web
class Ping(tornado.web.RequestHandler):
    def get(self):
        os.system("ping " + self.get_argument("host"))
        open(self.request.body)
"""), ["CS-CMD-001", "CS-PATH-001"])

    def test_get_argument_outside_a_tornado_handler_is_not_a_source(self):
        self.assertEqual(self.rules("""
import os
class Settings:
    def load(self):
        os.system("ping " + self.get_argument("host"))
"""), [])

    def test_http_server_handler_sources(self):
        self.assertEqual(self.rules("""
import os
from http.server import BaseHTTPRequestHandler
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        open(self.path.lstrip("/")).read()
        os.system("echo " + self.rfile.read(10).decode())
"""), ["CS-PATH-001", "CS-CMD-001"])

    def test_self_path_outside_a_request_handler_is_not_a_source(self):
        self.assertEqual(self.rules("""
class Config:
    def read(self):
        return open(self.path).read()
"""), [])


    # --- records loaded by a route parameter are stored data
    def test_record_loaded_by_route_id_is_not_user_data(self):
        # FlaskBB: ``forum = db.session.get(Forum, forum_id)``, then redirect(forum.external)
        self.assertEqual(self.rules("""
from flask import redirect
from flask.views import MethodView
class ViewForum(MethodView):
    def get(self, forum_id):
        forum = db.session.get(Forum, forum_id)
        topic = Topic.query.filter_by(forum_id=forum_id).first_or_404()
        post = Post.objects.get(pk=forum_id)
        redirect(forum.external)
        redirect(topic.url)
        redirect(post.link)
        redirect(forum_id)
"""), ["CS-REDIRECT-001"])

    def test_raw_sql_before_a_result_method_is_still_reported(self):
        self.assertEqual(self.rules("""
from flask import request
from sqlalchemy import text
def view():
    return db.session.execute(text("SELECT * FROM u WHERE n = '" + request.args["n"] + "'")).first()
"""), ["CS-SQL-001"])

    def test_session_get_with_one_argument_is_not_an_orm_read(self):
        # ``requests.Session().get(url)`` and friends are not record lookups.
        self.assertEqual(self.rules("""
import requests
from flask import request, redirect
def view():
    s = requests.session()
    r = s.get(request.args["u"])
    redirect(r.text)
"""), ["CS-REDIRECT-001"])


    def test_mapping_lookup_by_route_id_is_stored_data(self):
        # changedetection.io: ``watch = self.datastore.data["watching"].get(uuid)``
        self.assertEqual(self.rules("""
from flask_restful import Resource
from flask import redirect
class Watch(Resource):
    def get(self, uuid):
        watch = self.datastore.data["watching"].get(uuid)
        redirect(watch["url"])
        redirect(self.datastore.data["watching"].get(uuid, uuid))
"""), ["CS-REDIRECT-001"])



class TraceTests(unittest.TestCase):
    """Each finding records how the data reached the sink."""

    def steps(self, finding):
        return [(t["kind"], t["line"], t["name"]) for t in finding.trace]

    def test_trace_within_a_module(self):
        [finding] = TaintAnalyzer("t.py").analyze("""
import os
from flask import request
def run(cmd):
    os.system(cmd)
def view():
    host = request.args["host"]
    run("ping " + host)
view()
""")
        self.assertEqual(self.steps(finding), [
            ("source", 7, "request.args"), ("call", 9, "view"), ("call", 8, "run"),
            ("sink", 5, "os.system")])

    def test_trace_across_modules(self):
        import tempfile, pathlib
        from codesentinel import Project, collect_python_files
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "views.py").write_text(
                "from flask import request\nimport helpers\n"
                "def save():\n    data = request.form\n    helpers.fetch(data['url'])\n")
            (root / "helpers.py").write_text(
                "import requests\ndef fetch(url):\n    return requests.get(url)\n")
            [finding] = Project(collect_python_files([root])).run()
            self.assertEqual([(t["kind"], pathlib.Path(t["file"]).name, t["line"]) for t in finding.trace],
                             [("source", "views.py", 4), ("call", "views.py", 5), ("sink", "helpers.py", 3)])

    def test_route_parameter_source_names_the_handler(self):
        [finding] = TaintAnalyzer("t.py").analyze("""
import os
@app.route("/ping/<host>")
def ping(host):
    os.system("ping " + host)
""")
        self.assertEqual(finding.trace[0]["kind"], "source")
        self.assertIn("host of ping", finding.trace[0]["name"])
        self.assertEqual(finding.trace[-1]["kind"], "sink")

    def test_sarif_code_flow(self):
        from codesentinel import to_sarif
        [finding] = TaintAnalyzer("t.py").analyze(
            "import os\nfrom flask import request\nos.system(request.args['c'])\n")
        result = to_sarif([finding])["runs"][0]["results"][0]
        locations = result["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual([loc["location"]["message"]["text"] for loc in locations],
                         ["source: request.args", "sink: os.system"])

    def test_trace_does_not_change_finding_equality(self):
        a = TaintAnalyzer("t.py").analyze("import os\nos.system(input())\n")
        b = TaintAnalyzer("t.py").analyze("import os\nos.system(input())\n")
        self.assertEqual(a, b)



class EncodingTests(unittest.TestCase):
    def test_file_with_a_latin1_declaration_is_scanned(self):
        import tempfile, pathlib
        from codesentinel import Project
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "legacy.py"
            path.write_bytes(b'# -*- coding: latin-1 -*-\nimport os\nname = "caf\xe9"\n'
                             b'os.system("echo " + input())\n')
            project = Project([path])
            self.assertEqual([f.rule_id for f in project.run()], ["CS-CMD-001"])
            self.assertEqual(project.errors, {})


if __name__ == "__main__":
    unittest.main()


class ReviewRegressionTests(unittest.TestCase):
    def rules(self, code):
        return [f.rule_id for f in TaintAnalyzer("sample.py").analyze(code)]

    def test_callee_early_exit_does_not_leak_into_caller_try(self):
        code = (
            "import os\nfrom flask import request\n"
            "def helper(v):\n    cmd = request.args.get('c')\n    if v:\n        return 1\n    return 2\n"
            "def view():\n    cmd = 'ls'\n    try:\n        helper(1)\n    except Exception:\n        pass\n"
            "    os.system(cmd)\n"
        )
        self.assertEqual(self.rules(code), [])

    def test_host_present_check_is_not_a_redirect_guard(self):
        code = (
            "from flask import request, redirect\nfrom urllib.parse import urlparse\n"
            "def is_safe(u):\n    return urlparse(u).netloc != ''\n"
            "def view():\n    n = request.args.get('next')\n    if is_safe(n):\n        return redirect(n)\n"
        )
        self.assertEqual(self.rules(code), ["CS-REDIRECT-001"])

    def test_host_absent_check_is_still_a_redirect_guard(self):
        code = (
            "from flask import request, redirect\nfrom urllib.parse import urlparse\n"
            "def is_safe(u):\n    return urlparse(u).netloc == ''\n"
            "def view():\n    n = request.args.get('next')\n    if is_safe(n):\n        return redirect(n)\n"
        )
        self.assertEqual(self.rules(code), [])
