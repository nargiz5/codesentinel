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


if __name__ == "__main__":
    unittest.main()
