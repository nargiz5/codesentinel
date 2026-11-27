"""Code injection (CWE-95) cases."""
import ast
import builtins

from flask import Flask, request

app = Flask(__name__)


def eval_input():
    return eval(input())  # expect: vuln CWE-95


@app.route("/run", methods=["POST"])
def exec_form():
    exec(request.form["code"])  # expect: vuln CWE-95
    return "ok"


@app.route("/calc")
def builtins_eval():
    return str(builtins.eval(request.args["expr"]))  # expect: vuln CWE-95


def eval_constant():
    return eval("2 + 2")  # expect: safe CWE-95


def literal_eval():
    return ast.literal_eval(input())  # expect: safe CWE-95


def calc(expression):
    return eval(expression)  # expect: vuln CWE-95


def interprocedural():
    return calc(input())


def lambda_argument():
    return list(map(lambda s: eval(s), [input()]))  # expect: vuln CWE-95
