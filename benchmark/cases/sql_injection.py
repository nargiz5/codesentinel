"""SQL injection (CWE-89) cases."""
import shlex
import sqlite3

from flask import Flask, request
from sqlalchemy import text

app = Flask(__name__)
conn = sqlite3.connect("app.db")


def concat_input():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + input() + "'")  # expect: vuln CWE-89


@app.route("/user")
def user_fstring():
    name = request.args["name"]
    return str(conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall())  # expect: vuln CWE-89


@app.route("/user2")
def user_percent():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return str(conn.execute(query).fetchall())  # expect: vuln CWE-89


@app.route("/user3")
def user_parameterized():
    return str(conn.execute("SELECT * FROM users WHERE name = ?", (request.args["name"],)).fetchall())  # expect: safe CWE-89


@app.route("/item")
def item_numeric():
    item_id = int(request.args["id"])
    return str(conn.execute(f"SELECT * FROM items WHERE id = {item_id}").fetchall())  # expect: safe CWE-89


def constant_query():
    conn.execute("SELECT COUNT(*) FROM users")  # expect: safe CWE-89


def build_query(name):
    return "SELECT * FROM users WHERE name = '" + name + "'"


def interprocedural_return():
    conn.execute(build_query(input()))  # expect: vuln CWE-89


def sqlalchemy_text(session):
    session.execute(text("SELECT * FROM users WHERE name = '" + input() + "'"))  # expect: vuln CWE-89


def branch(flag):
    base = "SELECT * FROM users"
    if flag:
        query = base + " WHERE name = '" + input() + "'"
    else:
        query = base
    conn.execute(query)  # expect: vuln CWE-89


def wrong_sanitizer():
    conn.execute("SELECT * FROM users WHERE name = " + shlex.quote(input()))  # expect: vuln CWE-89


@app.route("/sorted")
def column_whitelist():
    column = {"name": "name", "age": "age"}.get(request.args["sort"], "name")
    return str(conn.execute("SELECT * FROM users ORDER BY " + column).fetchall())  # expect: safe CWE-89
