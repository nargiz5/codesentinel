"""Path traversal (CWE-22) cases."""
import os
import sys
from pathlib import Path

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
BASE = "/srv/files"


@app.route("/read")
def read_concat():
    with open(BASE + "/" + request.args["name"]) as handle:  # expect: vuln CWE-22
        return handle.read()


@app.route("/read2")
def read_secure_filename():
    with open(os.path.join(BASE, secure_filename(request.args["name"]))) as handle:  # expect: safe CWE-22
        return handle.read()


@app.route("/read3")
def read_basename():
    name = os.path.basename(request.args["name"])
    with open(os.path.join(BASE, name)) as handle:  # expect: safe CWE-22
        return handle.read()


@app.route("/read4")
def read_pathlib():
    return Path(BASE, request.args["name"]).read_text()  # expect: vuln CWE-22


@app.route("/download")
def download():
    return send_file(request.args["file"])  # expect: vuln CWE-22


def cli_tool():
    with open(sys.argv[1]) as handle:  # expect: safe CWE-22
        return handle.read()


def constant_path():
    with open("settings.ini") as handle:  # expect: safe CWE-22
        return handle.read()


# Added after the first release: a documented known gap
# (docs/DETAILS.md#known-gaps-and-next-steps).

def is_inside_base(path):
    real = os.path.realpath(os.path.join(BASE, path))
    return real.startswith(BASE + os.sep)


@app.route("/read5")
def guard_in_variable():
    name = request.args["name"]
    if is_inside_base(name):
        with open(os.path.join(BASE, name)) as handle:  # expect: safe CWE-22
            return handle.read()
    return "denied"


@app.route("/read6")
def guard_stored_first():
    name = request.args["name"]
    allowed = is_inside_base(name)
    if allowed:
        with open(os.path.join(BASE, name)) as handle:  # expect: safe CWE-22
            return handle.read()
    return "denied"
