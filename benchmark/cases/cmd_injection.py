"""Command injection (CWE-78) cases."""
import os
import shlex
import subprocess

from flask import Flask, request

app = Flask(__name__)


def direct_input():
    os.system("ping -c 1 " + input())  # expect: vuln CWE-78


def run_ping(host):
    os.system("ping -c 1 " + host)  # expect: vuln CWE-78


def interprocedural():
    run_ping(input())


def quoted():
    os.system("ping -c 1 " + shlex.quote(input()))  # expect: safe CWE-78


def argv_list():
    host = input()
    subprocess.run(["ping", "-c", "1", host])  # expect: safe CWE-78


def constant_shell():
    subprocess.run("uptime", shell=True)  # expect: safe CWE-78


def explicit_shell():
    subprocess.run(["sh", "-c", "echo " + input()])  # expect: vuln CWE-78


def numeric():
    os.system("kill -9 " + str(int(input())))  # expect: safe CWE-78


def string_without_shell():
    subprocess.run(input())  # expect: vuln CWE-78


def whitelisted_command():
    command = {"disk": "df -h", "mem": "free -m"}.get(input(), "uptime")
    os.system(command)  # expect: safe CWE-78


@app.route("/lookup")
def lookup():
    return subprocess.getoutput("dig " + request.args.get("domain", ""))  # expect: vuln CWE-78


@app.route("/ping/<host>")
def ping_route(host):
    return os.popen("ping -c 1 " + host).read()  # expect: vuln CWE-78


@app.route("/archive", methods=["POST"])
def archive():
    name = request.form["name"]
    subprocess.run(f"tar czf /tmp/{name}.tgz /srv/data", shell=True)  # expect: vuln CWE-78
    return "ok"


class Runner:
    def run(self, command):
        os.system(command)  # expect: vuln CWE-78


def instance_method():
    Runner().run(input())


# Added after the first release from the documented known gaps
# (docs/DETAILS.md#known-gaps-and-next-steps), so the benchmark also
# contains cases the analyzer got wrong. Tuple unpacking has since been fixed.

@app.route("/status")
def tuple_unpacking_safe():
    host, command = request.args["host"], "uptime"
    return os.popen(command).read()  # expect: safe CWE-78


@app.route("/status2")
def tuple_unpacking_vuln():
    host, command = request.args["host"], "uptime"
    return os.popen("ping -c 1 " + host).read()  # expect: vuln CWE-78
