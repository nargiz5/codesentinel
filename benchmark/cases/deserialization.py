"""Insecure deserialization (CWE-502) cases."""
import base64
import json
import marshal
import pickle

import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/load", methods=["POST"])
def pickle_body():
    return str(pickle.loads(request.data))  # expect: vuln CWE-502


@app.route("/config", methods=["POST"])
def yaml_safe_loader():
    return str(yaml.load(request.data, Loader=yaml.SafeLoader))  # expect: safe CWE-502


def yaml_safe_load():
    return yaml.safe_load(input())  # expect: safe CWE-502


@app.route("/config2", methods=["POST"])
def yaml_unsafe_loader():
    return str(yaml.load(request.get_data(), Loader=yaml.Loader))  # expect: vuln CWE-502


def local_model():
    with open("model.pkl", "rb") as handle:
        return pickle.load(handle)  # expect: safe CWE-502


@app.route("/json", methods=["POST"])
def json_body():
    return str(json.loads(request.data))  # expect: safe CWE-502


@app.route("/code")
def marshal_param():
    return str(marshal.loads(base64.b64decode(request.args["payload"])))  # expect: vuln CWE-502
