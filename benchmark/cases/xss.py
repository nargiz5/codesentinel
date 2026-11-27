"""Cross-site scripting (CWE-79) cases."""
import html

from flask import Flask, make_response, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/hello")
def hello():
    return f"<h1>Hello {request.args['name']}</h1>"  # expect: vuln CWE-79


@app.route("/hello2")
def hello_escaped():
    return "<h1>Hello " + html.escape(request.args["name"]) + "</h1>"  # expect: safe CWE-79


@app.route("/hello3")
def hello_markup():
    return Markup("<b>" + request.args["name"] + "</b>")  # expect: vuln CWE-79


@app.route("/hello4")
def hello_response():
    return make_response("<p>" + request.args.get("msg", "") + "</p>")  # expect: vuln CWE-79


@app.route("/static")
def static_page():
    return "<h1>Welcome</h1>"  # expect: safe CWE-79
