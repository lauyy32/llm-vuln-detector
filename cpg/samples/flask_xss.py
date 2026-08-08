"""Smoke test for the CWE-079 taint config in queries/cwe-079.ql.

Flask request args are modelled as a ``RemoteFlowSource``. Writing the untrusted
value directly into the HTTP response body (``return "..." + name``) reaches the
``ReflectedXss`` sink (``HttpResponse``). This is the *positive* control: it
proves the XSS config fires on framework-modelled sources. A value that reaches
the response through a non-modelled template pipeline would be invisible to
static taint — the gap the LLM context enhancement is meant to close.
"""
from flask import Flask, request

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")  # RemoteFlowSource
    return "Hello, " + name          # HttpResponse sink (CWE-079)
