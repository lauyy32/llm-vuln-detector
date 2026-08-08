"""Smoke test for the CWE-918 taint config in queries/cwe-918.ql.

Flask request args are modelled as a ``RemoteFlowSource`` by CodeQL. When the
*entire* outbound request URL is user-controlled and flows into an HTTP client
(``requests.get``), CodeQL's ``FullServerSideRequestForgeryFlow`` reports a
CWE-918 path (it requires ``fullyControlledRequest`` — every URL part tainted).

This is the *positive* control: it proves the SSRF config fires when the source
is framework-modelled. A custom-context source (e.g. a value pulled from an
internal bus and then requested) is invisible to static taint — the gap the LLM
context enhancement is meant to close.
"""
from flask import Flask, request
import requests

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")  # RemoteFlowSource, fully controls the URL
    resp = requests.get(url)       # Http::Client::Request sink (CWE-918)
    return resp.text
