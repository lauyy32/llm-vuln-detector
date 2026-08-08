"""Smoke test for the CWE-022 taint config in queries/taint.ql.

Flask request args are modelled as a ``RemoteFlowSource`` by CodeQL, so the
untrusted ``filename`` must flow into ``open(...)`` (a ``FileSystemAccess``
sink) and the query should report a CWE-022 path. This is the *positive*
control: it proves the per-CWE config fires when the source is
framework-modelled, whereas a custom-context source (e.g. thumbor's
``load(context, path)``) is invisible to static taint — the gap the LLM
context enhancement is meant to close.
"""
from flask import Flask, request
import os

app = Flask(__name__)
BASE_DIR = "/var/data/uploads"


@app.route("/download")
def download():
    filename = request.args.get("file")  # RemoteFlowSource
    path = os.path.join(BASE_DIR, filename)  # tainted path
    with open(path, "rb") as fh:  # FileSystemAccess sink (CWE-022)
        return fh.read()
