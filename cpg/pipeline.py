"""Drive the CodeQL side of the CPG pipeline: build DB -> run queries -> CSV.

Usage
-----
    python pipeline.py --src samples --function get_user_profile
    python pipeline.py --rebuild            # recreate the DB from scratch
    python pipeline.py --skip-taint         # omit the heavy dataflow query
    python pipeline.py --force              # ignore existing CSVs and re-run

Environment gotchas this script encodes (all discovered the hard way on
Windows, see cpg/README.md):

* ``JAVA_HOME`` must be set explicitly or ``codeql`` exits with code 2 and
  prints nothing at all.
* The CodeQL database must live on a SHORT path outside the repo. Windows
  Defender holds a lock on ``<db>/db-python/default/cache/...`` while a query
  writes its string/tuple pool, and ``query run`` then dies with
  ``ResourceError: Cant write tuple pool file (AccessDeniedException)``.
  - The clean fix is to exclude the DB directory from Defender (admin):
      Add-MpPreference -ExclusionPath "C:/Users/lenovo/cpg_db"
  - Until that is done, a FRESH database (``--rebuild``) usually evaluates
    fine; the *poisoned* cache of a previously-killed run is what blocks.
* ``codeql.exe`` is a native Windows binary, so MSYS-style ``/c/Users/...``
  paths get mangled into ``C:\\c\\Users\\...``. Always hand it ``C:/Users/...``.
* There is no POSIX ``timeout`` on Git Bash here, so the watchdog is done in
  Python via ``subprocess`` + ``taskkill /T`` (Windows) to nuke the whole
  codeql -> java process tree on overrun.

Idempotency: a query whose CSV already exists with a data row is skipped, so a
partial run (e.g. taint blocked by Defender) does not force re-running the
cheap queries, and a later ``--force`` re-runs everything.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_JAVA_HOME = r"C:/Program Files/Java/jdk-21.0.1"
DEFAULT_DB = Path("C:/Users/lenovo/cpg_db/sample_db")
QUERIES = ("ast", "cfg", "dfg", "taint")
# Dataflow query is by far the heaviest; give it more headroom by default.
QUERY_TIMEOUT = {"ast": 120, "cfg": 120, "dfg": 180, "taint": 1200}


def win_path(p: Path) -> str:
    """Render a path the way the native codeql.exe expects it."""
    return str(p.resolve()).startswith("/") and str(p.resolve()) or str(p.resolve()).replace("\\", "/")


def codeql_binary() -> Path:
    exe = HERE / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
    if not exe.exists():
        sys.exit(f"codeql binary not found at {exe}; see cpg/README.md for the bundle download")
    return exe


def make_env(java_home: str) -> dict[str, str]:
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    return env


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        import signal
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass


def run(cmd: list[str], env: dict[str, str], timeout_s: int) -> int:
    """Run a command under a wall-clock watchdog. Returns the exit code.

    On overrun the whole process tree is killed and a non-zero sentinel (124)
    is returned so the caller can mark the step failed and move on.
    """
    print("$", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        # drain anything buffered so we can surface a hint
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        print(f"[timeout] killed after {timeout_s}s: {' '.join(cmd)}", flush=True)
        if out:
            print(out, flush=True)
        if err:
            print(err, file=sys.stderr, flush=True)
        return 124
    if out:
        print(out, flush=True)
    if err:
        print(err, file=sys.stderr, flush=True)
    return proc.returncode


def _csv_has_rows(csv_path: Path) -> bool:
    if not csv_path.exists():
        return False
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    return len(lines) >= 2  # header + at least one data row


def _is_defender_block(stderr: str) -> bool:
    return any(
        sig in stderr
        for sig in (
            "Cant write tuple pool file",
            "AccessDeniedException",
            "ResourceError",
            "Severe disk cache trouble",
        )
    )


# CWE -> query basename. Each reuses CodeQL's *upstream* per-CWE flow module
# (semmle.python.security.dataflow.*), so the taint evidence maps to the real
# CWE instead of the old get->execute heuristic. The injection family
# (022/089/078/094) plus SSRF(918) and reflected XSS(079) are covered by
# upstream *flow* modules. The rest of the dataset's CWEs (authz 862/863,
# smuggling 444, TLS 295, DoS 400, info-exposure 200, IDOR 639, link-following
# 59, input-validation 20) are structural / non-pure-dataflow and need upstream
# Security/CWE-* structural queries or a custom ConfigSig — see OPEN-DECISIONS.md
# (taint CWE coverage).
CWE_TAINT_QUERIES = (
    ("CWE-022", "taint"),     # queries/taint.ql      -> PathInjectionFlow
    ("CWE-089", "cwe-089"),   # SqlInjectionFlow
    ("CWE-078", "cwe-078"),   # CommandInjectionFlow
    ("CWE-094", "cwe-094"),   # CodeInjectionFlow
    ("CWE-918", "cwe-918"),   # FullServerSideRequestForgeryFlow
    ("CWE-079", "cwe-079"),   # ReflectedXssFlow
)


def _run_cwe_taint(
    exe: Path, db: Path, out_dir: Path, env: dict[str, str], ram: int, threads: int, force: bool
) -> str:
    """Run each per-CWE upstream taint query and aggregate rows into taint.csv.

    The aggregated CSV keeps a leading ``cwe`` column so slice_builder can group
    the evidence by weakness class. Idempotent: a present taint.csv is reused
    unless ``--force``.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    search_path = win_path(HERE / "codeql-queries")
    aggregate = out_dir / "taint.csv"
    if (not force) and _csv_has_rows(aggregate):
        print("[cache] taint.csv present, skipping (use --force to re-run)")
        return "cached"
    header: str | None = None
    rows: list[str] = []
    failed = False
    for cwe, qbase in CWE_TAINT_QUERIES:
        ql = HERE / "queries" / f"{qbase}.ql"
        bqrs = out_dir / f"{qbase}.bqrs"
        rc = run(
            [
                str(exe),
                "query",
                "run",
                win_path(ql),
                f"--database={win_path(db)}",
                f"--search-path={search_path}",
                f"--output={win_path(bqrs)}",
                f"--ram={ram}",
                f"--threads={threads}",
            ],
            env,
            QUERY_TIMEOUT["taint"],
        )
        if rc != 0:
            failed = True
            continue
        tmp_csv = out_dir / f"{qbase}.csv"
        rc = run(
            [
                str(exe),
                "bqrs",
                "decode",
                "--format=csv",
                f"--output={win_path(tmp_csv)}",
                win_path(bqrs),
            ],
            env,
            60,
        )
        if rc != 0:
            failed = True
            continue
        lines = tmp_csv.read_text(encoding="utf-8").splitlines()
        if not lines:
            continue
        if header is None:
            header = lines[0]
        rows.extend(lines[1:])
    if header is None:
        header = "cwe,sourceLine,sourceNode,sinkLine,sinkNode"
    if not rows:
        # header-only so slice_builder degrades gracefully (no modelled sink hit)
        aggregate.write_text(header + "\n", encoding="utf-8")
        print("[ok] taint: 0 rows (no untrusted input reaches a modelled sink)")
        return "failed" if failed else "ok"
    aggregate.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    print(f"[ok] taint: {len(rows)} rows -> {aggregate}")
    return "failed" if failed else "ok"


def build_database(exe: Path, src: Path, db: Path, env: dict[str, str], rebuild: bool) -> None:
    if db.exists() and not rebuild:
        print(f"[skip] database already exists at {db} (use --rebuild to recreate)")
        return
    # No manual rmtree: `--overwrite` does it, and the DB deliberately lives outside
    # the workspace (Defender workaround), where recursive deletes are blocked anyway.
    db.parent.mkdir(parents=True, exist_ok=True)
    rc = run(
        [
            str(exe),
            "database",
            "create",
            win_path(db),
            "--language=python",
            f"--source-root={win_path(src)}",
            "--overwrite",
        ],
        env,
        timeout_s=300,
    )
    if rc != 0:
        sys.exit(f"database create failed with exit code {rc}")


def run_queries(
    exe: Path,
    db: Path,
    out_dir: Path,
    env: dict[str, str],
    ram: int,
    threads: int,
    force: bool,
    skip_taint: bool,
) -> dict[str, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    search_path = win_path(HERE / "codeql-queries")
    status: dict[str, str] = {}
    for name in QUERIES:
        if skip_taint and name == "taint":
            print(f"[skip] taint omitted (--skip-taint)")
            status[name] = "skipped"
            continue
        if name == "taint":
            # Aggregate per-CWE upstream taint queries into taint.csv.
            status[name] = _run_cwe_taint(exe, db, out_dir, env, ram, threads, force)
            continue
        csv_out = out_dir / f"{name}.csv"
        if (not force) and _csv_has_rows(csv_out):
            print(f"[cache] {name}.csv present, skipping (use --force to re-run)")
            status[name] = "cached"
            continue
        ql = HERE / "queries" / f"{name}.ql"
        bqrs = out_dir / f"{name}.bqrs"
        rc = run(
            [
                str(exe),
                "query",
                "run",
                win_path(ql),
                f"--database={win_path(db)}",
                f"--search-path={search_path}",
                f"--output={win_path(bqrs)}",
                # Below ~2 GB CodeQL refuses to cache evaluation stages and the
                # dataflow query degrades from seconds to tens of minutes.
                f"--ram={ram}",
                f"--threads={threads}",
            ],
            env,
            timeout_s=QUERY_TIMEOUT[name],
        )
        if rc != 0:
            # Surface the Defender hint exactly once, at the point of failure.
            if rc == 124:
                print(f"[FAIL] {name}: watchdog timeout (possible Defender lock on DB cache)")
            else:
                print(f"[FAIL] {name}: query run exited {rc}")
            status[name] = "failed"
            continue
        # Decode BQRS -> CSV
        rc = run(
            [
                str(exe),
                "bqrs",
                "decode",
                "--format=csv",
                f"--output={win_path(csv_out)}",
                win_path(bqrs),
            ],
            env,
            timeout_s=60,
        )
        if rc != 0:
            print(f"[FAIL] {name}: bqrs decode exited {rc}")
            status[name] = "failed"
            continue
        rows = max(0, len(csv_out.read_text(encoding="utf-8").splitlines()) - 1)
        print(f"[ok] {name}: {rows} rows -> {csv_out}")
        status[name] = "ok"
    return status


def _summarize(status: dict[str, str]) -> None:
    print("\n=== pipeline summary ===")
    for name, st in status.items():
        print(f"  {name:6} {st}")
    if any(st == "failed" for st in status.values()):
        print(
            "\nOne or more queries failed. If the error was "
            "'Cant write tuple pool file' / AccessDeniedException, Windows Defender "
            "is locking the DB cache. Run (as Administrator):\n"
            "    Add-MpPreference -ExclusionPath 'C:/Users/lenovo/cpg_db'\n"
            "then re-run with --force."
        )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", type=Path, default=HERE / "samples", help="source root to analyse")
    ap.add_argument("--db", type=Path, default=DEFAULT_DB, help="CodeQL database path (keep it short)")
    ap.add_argument("--out-dir", type=Path, default=HERE / "output")
    ap.add_argument("--java-home", default=os.environ.get("JAVA_HOME", DEFAULT_JAVA_HOME))
    ap.add_argument("--rebuild", action="store_true", help="delete and recreate the database")
    ap.add_argument("--skip-db", action="store_true", help="reuse the existing database")
    ap.add_argument("--force", action="store_true", help="ignore cached CSVs and re-run all queries")
    ap.add_argument("--skip-taint", action="store_true", help="omit the heavy dataflow query")
    ap.add_argument("--ram", type=int, default=3000, help="query evaluator heap in MB")
    ap.add_argument("--threads", type=int, default=8)
    args = ap.parse_args()

    exe = codeql_binary()
    env = make_env(args.java_home)

    if not args.skip_db:
        build_database(exe, args.src, args.db, env, args.rebuild)
    status = run_queries(
        exe, args.db, args.out_dir, env, args.ram, args.threads, args.force, args.skip_taint
    )
    _summarize(status)

    ok = [n for n, s in status.items() if s in ("ok", "cached")]
    if ok:
        print("\nNext: python slice_builder.py --function <name>")
        print("  (CSV slices present for:", ", ".join(ok), ")")


if __name__ == "__main__":
    main()
