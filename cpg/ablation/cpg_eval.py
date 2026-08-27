"""单样本 CPG 抽取：把 pipeline 的 sample 级逻辑泛化到一段代码文本。

``extract_taint(code_text, cwe, out_dir) -> list[dict]``

1. 把 code_text 写到 ``<out_dir>/src/sample.py``。
2. ``codeql database create <out_dir>/db --language=python --source-root <out_dir>/src``
   （幂等：db 已存在则跳过；先建库，供 baseline 复用，即使该 CWE 无 taint 查询）。
3. 若该 CWE 有对应 taint 查询（见 config.CWE_TAINT_QUERIES），跑
   ``cpg/queries/cwe-XXX.ql`` 并解码 bqrs → dict 列表（列
   cwe,file,sourceLine,sourceNode,sinkLine,sinkNode）。

命令与 bqrs 解码逐字复制自 pipeline.py（已验证），不重新实现 CodeQL 调用。
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from . import config

SAMPLE_FILENAME = "sample.py"


def _coerce(rows: list[dict]) -> list[dict]:
    """数值列 best-effort 转 int，其余保持原样（与 scorer / slice 约定一致）。"""
    out: list[dict] = []
    for r in rows:
        clean = {k: (v.strip() if isinstance(v, str) else v) for k, v in r.items()}
        for num_key in ("sourceLine", "sinkLine"):
            raw = clean.get(num_key)
            if raw not in (None, ""):
                try:
                    clean[num_key] = int(raw)
                except (TypeError, ValueError):
                    pass
        out.append(clean)
    return out


def _decode_bqrs_to_rows(bqrs: Path, csv_out: Path, env: dict[str, str]) -> list[dict]:
    rc = config.run(
        [
            str(config.codeql_binary()),
            "bqrs",
            "decode",
            "--format=csv",
            f"--output={config.win_path(csv_out)}",
            config.win_path(bqrs),
        ],
        env,
        60,
    )
    if rc != 0:
        print(f"[FAIL] bqrs decode exited {rc}")
        return []
    if not csv_out.exists():
        return []
    lines = csv_out.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        return []
    return _coerce(list(csv.DictReader(lines)))


def extract_taint(code_text: str, cwe: str | None, out_dir: str | Path) -> list[dict]:
    """为单段代码建 DB（若缺失）并抽取目标 CWE 的 source->sink 流。

    返回结构化 taint 行；该 CWE 无 taint 查询或无建模流时返回空列表。
    DB 始终在 out_dir/db 落盘，供 CodeQLBaselineScorer 复用。
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    src = out_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    sample_py = src / SAMPLE_FILENAME
    sample_py.write_text(code_text, encoding="utf-8")

    # 幂等缓存：已解码行直接复用，避免重复建库 + 跑查询
    cached = out_dir / "taint_rows.json"
    if cached.exists():
        try:
            rows = json.loads(cached.read_text(encoding="utf-8"))
            print(f"[cache] extract_taint reused {len(rows)} rows from {cached}")
            return rows
        except (OSError, json.JSONDecodeError):
            pass

    db = out_dir / "db"
    env = config.make_env(config.DEFAULT_JAVA_HOME)

    # 1) 建库（幂等；DB 存在则跳过）。DB 失败（Defender 锁）直接抛出，交由调用方降级。
    if not db.exists():
        rc = config.run(
            [
                str(config.codeql_binary()),
                "database",
                "create",
                config.win_path(db),
                "--language=python",
                f"--source-root={config.win_path(src)}",
                "--overwrite",
            ],
            env,
            config.DB_CREATE_TIMEOUT,
        )
        if rc != 0:
            hint = ""
            if rc == 124:
                hint = (
                    " (watchdog timeout — likely Windows Defender locking the DB cache. "
                    "Run as Administrator: Add-MpPreference -ExclusionPath 'C:/Users/lenovo/cpg_db')"
                )
            raise RuntimeError(f"codeql database create failed (exit {rc}){hint}")

    # 2) 跑目标 CWE 的 taint 查询（若存在）
    qbase = config.taint_query_basename(cwe)
    if qbase is None:
        # 非可污点类 CWE：无 taint 查询，结构化启发式本就判 benign；DB 仍可用作 baseline
        print(f"[skip] no taint query for {config.normalize_cwe(cwe)}; DB kept at {db} for baseline")
        cached.write_text(json.dumps([], ensure_ascii=False), encoding="utf-8")
        return []

    ql = config.QUERIES_DIR / f"{qbase}.ql"
    if not ql.exists():
        print(f"[skip] query file missing: {ql}")
        return []

    bqrs = out_dir / f"{qbase}.bqrs"
    csv_out = out_dir / f"{qbase}.csv"
    rc = config.run(
        [
            str(config.codeql_binary()),
            "query",
            "run",
            config.win_path(ql),
            f"--database={config.win_path(db)}",
            f"--search-path={config.win_path(config.CODEQL_QUERIES_DIR)}",
            f"--output={config.win_path(bqrs)}",
            "--ram=3000",
            "--threads=8",
        ],
        env,
        config.EXTRACT_TAINT_TIMEOUT,
    )
    if rc != 0:
        print(f"[FAIL] taint query {qbase} exited {rc}; returning empty evidence")
        cached.write_text(json.dumps([], ensure_ascii=False), encoding="utf-8")
        return []

    rows = _decode_bqrs_to_rows(bqrs, csv_out, env)
    cached.write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    print(f"[ok] extract_taint: {len(rows)} taint row(s) for {config.normalize_cwe(cwe)} -> {db}")
    return rows


def _read_src_lines(r: dict, fallback_text: str) -> list[str] | None:
    """按 taint 行的 abs_path 读源码行；无路径或读取失败时回退到 code_text 拆行。

    语料库模式下 code_text 可能是多文件节选拼接，行号只对该 taint 行所属文件有效，
    故优先按 abs_path 直接读文件，避免拼接错位导致切片文本渲染出错误代码行。
    """
    ap = r.get("abs_path")
    if ap:
        try:
            txt = Path(ap).read_text(encoding="utf-8", errors="replace")
            return txt.splitlines()
        except OSError:
            pass
    if fallback_text:
        return fallback_text.splitlines()
    return None


def build_cpg_slices_text(taint_rows: list[dict], code_text: str) -> str:
    """把结构化 taint 行渲染成可读 CPG 切片文本（供 LLM 上下文；非判定依据）。"""
    if not taint_rows:
        return "(no untrusted input reaches a modelled sink)\n"
    out: list[str] = ["# CPG TAINT SLICE", ""]
    for r in taint_rows:
        cwe = r.get("cwe")
        try:
            a = int(r.get("sourceLine") or 0)
            b = int(r.get("sinkLine") or 0)
        except (TypeError, ValueError):
            a = b = 0
        lines = _read_src_lines(r, code_text)
        if lines is None:
            src_line = sink_line = "?"
        else:
            src_line = lines[a - 1].strip() if 1 <= a <= len(lines) else "?"
            sink_line = lines[b - 1].strip() if 1 <= b <= len(lines) else "?"
        out.append(f"### {cwe}")
        out.append(f"UNTRUSTED  L{a}: {src_line}")
        out.append(f"           ==> reaches sink at L{b}: {sink_line}")
        out.append(f"           (flow: {r.get('sourceNode')} -> {r.get('sinkNode')})")
        out.append("")
    return "\n".join(out)
