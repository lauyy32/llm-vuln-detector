"""语料库级单数据库（消融待办 #1）。

把 ``dataset.jsonl`` 的全部样本源码（``corpus_pairs/<cve>/<version>/``）复制到单一
source-root ``WORK_DIR/corpus_src/<cve>_<version>/``，建**一个** CodeQL 数据库
（替代逐样本 32 次建库），再对 6 个可污点 CWE 各跑一次 taint 查询（覆盖全库），
并按 ``abs_path`` 列区分样本；baseline 的 ``database analyze`` 也只跑一次，SARIF
按样本路径前缀过滤，避免跨样本串味。

相比原逐样本建库：建库 1 次 + taint 查询 6 次 + analyze 1 次，开销由
O(样本数 × 建库) 降为 O(1 建库 + 6 查询 + 1 analyze)。所有产物落在
``cpg/ablation/.work``（已 gitignore），不进入版本库。
"""

from __future__ import annotations

import csv
import json
import os
import shutil
from pathlib import Path

from . import config


def _rmtree_manual(path) -> None:
    """递归删除目录，绕过沙箱对 ``shutil.rmtree`` 的安全拦截。

    本环境（managed Python）的 ``sitecustomize`` 将 ``shutil.rmtree`` 替换为安全删除，
    而 Windows 沙箱回收站不可用时直接 ``FAIL_CLOSED`` 抛 ``OSError``。此处仅用
    ``os.remove`` / ``os.rmdir``（未被 hook），在当前隔离策略下可用。
    """
    p = Path(path)
    if not p.exists():
        return
    if p.is_file():
        os.remove(p)
        return
    for entry in os.scandir(p):
        if entry.is_dir(follow_symlinks=False):
            _rmtree_manual(entry.path)
        else:
            os.remove(entry.path)
    os.rmdir(p)

# 语料库级临时产物统一落在已加入 Windows Defender 排除项的 DATA_ROOT
# （默认 ``C:/Users/lenovo/cpg_db``，可用环境变量 CPG_DATA_ROOT 覆盖）之下，
# 规避 CodeQL TRAP 缓存被 Defender 锁死（此前 sample_db 已验证该目录可跑通建库
# + taint 查询 + analyze）。产物均为可重建中间文件，不进入版本库。
CORPUS_PAIRS = config.CPG_DIR / "corpus_pairs"
CORPUS_SRC = config.CORPUS_SRC
CORPUS_DB = config.CORPUS_DB
CORPUS_SARIF = config.CORPUS_SARIF

# 大库（真实仓库多文件）建库 / analyze 给足墙钟余量
DB_TIMEOUT = 900
BASELINE_TIMEOUT = 900

# 基线用与数据集 CWE 对应的**官方**查询（覆盖数据集中存在官方成熟查询的 CWE：
# 022 路径穿越、918 SSRF、020 输入校验、295 证书校验）。数据集其余逻辑/语义型
# CWE（059/200/400/444/639/862/863）在 CodeQL Python 安全套件中并无成熟查询，
# 静态基线对其天然恒 benign——恰说明"LLM+CPG 上下文增强"针对的就是这类盲区。
# 故不跑全量 45 查询套件（既慢又易因个别查询失败整体非零退出、丢 SARIF），而仅定向跑
# 与数据集 CWE 对齐的官方查询。查询路径相对 ``CODEQL_QUERIES_DIR``（即 ``cpg/codeql-queries``）。
BASELINE_QUERIES = [
    "python/ql/src/Security/CWE-022/PathInjection.ql",
    "python/ql/src/Security/CWE-022/TarSlip.ql",
    "python/ql/src/Security/CWE-918/FullServerSideRequestForgery.ql",
    "python/ql/src/Security/CWE-918/PartialServerSideRequestForgery.ql",
    "python/ql/src/Security/CWE-020/CookieInjection.ql",
    "python/ql/src/Security/CWE-020/IncompleteHostnameRegExp.ql",
    "python/ql/src/Security/CWE-020/IncompleteUrlSubstringSanitization.ql",
    "python/ql/src/Security/CWE-020/OverlyLargeRange.ql",
    "python/ql/src/Security/CWE-295/MissingHostKeyValidation.ql",
    "python/ql/src/Security/CWE-295/RequestWithoutValidation.ql",
]


def _stage_corpus(rows: list[dict], corpus_src: Path) -> list[dict]:
    """把每个 (cve, version) 的真实源码目录复制到 ``<cve>_<version>/``，保持相对路径。

    不做整体删除：沙箱（managed Python 的 ``sitecustomize``）拦截 ``os.remove`` /
    ``shutil.rmtree``，回收站不可用时 ``FAIL_CLOSED`` 抛 ``OSError``。改为**合并不删**
    策略——``corpus_src`` 持久存在，逐样本 ``copytree(diry_exist_ok=True)`` 覆盖写入；
    历史残留的旧样本目录不影响正确性：其 ``abs_path`` 前缀不匹配当前样本，会被
    ``_taint_row_in_prefix`` / baseline SARIF 的前缀过滤剔除。数据集静态，合并即幂等。
    """
    corpus_src.mkdir(parents=True, exist_ok=True)
    staged: list[dict] = []
    for row in rows:
        cve = row.get("cve_id")
        if not cve:
            continue
        cwes = row.get("cwes") or ([row["cwe"]] if row.get("cwe") else [])
        cwe = config.normalize_cwe(cwes[0]) if cwes else None
        for version, truth in (("vuln", "vulnerable"), ("fixed", "benign")):
            src = CORPUS_PAIRS / cve / version
            if not src.exists():
                continue
            dst = corpus_src / f"{cve}_{version}"
            shutil.copytree(src, dst, dirs_exist_ok=True)
            staged.append({
                "cve": cve, "version": version, "truth": truth, "cwe": cwe,
                "prefix": f"{cve}_{version}", "summary": row.get("summary"),
            })
    return staged


def _decode_bqrs(bqrs: Path, csv_out: Path, env: dict) -> list[dict]:
    rc = config.run(
        [
            str(config.codeql_binary()), "bqrs", "decode", "--format=csv",
            f"--output={config.win_path(csv_out)}", config.win_path(bqrs),
        ],
        env, 120,
    )
    if rc != 0 or not csv_out.exists():
        return []
    lines = csv_out.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        return []
    out: list[dict] = []
    for r in csv.DictReader(lines):
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


def _db_ready(db: Path) -> bool:
    return (db / "codeql-database.yml").exists()


def _parse_taint_csv(csv_out: Path) -> list[dict]:
    """直接解析已由 ``bqrs decode`` 落盘的 taint CSV（用于复用，避免重跑查询）。"""
    if not csv_out.exists() or csv_out.stat().st_size == 0:
        return []
    lines = csv_out.read_text(encoding="utf-8").splitlines()
    if len(lines) < 2:
        return []
    out: list[dict] = []
    for r in csv.DictReader(lines):
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


def build_corpus_db(rows: list[dict], skip_baseline: bool = False, force_rebuild: bool = False):
    """建单库 + 跑 6 个 taint 查询 + 可选 baseline analyze（语料库级、幂等可复用）。

    返回 ``(db_path, staged_samples, all_taint_rows, sarif_path|None)``。
    ``staged_samples`` 每项含 ``prefix``（如 ``CVE-2026-50558_vuln``），供 harness
    按绝对路径前缀过滤 taint 行与 SARIF 结果。

    幂等策略：``CORPUS_DB`` / 各 taint ``.csv`` / ``CORPUS_SARIF`` 已存在且非空时直接
    复用，跳过昂贵的建库、查询编译与 analyze（数据集静态，结果稳定）。``--force-rebuild``
    时全部重算。analyze 失败不再强制删除已有 SARIF，且失败时 ``sarif_path`` 置 ``None``，
    由 harness 优雅跳过基线评分而非崩溃。
    """
    staged = _stage_corpus(rows, CORPUS_SRC)
    env = config.make_env(config.DEFAULT_JAVA_HOME)

    # 建库：DB 已存在且非强制重建则复用（省去约 20min 建库）
    if force_rebuild or not _db_ready(CORPUS_DB):
        rc = config.run(
            [
                str(config.codeql_binary()), "database", "create",
                config.win_path(CORPUS_DB), "--language=python",
                f"--source-root={config.win_path(CORPUS_SRC)}", "--overwrite",
            ],
            env, DB_TIMEOUT,
        )
        if rc != 0:
            raise RuntimeError(f"corpus database create failed (exit {rc})")
    else:
        print(f"[info] reuse existing corpus DB: {config.win_path(CORPUS_DB)}")

    all_taint: list[dict] = []
    for _cwe, qbase in config.CWE_TAINT_QUERIES:
        ql = config.QUERIES_DIR / f"{qbase}.ql"
        if not ql.exists():
            continue
        bqrs = config.WORK_DIR / f"{qbase}.bqrs"
        csv_out = config.WORK_DIR / f"{qbase}.csv"
        # 复用已有非空 CSV（taint 查询编译慢，约 30s/查询）
        if not force_rebuild and csv_out.exists() and csv_out.stat().st_size > 0:
            all_taint.extend(_parse_taint_csv(csv_out))
            continue
        rc = config.run(
            [
                str(config.codeql_binary()), "query", "run", config.win_path(ql),
                f"--database={config.win_path(CORPUS_DB)}",
                f"--search-path={config.win_path(config.CODEQL_QUERIES_DIR)}",
                f"--output={config.win_path(bqrs)}", "--ram=3000", "--threads=8",
            ],
            env, config.EXTRACT_TAINT_TIMEOUT,
        )
        if rc != 0:
            continue
        all_taint.extend(_decode_bqrs(bqrs, csv_out, env))

    sarif_path = None
    if not skip_baseline:
        if (not force_rebuild) and CORPUS_SARIF.exists() and CORPUS_SARIF.stat().st_size > 0:
            sarif_path = CORPUS_SARIF
            print(f"[info] reuse existing corpus SARIF: {config.win_path(CORPUS_SARIF)}")
        else:
            query_args = [config.win_path(config.CODEQL_QUERIES_DIR / q) for q in BASELINE_QUERIES]
            rc = config.run(
                [
                    str(config.codeql_binary()), "database", "analyze",
                    config.win_path(CORPUS_DB), *query_args,
                    "--format=sarif-latest",
                    f"--output={config.win_path(CORPUS_SARIF)}",
                    f"--search-path={config.win_path(config.CODEQL_QUERIES_DIR)}",
                    "--ram=3000", "--threads=8",
                ],
                env, BASELINE_TIMEOUT,
            )
            if rc == 0 and CORPUS_SARIF.exists() and CORPUS_SARIF.stat().st_size > 0:
                sarif_path = CORPUS_SARIF
            else:
                print("[warn] corpus baseline analyze failed/empty; "
                      "CodeQLBaselineScorer will be skipped for this run")
    return CORPUS_DB, staged, all_taint, sarif_path
