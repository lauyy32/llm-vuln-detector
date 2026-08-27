"""消融 harness（SPEC §7 / ARCHITECTURE §4）。

遍历样本，对每样本展开 vuln(正例)/fixed(负例) 两版本，构造 request/code/both 三模式
DetectionContext，跑 StructuralHeuristicScorer + CodeQLBaselineScorer + ConfigSigScorer + CPGEvidenceScorer，收集
``(sample_id, version, mode, scorer, predicted, truth)``，聚合并落
``results.csv`` + ``summary.md``。

数据来源
--------
* 默认（真实）：``cpg/dataset.jsonl``，所有样本源码聚合到**一个** CodeQL 数据库
  （``corpus_db``），建库一次 + 6 次 taint 查询 + 1 次官方 analyze；按样本路径前缀
  区分实例，避免跨样本串味。
* ``--demo``：复用已建好的 ``sample_db`` 与 ``output_demo/taint.csv``，对 ``cpg/samples``
  4 个 demo 文件跑同样的聚合逻辑，验证链路（不重建 DB）。

指标（SPEC §7）
--------------
正类 = vulnerable；predicted=abstain 计为「未判 vulnerable」→ 对正例召回 0。
分组报告：可污点类（CPG taint 覆盖 022/089/078/094/918/079）vs 逻辑类。

用法
----
    python3 cpg/ablation/run_ablation.py --limit 3          # 真实前 3 条
    python3 cpg/ablation/run_ablation.py --demo             # 复用 sample_db 验证聚合
    python3 cpg/ablation/run_ablation.py --demo --skip-baseline
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import sys
from pathlib import Path

# 仓库根引导：脚本直跑时 sys.path[0]=cpg/ablation，须先把仓库根加入才能 `import cpg.ablation.*`
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cpg.ablation.config import (  # noqa: E402
    ABLATION_DIR, CPG_DIR, DATASET_JSONL, DEMO_DB, DEMO_TAINT_CSV, SAMPLES_DIR,
    TAINT_COVERED_CWES, WORK_DIR, normalize_cwe,
)
from cpg.ablation.context_build import build_context  # noqa: E402
from cpg.ablation.cpg_eval import build_cpg_slices_text, extract_taint  # noqa: E402
from cpg.ablation.corpus_db import build_corpus_db, CORPUS_SRC  # noqa: E402
from cpg.ablation.codeql_baseline import run_codeql_baseline_corpus  # noqa: E402
from cpg.ablation.scorers import (  # noqa: E402
    CodeQLBaselineScorer, ConfigSigScorer, CPGEvidenceScorer, DetectionContext, LocalLLMScorer,
    StructuralHeuristicScorer, Verdict,
)

POSITIVE = "vulnerable"
MODES = ("request", "code", "both")
SCORERS = ("StructuralHeuristicScorer", "CodeQLBaselineScorer", "ConfigSigScorer", "CPGEvidenceScorer")

# demo 文件名 -> 目标 CWE（与 output_demo/taint.csv 中的 file 列一致）
DEMO_FNAME_CWE = {
    "flask_path_traversal.py": "CWE-022",
    "flask_ssrf.py": "CWE-918",
    "flask_xss.py": "CWE-079",
    "cve_sqli_demo.py": "CWE-089",
}


# ---------------------------------------------------------------------------
# 样本加载
# ---------------------------------------------------------------------------
def _read_taint_csv_for_file(csv_path: Path, basename: str) -> list[dict]:
    if not csv_path.exists():
        return []
    out: list[dict] = []
    with csv_path.open(newline="", encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if (r.get("file") or "").strip() == basename:
                out.append(r)
    return out


def _taint_row_in_prefix(row: dict, prefix: str) -> bool:
    """语料库级单数据库下，按样本路径前缀（如 ``CVE-2026-50558_vuln``）隔离 taint 行。

    ``abs_path`` 为真实源码在 ``corpus_src/<cve>_<version>/`` 下的绝对路径；前缀段
    直接挂在 ``corpus_src`` 之下，故以 ``/<prefix>/`` 子串匹配即可避免同名文件串味。
    """
    if not prefix:
        return False
    p = (row.get("abs_path") or "").replace("\\", "/")
    if not p:
        return False
    return f"/{prefix}/" in p


def _load_sample_code(prefix: str, taint_rows: list[dict], max_chars: int = 6000) -> str:
    """从 ``corpus_src/<prefix>/`` 读取真实源码节选，作为 code_text 注入 LLM 上下文。

    语料库模式下样本源码落在 ``corpus_src/<cve>_<version>/``；此前 harness 把真实样本
    的 ``code_text`` 置空串，导致 LLM 在真实 CVE 上看不到任何源码，仅靠 taint 占位文本
    与公告摘要盲判。此函数按「taint 锚点优先 + 窗口截断」选取对判定最有价值的节选：

    * taint 命中的文件：把每个 source/sink 行号展开为锚点区间（sink±60 / source±40），
      合并重叠区间后**按命中行数降序**输出——保证 sink 附近（含安全包装、守卫等判定
      关键上下文）优先进入文本，而非简单取大窗口开头（大窗口会因 6000 字符截断
      丢掉 sink 之后的安全 wrapper 定义，导致 LLM 误判）；
    * 其余 ``.py`` 文件：取头部前 100 行（通常含入口 / import / 配置上下文）；
    * 总量受 ``max_chars`` 约束（与 LocalLLMScorer 的 ``code_text[:6000]`` 对齐），
      文件/区间间以 ``# ===== FILE: <basename> (L<lo>-L<hi>) =====`` 分隔标注。

    切片文本的行号经 ``cpg_eval._read_src_lines`` 按 abs_path 独立读取，不受节选影响。
    """
    root = CORPUS_SRC / prefix
    if not root.is_dir():
        return ""
    hit_paths: dict[str, list[tuple[int, int]]] = {}
    root_str = str(root).replace("\\", "/") + "/"
    for r in taint_rows:
        ap = (r.get("abs_path") or "").replace("\\", "/")
        if ap.startswith(root_str):
            try:
                a = int(r.get("sourceLine") or 0)
                b = int(r.get("sinkLine") or 0)
            except (TypeError, ValueError):
                a = b = 0
            hit_paths.setdefault(ap, []).append((a, b))
    py_files = sorted(
        (p for p in root.rglob("*.py") if p.is_file()),
        key=lambda p: (p.resolve().as_posix() not in hit_paths, p.stat().st_size),
    )
    # 候选块：(优先级, 起始行, 结束行, 文件, 行列表)。命中文件块 prio=0 且按命中
    # 行数降序，非命中文件块 prio=1。
    blocks: list[tuple[int, int, int, Path, list[str]]] = []
    for p in py_files:
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        if not lines:
            continue
        ap = p.resolve().as_posix()
        ab = [x for x in hit_paths.get(ap, []) if x[0] and x[1]]
        if ab:
            spans: list[tuple[int, int]] = []
            for a, b in ab:
                spans.append((max(1, b - 60), min(len(lines), b + 60)))
                spans.append((max(1, a - 30), min(len(lines), a + 60)))
            spans.sort()
            merged: list[list[int]] = []
            for lo, hi in spans:
                if merged and lo <= merged[-1][1] + 20:
                    merged[-1][1] = max(merged[-1][1], hi)
                else:
                    merged.append([lo, hi])
            # 命中行数（区间内 source/sink 锚点计数）降序 → 判定关键上下文优先
            scored = []
            for lo, hi in merged:
                n_hit = sum(1 for (a, b) in ab
                            if (lo <= a <= hi) or (lo <= b <= hi))
                scored.append((n_hit, lo, hi))
            scored.sort(key=lambda x: (-x[0], x[1]))
            for n_hit, lo, hi in scored:
                blocks.append((0, lo, hi, p, lines))
        else:
            blocks.append((1, 1, min(100, len(lines)), p, lines))
    # 稳定排序（key 仅 prio）：命中文件块（prio=0）整体优先于非命中文件（prio=1）；
    # 同文件多块保持构造时的命中数降序（不能用起始行二次排序，会把 sink 密集区间
    # 挤到 6000 字符截断之外，导致安全包装定义丢失）。
    blocks.sort(key=lambda b: b[0])
    parts: list[str] = []
    used = 0
    for _prio, lo, hi, p, lines in blocks:
        text = f"# ===== FILE: {p.name} (L{lo}-L{hi}) =====\n" + "\n".join(lines[lo - 1:hi])
        if used + len(text) > max_chars:
            remain = max_chars - used
            if remain > 200:
                parts.append(text[:remain] + "\n# (truncated)")
            break
        parts.append(text)
        used += len(text) + 1
    return "\n".join(parts)


def load_demo_samples() -> list[dict]:
    samples: list[dict] = []
    for f in sorted(SAMPLES_DIR.glob("*.py")):
        cwe = DEMO_FNAME_CWE.get(f.name)
        if cwe is None:
            continue
        samples.append({
            "sample_id": f.stem,
            "cwes": [cwe],
            "cwe": cwe,
            "summary": f"demo sample {f.name}",
            "code_text": f.read_text(encoding="utf-8"),
            "version": "vuln",
            "truth": "vulnerable",
            "source_file": f,
            "reuse_db": DEMO_DB,
            "reuse_taint_csv": DEMO_TAINT_CSV,
        })
    return samples


def _load_dataset_rows(limit: int | None) -> list[dict]:
    """读取 dataset.jsonl 原始行（供语料库级单数据库构建）。"""
    rows: list[dict] = []
    with DATASET_JSONL.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if limit is not None:
        rows = rows[:limit]
    return rows


def load_dataset_samples(limit: int | None) -> list[dict]:
    rows: list[dict] = []
    with DATASET_JSONL.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    if limit is not None:
        rows = rows[:limit]

    samples: list[dict] = []
    for row in rows:
        cwes = row.get("cwes") or ([row["cwe"]] if row.get("cwe") else [])
        cwe = normalize_cwe(cwes[0]) if cwes else None
        cve_id = row.get("cve_id")
        files = row.get("files") or []
        vuln_path = fixed_path = None
        for fp in files:
            if "\\vuln\\" in fp or "/vuln/" in fp:
                vuln_path = CPG_DIR / fp
            elif "\\fixed\\" in fp or "/fixed/" in fp:
                fixed_path = CPG_DIR / fp
        # 兼容文档约定形状 vuln_code/fixed_code（直接内联代码）
        for version, path, truth in (
            ("vuln", vuln_path, "vulnerable"),
            ("fixed", fixed_path, "benign"),
        ):
            code = None
            if path and Path(path).exists():
                code = Path(path).read_text(encoding="utf-8")
            elif version == "vuln" and row.get("vuln_code"):
                code = row["vuln_code"]
            elif version == "fixed" and row.get("fixed_code"):
                code = row["fixed_code"]
            if code is None:
                continue
            samples.append({
                "sample_id": cve_id,
                "cwes": [cwe] if cwe else [],
                "cwe": cwe,
                "summary": row.get("summary"),
                "code_text": code,
                "version": version,
                "truth": truth,
                "source_file": path,
                "reuse_db": None,
                "reuse_taint_csv": None,
            })
    return samples


# ---------------------------------------------------------------------------
# 指标
# ---------------------------------------------------------------------------
def compute_metrics(records: list[tuple]) -> dict:
    """records: list of (predicted, truth)。返回 P/R/F1/support/混淆矩阵。"""
    tp = fp = tn = fn = 0
    conf = {lbl: {"vulnerable": 0, "benign": 0, "abstain": 0, "error": 0}
            for lbl in ("vulnerable", "benign", "abstain", "error")}
    for pred, truth in records:
        if pred not in conf:
            pred = "error"
        if truth not in conf["vulnerable"]:
            continue
        conf[pred][truth] += 1
        if truth == POSITIVE and pred == POSITIVE:
            tp += 1
        elif truth != POSITIVE and pred == POSITIVE:
            fp += 1
        elif truth != POSITIVE and pred != POSITIVE:
            tn += 1
        elif truth == POSITIVE and pred != POSITIVE:
            fn += 1
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * p * r / (p + r)) if (p + r) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": p, "recall": r, "f1": f1,
        "support": tp + fp + tn + fn, "confusion": conf,
    }


def md_table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(c) for c in r) + " |")
    return "\n".join(out)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limit", type=int, default=None, help="只跑前 N 条 dataset 样本（仅真实模式）")
    ap.add_argument("--exclude-cves", type=str, default="",
                    help="逗号分隔的 CVE 列表，从真实模式中剔除（如跨语言修复样本，Python 侧不可判定）")
    ap.add_argument("--no-taint", action="store_true",
                    help="禁用 CPG taint 注入（cpg_slices=None、taint_rows=[]），隔离「源码」与「CPG 证据」的增益")
    ap.add_argument("--no-code", action="store_true",
                    help="禁用源码注入（code_text 置空，仅保留摘要 + taint），隔离「源码」增益")
    ap.add_argument("--demo", action="store_true", help="复用 sample_db + taint.csv 跑 cpg/samples（验证聚合）")
    ap.add_argument("--skip-baseline", action="store_true", help="跳过 CodeQL 基线（仅跑结构化启发式，提速）")
    ap.add_argument("--with-local-llm", action="store_true",
                    help="纳入 LocalLLMScorer（需本机 Ollama + 模型已拉取；不可达时自动 abstain）")
    ap.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
    args = ap.parse_args()

    corpus: dict | None = None
    if args.demo:
        samples = load_demo_samples()
    else:
        # 真实模式：语料库级单数据库（建库一次 + 6 次 taint 查询 + 1 次 analyze）
        rows = _load_dataset_rows(args.limit)
        if args.exclude_cves:
            excluded = {c.strip() for c in args.exclude_cves.split(",") if c.strip()}
            kept = [r for r in rows if (r.get("cve_id") or "") not in excluded]
            print(f"[info] --exclude-cves: 剔除 {len(rows) - len(kept)} 条（{sorted(excluded)}），保留 {len(kept)} 条")
            rows = kept
        try:
            _db, _staged, _taint, _sarif = build_corpus_db(rows, skip_baseline=args.skip_baseline)
        except RuntimeError as exc:
            print(f"[fatal] corpus database build failed: {exc}")
            return 1
        corpus = {"db": _db, "staged": _staged, "taint": _taint, "sarif": _sarif}
        samples = [
            {
                "sample_id": st["cve"],
                "cwes": [st["cwe"]] if st["cwe"] else [],
                "cwe": st["cwe"],
                "summary": st.get("summary"),
                "version": st["version"],
                "truth": st["truth"],
                "prefix": st["prefix"],
                # 真实源码已落在 corpus_src；此处置空字符串仅用于触发 cpg_slices 构建，
                # 评分由注入的 taint_rows 决定，不依赖源码文本。
                "code_text": "",
            }
            for st in _staged
        ]
    if not samples:
        print("[warn] no samples loaded; check dataset / demo files")
        return 1

    # 本地 LLM 评分器（可选）：仅当 --with-local-llm 且本机 Ollama 实际可达时纳入；
    # 否则不计入，避免一列全 abstain 干扰指标。
    local_llm = LocalLLMScorer(timeout=600)
    local_llm_enabled = bool(args.with_local_llm) and local_llm.reachable()
    if args.with_local_llm and not local_llm_enabled:
        print("[warn] --with-local-llm set but Ollama unreachable; LocalLLMScorer disabled")
    active_scorers = list(SCORERS) + (["LocalLLMScorer"] if local_llm_enabled else [])

    # 基线可用性：demo 逐样本走 CodeQLBaselineScorer（自带 db）；真实模式依赖 corpus SARIF，
    # 缺失（analyze 失败）时整轮跳过基线评分，避免崩溃。
    baseline_available = not args.skip_baseline and (
        args.demo or bool(corpus and corpus.get("sarif"))
    )
    if not baseline_available and not args.skip_baseline:
        print("[warn] CodeQL baseline unavailable (corpus SARIF missing); "
              "skipping CodeQLBaselineScorer for this run")

    print(f"[info] loaded {len(samples)} sample-version(s); demo={args.demo}; "
          f"skip_baseline={args.skip_baseline}")

    records: list[tuple] = []  # (sample_id, version, mode, scorer, predicted, truth, cwe_pred, cwe_truth, group)
    baseline_cache: dict[tuple, object] = {}
    errors: list[str] = []

    for s in samples:
        cwe = s["cwe"]
        group = "taint" if cwe in TAINT_COVERED_CWES else "logic"
        sid = s["sample_id"]

        if s.get("reuse_db"):
            # demo：复用 sample_db + output_demo/taint.csv
            db_path = Path(s["reuse_db"])
            sample_file = Path(s["source_file"])
            taint_rows = _read_taint_csv_for_file(Path(s["reuse_taint_csv"]), sample_file.name)
            wd = None
            baseline_key = (str(db_path), str(sample_file), cwe)
        else:
            # 真实：语料库级单数据库，按样本前缀过滤 taint 行；baseline 按前缀过滤 SARIF
            prefix = s.get("prefix")
            taint_rows = [r for r in corpus["taint"] if _taint_row_in_prefix(r, prefix)]
            # B-0.5：注入真实源码节选（此前 code_text 恒为空串，LLM 在真实样本上看不到源码；
            # 三模式共享同一 code_text，只构造一次）。--no-code 时保持空串，隔离源码增益。
            if not s.get("code_text") and not args.no_code:
                s["code_text"] = _load_sample_code(prefix, taint_rows)
            wd = None
            db_path = corpus["db"]
            sample_file = None
            baseline_key = (str(db_path), prefix, cwe)

        # 三模式
        for mode in MODES:
            # --no-taint：隔离 CPG 增益。taint_rows 置空 + cpg_slices 显式 None，
            # 使 LLM / 确定性 scorer 均不消费 CPG 污点证据（仅源码 + 摘要）。
            effective_taint = [] if args.no_taint else taint_rows
            ctx_kwargs = {"workdir": wd, "taint_rows": effective_taint}
            if args.no_taint:
                ctx_kwargs["cpg_slices"] = None
            ctx = build_context(mode, s, **ctx_kwargs)
            # 结构化启发式（吃注入的 taint_rows；request 模式 cpg_slices=None → 显式 abstain）
            v_sh = StructuralHeuristicScorer(taint_rows=effective_taint).score(ctx)
            records.append((sid, s["version"], mode, "StructuralHeuristicScorer",
                            v_sh.label, s["truth"], v_sh.cwe, cwe, group))
            # CodeQL 官方基线：demo 逐样本跑 analyze；真实按前缀过滤已建好的 corpus SARIF；
            # 不可用（skip_baseline 或缺 SARIF）时跳过，不崩溃。
            if not baseline_available:
                continue
            if baseline_key not in baseline_cache:
                if s.get("reuse_db"):
                    bl = CodeQLBaselineScorer(db_path=db_path, sample_file=sample_file)
                    baseline_cache[baseline_key] = bl.score(ctx)
                else:
                    baseline_cache[baseline_key] = run_codeql_baseline_corpus(
                        corpus["sarif"], prefix, cwe)
            v_bl = baseline_cache[baseline_key]
            records.append((sid, s["version"], mode, "CodeQLBaselineScorer",
                            v_bl.label, s["truth"], v_bl.cwe, cwe, group))
            # 结构型/配置签名基线（ConfigSig）：吃真实源码目录（真实）或 code_text（demo），
            # 按目标 CWE 匹配不安全配置签名；request 模式 / 基于缺失的 CWE 显式 abstain。
            cfg_src = CORPUS_SRC / s["prefix"] if (not s.get("reuse_db") and s.get("prefix")) else None
            v_cfg = ConfigSigScorer(source_root=cfg_src).score(ctx)
            records.append((sid, s["version"], mode, "ConfigSigScorer",
                            v_cfg.label, s["truth"], v_cfg.cwe, cwe, group))
            # CPG 证据评分器：直接解析 cpg_slices 切片文本做确定性判定，
            # 与 StructuralHeuristic（吃注入 taint_rows）互补，为 LocalLLMScorer 提供对照基线。
            v_cpg = CPGEvidenceScorer().score(ctx)
            records.append((sid, s["version"], mode, "CPGEvidenceScorer",
                            v_cpg.label, s["truth"], v_cpg.cwe, cwe, group))
            # 本地 LLM（可选；Ollama 不可达时自动 abstain）
            if local_llm_enabled:
                v_llm = local_llm.score(ctx)
                records.append((sid, s["version"], mode, "LocalLLMScorer",
                                v_llm.label, s["truth"], v_llm.cwe, cwe, group))

    _write_results(args.out_dir / "results.csv", records)
    summary = _build_summary(records, errors, args, len(samples), active_scorers)
    (args.out_dir / "summary.md").write_text(summary, encoding="utf-8")
    print("\n=== ablation summary ===")
    print(summary)
    print(f"\n[ok] wrote {args.out_dir / 'results.csv'} and {args.out_dir / 'summary.md'}")
    return 0


def _error_verdict(cwe):
    from cpg.ablation.scorers import Verdict
    return Verdict(label="error", confidence=0.0, cwe=cwe,
                   evidence=[{"reason": "extract_taint failed; DB not built"}])


def _write_results(path: Path, records: list[tuple]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    headers = ["sample_id", "version", "mode", "scorer", "predicted", "truth",
               "cwe_predicted", "cwe_truth", "group"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(headers)
        for r in records:
            w.writerow(r)


def _build_summary(records: list[tuple], errors: list[str], args, n_samples: int,
                    scorers: list[str] | None = None) -> str:
    # 活跃 scorer 列表：传入 active_scorers 优先；否则默认随 skip_baseline 决定。
    # skip_baseline 时剔除 CodeQLBaselineScorer（无对应记录）。
    base = scorers if scorers is not None else SCORERS
    sc_list = base if not args.skip_baseline else [s for s in base if s != "CodeQLBaselineScorer"]
    # 过滤 error 行用于指标，但保留计数
    def rec_filter(scorer=None, mode=None, group=None, truth_in=None):
        out = []
        for sid, ver, m, sc, pred, truth, cp, ct, g in records:
            if scorer and sc != scorer:
                continue
            if mode and m != mode:
                continue
            if group and g != group:
                continue
            if truth_in and truth not in truth_in:
                continue
            out.append((pred, truth))
        return out

    lines = []
    lines.append("# 三模式上下文消融实验 - 结果汇总")
    lines.append("")
    lines.append(f"- 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"- 数据来源: {'demo (cpg/samples + sample_db)' if args.demo else 'dataset.jsonl (真实 CVE)'}")
    lines.append(f"- 样本版本数: {n_samples}  (vuln=正例 / fixed=负例)")
    lines.append(f"- 跳过基线: {args.skip_baseline}")
    lines.append(f"- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）")
    lines.append(f"- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）")
    lines.append(f"- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）")
    if args.demo:
        lines.append("")
        lines.append("> 注：demo 模式仅含 4 个 vuln 正例（无 fixed 负例），用于验证聚合链路；"
                     "真实 dataset.jsonl 全量已通过语料库级单数据库（建库一次 + 6 次 taint 查询 + 1 次 analyze）完成。")
    if errors:
        lines.append("")
        lines.append(f"## 建库/抽取失败（{len(errors)}）")
        for e in errors:
            lines.append(f"- {e}")
    lines.append("")

    # 全局（scorer, mode）
    lines.append("## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）")
    lines.append("")
    headers = ["scorer", "mode", "P", "R", "F1", "support", "TP", "FP", "TN", "FN"]
    rows = []
    for sc in sc_list:
        for m in MODES:
            recs = rec_filter(scorer=sc, mode=m)
            met = compute_metrics(recs)
            rows.append([sc, m, f"{met['precision']:.3f}", f"{met['recall']:.3f}",
                         f"{met['f1']:.3f}", met["support"], met["tp"], met["fp"],
                         met["tn"], met["fn"]])
    lines.append(md_table(headers, rows))
    lines.append("")

    # 分组（taint / logic）
    lines.append("## 分组指标（可污点类 vs 逻辑类）")
    lines.append("")
    headers = ["group", "scorer", "mode", "P", "R", "F1", "support"]
    rows = []
    for g in ("taint", "logic"):
        for sc in sc_list:
            for m in MODES:
                recs = rec_filter(scorer=sc, mode=m, group=g)
                if not recs:
                    continue
                met = compute_metrics(recs)
                rows.append([g, sc, m, f"{met['precision']:.3f}", f"{met['recall']:.3f}",
                             f"{met['f1']:.3f}", met["support"]])
    lines.append(md_table(headers, rows))
    lines.append("")

    # 每 CWE（核心消融单元：结构化启发式 + 配置签名基线 + CPG 证据）
    lines.append("## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）")
    lines.append("")
    cwes_seen = sorted({ct for *_x, ct, _g in records})
    headers = ["cwe", "scorer", "mode", "P", "R", "F1", "support"]
    rows = []
    for sc in ("StructuralHeuristicScorer", "ConfigSigScorer", "CPGEvidenceScorer"):
        for cw in cwes_seen:
            for m in MODES:
                sub = [(p, t) for (sid, ver, mm, scc, p, t, cp, ct, g) in records
                       if scc == sc and mm == m and ct == cw]
                if not sub:
                    continue
                met = compute_metrics(sub)
                rows.append([cw, sc, m, f"{met['precision']:.3f}", f"{met['recall']:.3f}",
                             f"{met['f1']:.3f}", met["support"]])
    lines.append(md_table(headers, rows))
    lines.append("")

    # 混淆矩阵（全局，两个 scorer）
    lines.append("## 混淆矩阵（全局，行=预测 / 列=真值）")
    lines.append("")
    for sc in sc_list:
        recs = rec_filter(scorer=sc)
        met = compute_metrics(recs)
        lines.append(f"### {sc}")
        conf = met["confusion"]
        headers = ["predicted \\ truth", "vulnerable", "benign", "abstain", "error"]
        rows = []
        for pred_lbl in ("vulnerable", "benign", "abstain", "error"):
            rows.append([pred_lbl, conf[pred_lbl]["vulnerable"], conf[pred_lbl]["benign"],
                         conf[pred_lbl]["abstain"], conf[pred_lbl]["error"]])
        lines.append(md_table(headers, rows))
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
