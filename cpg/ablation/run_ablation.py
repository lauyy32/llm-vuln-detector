"""消融 harness（SPEC §7 / ARCHITECTURE §4）。

遍历样本，对每样本展开 vuln(正例)/fixed(负例) 两版本，构造 request/code/both 三模式
DetectionContext，跑 StructuralHeuristicScorer + CodeQLBaselineScorer，收集
``(sample_id, version, mode, scorer, predicted, truth)``，聚合并落
``results.csv`` + ``summary.md``。

数据来源
--------
* 默认（真实）：``cpg/dataset.jsonl``，每行展开 vuln/fixed 两样本；逐样本建 DB +
  跑 taint + 复用该 DB 跑 baseline（慢，受 Defender/超时影响）。
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
from cpg.ablation.cpg_eval import extract_taint  # noqa: E402
from cpg.ablation.scorers import (  # noqa: E402
    CodeQLBaselineScorer, DetectionContext, StructuralHeuristicScorer,
)

POSITIVE = "vulnerable"
MODES = ("request", "code", "both")
SCORERS = ("StructuralHeuristicScorer", "CodeQLBaselineScorer")

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
    ap.add_argument("--demo", action="store_true", help="复用 sample_db + taint.csv 跑 cpg/samples（验证聚合）")
    ap.add_argument("--skip-baseline", action="store_true", help="跳过 CodeQL 基线（仅跑结构化启发式，提速）")
    ap.add_argument("--out-dir", type=Path, default=ABLATION_DIR)
    args = ap.parse_args()

    samples = load_demo_samples() if args.demo else load_dataset_samples(args.limit)
    if not samples:
        print("[warn] no samples loaded; check dataset / demo files")
        return 1

    print(f"[info] loaded {len(samples)} sample-version(s); demo={args.demo}; "
          f"skip_baseline={args.skip_baseline}")

    records: list[tuple] = []  # (sample_id, version, mode, scorer, predicted, truth, cwe_pred, cwe_truth, group)
    baseline_cache: dict[tuple, object] = {}
    errors: list[str] = []

    for s in samples:
        cwe = s["cwe"]
        group = "taint" if cwe in TAINT_COVERED_CWES else "logic"
        sid = s["sample_id"]

        # 准备该样本的 taint 证据与 DB（demo 复用，真实建库）
        if s.get("reuse_db"):
            db_path = Path(s["reuse_db"])
            sample_file = Path(s["source_file"])
            taint_rows = _read_taint_csv_for_file(Path(s["reuse_taint_csv"]), sample_file.name)
            wd = None
        else:
            wd = WORK_DIR / "samples" / f"{sid}_{s['version']}"
            try:
                taint_rows = extract_taint(s["code_text"], cwe, wd)
            except RuntimeError as exc:
                errors.append(f"{sid}/{s['version']}: extract_taint failed: {exc}")
                # 建库失败：code/both 无法分析，记 error；request 仍 abstain
                for mode in MODES:
                    ctx = DetectionContext(request_info=None,
                                            advisory_meta={"cve_id": sid, "cwe": cwe, "summary": s["summary"]},
                                            code_text=None, cpg_slices=None)
                    sh = StructuralHeuristicScorer()
                    v_sh = sh.score(ctx) if mode == "request" else _error_verdict(cwe)
                    records.append((sid, s["version"], mode, "StructuralHeuristicScorer",
                                    v_sh.label, s["truth"], v_sh.cwe, cwe, group))
                    if not args.skip_baseline:
                        records.append((sid, s["version"], mode, "CodeQLBaselineScorer",
                                        "error", s["truth"], None, cwe, group))
                continue
            db_path = wd / "db"
            sample_file = wd / "src" / "sample.py"

        # 三模式
        for mode in MODES:
            ctx = build_context(mode, s, workdir=wd, taint_rows=taint_rows)
            # 结构化启发式
            v_sh = StructuralHeuristicScorer(taint_rows=taint_rows).score(ctx)
            records.append((sid, s["version"], mode, "StructuralHeuristicScorer",
                            v_sh.label, s["truth"], v_sh.cwe, cwe, group))
            # CodeQL 基线（按 db/sample/cwe 记忆化，三模式共用）
            if args.skip_baseline:
                continue
            key = (str(db_path), str(sample_file), cwe)
            if key not in baseline_cache:
                bl = CodeQLBaselineScorer(db_path=db_path, sample_file=sample_file)
                baseline_cache[key] = bl.score(ctx)
            v_bl = baseline_cache[key]
            records.append((sid, s["version"], mode, "CodeQLBaselineScorer",
                            v_bl.label, s["truth"], v_bl.cwe, cwe, group))

    _write_results(args.out_dir / "results.csv", records)
    summary = _build_summary(records, errors, args, len(samples))
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


def _build_summary(records: list[tuple], errors: list[str], args, n_samples: int) -> str:
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
    lines.append(f"- CodeQL: 2.26.2  python-code-scanning 套件")
    if args.demo:
        lines.append("")
        lines.append("> 注：demo 模式仅含 4 个 vuln 正例（无 fixed 负例），用于验证聚合链路；"
                     "真实 dataset.jsonl 全量需逐样本建 DB，已用 demo 验证聚合逻辑。")
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
    for sc in SCORERS if not args.skip_baseline else SCORERS[:1]:
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
        for sc in SCORERS if not args.skip_baseline else SCORERS[:1]:
            for m in MODES:
                recs = rec_filter(scorer=sc, mode=m, group=g)
                if not recs:
                    continue
                met = compute_metrics(recs)
                rows.append([g, sc, m, f"{met['precision']:.3f}", f"{met['recall']:.3f}",
                             f"{met['f1']:.3f}", met["support"]])
    lines.append(md_table(headers, rows))
    lines.append("")

    # 每 CWE（仅 StructuralHeuristic，核心消融单元）
    lines.append("## 每 CWE 指标（StructuralHeuristicScorer）")
    lines.append("")
    cwes_seen = sorted({ct for *_x, ct, _g in records})
    headers = ["cwe", "mode", "P", "R", "F1", "support"]
    rows = []
    for cw in cwes_seen:
        for m in MODES:
            sub = [(p, t) for (sid, ver, mm, sc, p, t, cp, ct, g) in records
                   if sc == "StructuralHeuristicScorer" and mm == m and ct == cw]
            if not sub:
                continue
            met = compute_metrics(sub)
            rows.append([cw, m, f"{met['precision']:.3f}", f"{met['recall']:.3f}",
                         f"{met['f1']:.3f}", met["support"]])
    lines.append(md_table(headers, rows))
    lines.append("")

    # 混淆矩阵（全局，两个 scorer）
    lines.append("## 混淆矩阵（全局，行=预测 / 列=真值）")
    lines.append("")
    for sc in SCORERS if not args.skip_baseline else SCORERS[:1]:
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
