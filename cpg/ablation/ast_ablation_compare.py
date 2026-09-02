"""OPEN #11 消融对比：切片含 AST vs 不含 AST（LocalLLM 7b, code 模式）。

读取两个 run_ablation 产物（无 AST 基线 + 含 AST 实验），抽取 LocalLLMScorer
在 code 模式下的逐版本判定，计算配对平衡语料上的判别指标（paired_metrics），并给出
两条件的逐项对照与「加 AST 后判定翻转」统计。

用法
----
    python ast_ablation_compare.py \
        --baseline seeds/v8_74/results.csv \
        --ast      seeds/v8_74_ast/results.csv \
        --json-out ast_ablation_compare.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

# 脚本直跑时把仓库根加入 sys.path，使其能 `import cpg.ablation.paired_metrics`
_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from cpg.ablation.paired_metrics import confusion, basic_metrics, paired_metrics


def load_llm_flags(path: Path, mode: str) -> tuple[dict, dict]:
    """返回 ({(cve,ver): pred_is_vuln}, {(cve,ver): truth_is_vuln}) for LocalLLMScorer."""
    preds: dict = {}
    truth: dict = {}
    with path.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["mode"] != mode or r["scorer"] != "LocalLLMScorer":
                continue
            key = (r["sample_id"], r["version"])
            preds[key] = r["predicted"] == "vulnerable"
            truth[key] = r["truth"] == "vulnerable"
    return preds, truth


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--baseline", type=Path, required=True)
    ap.add_argument("--ast", type=Path, required=True)
    ap.add_argument("--mode", default="code")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    base_pred, truth = load_llm_flags(args.baseline, args.mode)
    ast_pred, _ = load_llm_flags(args.ast, args.mode)
    cves = sorted({c for c, _ in truth})

    base_pm = paired_metrics(base_pred, cves)
    ast_pm = paired_metrics(ast_pred, cves)

    base_pairs = [(truth[k], base_pred.get(k, False)) for k in truth]
    ast_pairs = [(truth[k], ast_pred.get(k, False)) for k in truth]
    base_m = basic_metrics(confusion(base_pairs))
    ast_m = basic_metrics(confusion(ast_pairs))

    # 逐版本翻转统计
    flip = sum(1 for k in truth if base_pred.get(k) != ast_pred.get(k))
    n_ver = len(truth)
    # 判别类别变化的 CVE
    base_cat = {}
    for cve in cves:
        pv, pf = base_pred.get((cve, "vuln")), base_pred.get((cve, "fixed"))
        base_cat[cve] = (pv, pf)
    changed_cves = []
    for cve in cves:
        pv, pf = ast_pred.get((cve, "vuln")), ast_pred.get((cve, "fixed"))
        if (pv, pf) != base_cat.get(cve):
            changed_cves.append(cve)

    out = {
        "n_cve": len(cves),
        "n_version": n_ver,
        "baseline": {**base_m, "paired": base_pm},
        "with_ast": {**ast_m, "paired": ast_pm},
        "delta_net_discrimination": ast_pm["net_discrimination"] - base_pm["net_discrimination"],
        "version_flip_count": flip,
        "version_flip_rate": flip / n_ver if n_ver else 0.0,
        "discrimination_category_changed_cves": changed_cves,
        "discrimination_category_changed_count": len(changed_cves),
    }

    def fmt_pm(pm):
        return (f"correct={pm['correct']} inverted={pm['inverted']} "
                f"both={pm['both_flagged']} neither={pm['neither_flagged']} "
                f"net={pm['net_discrimination']:+.3f} p={pm['p_value_exact']:.4f}")

    print(f"== AST 消融对比 | {len(cves)} CVE / {n_ver} 版本 | mode={args.mode}")
    print(f"  无 AST   BA={base_m['ba']:.3f} MCC={base_m['mcc']:+.3f} | {fmt_pm(base_pm)}")
    print(f"  含 AST   BA={ast_m['ba']:.3f} MCC={ast_m['mcc']:+.3f} | {fmt_pm(ast_pm)}")
    print(f"  Δ net_discrimination = {out['delta_net_discrimination']:+.3f}")
    print(f"  逐版本翻转: {flip}/{n_ver} ({out['version_flip_rate']:.1%})")
    print(f"  判别类别变化 CVE: {len(changed_cves)} 个 -> {changed_cves}")

    if args.json_out:
        args.json_out.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"\n[written] {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
