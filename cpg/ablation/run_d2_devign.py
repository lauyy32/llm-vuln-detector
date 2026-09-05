"""D2 公开基准外部效度校验：Devign 函数级 vuln/benign 分类（head-to-head）。

复用 LocalLLMScorer（语言无关，只看 code_text），在 Devign（C/C++ 函数级真实标注）
上验证「本地 LLM 打分器在通用公开基准上的判别力」，作为课题核心 claim
（补丁边界判别）的**外部效度 / 合理性对照**。

设计纪律（D2 设计定调块）：
- D2 与「补丁边界判别」是**不同 claim**，不混用；D2 仅回答「LLM 打分器在通用
  函数级 vuln 检测上有无判别力」，不声称 CPG 互补。
- Devign 为函数级**独立样本**（非 vuln/fixed 版本配对）→ McNemar 配对检验不适用，
  退化为独立样本 BA / MCC / F1 + 平凡基线对照。
- 仅跑 LLM 类（LocalLLMScorer；PublishedLLMBaseline 需 API Key，依规递延）。
  C/C++ CPG Scorer 出范围（CodeQL-python 仅覆盖 Python）。
- 为与 D1 统计契约（正类 50% 配对平衡）可比，采样为**平衡样本**（每类 n_per_class），
  使平凡「全判 vulnerable」基线 F1=0.667，暴露 F1 陷阱（与 D1 同一口径）。

用法：
    python cpg/ablation/run_d2_devign.py \
        --data cpg/benchmarks/devign/data/cpg/jsons \
        --out-dir cpg/ablation/seeds/v9_d2_devign \
        --model qwen2.5-coder:7b --n-per-class 250 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cpg.ablation.config import normalize_cwe  # noqa: E402
from cpg.ablation.scorers import DetectionContext, LocalLLMScorer  # noqa: E402

TRUTH_MAP = {1: "vulnerable", 0: "benign"}
COLUMNS = ["sample_id", "version", "mode", "scorer", "predicted", "truth",
           "cwe_predicted", "cwe_truth", "group"]


def load_devign(path: Path, min_func_len: int = 20, max_func_len: int = 6000) -> list[dict]:
    """Devign data/cpg/jsons 为 list[dict]，每项含 func / target / project / idx（+图结构）。

    容错：func 也可名为 code/function；target 也可名为 label。过滤空/超长/非标注项。
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    rows: list[dict] = []
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        func = item.get("func") or item.get("code") or item.get("function")
        if not isinstance(func, str):
            continue
        func = func.strip()
        if not (min_func_len <= len(func) <= max_func_len):
            continue
        tgt = item.get("target")
        if tgt not in (0, 1):
            tgt = item.get("label")
        if tgt not in (0, 1):
            continue
        proj = item.get("project") or "unknown"
        cwe = normalize_cwe(item.get("cwe")) if item.get("cwe") else None
        rows.append({"idx": idx, "func": func, "target": int(tgt),
                     "project": proj, "cwe": cwe})
    return rows


def balanced_sample(rows: list[dict], n_per_class: int, seed: int) -> list[dict]:
    rnd = random.Random(seed)
    vuln = [r for r in rows if r["target"] == 1]
    benign = [r for r in rows if r["target"] == 0]
    rnd.shuffle(vuln)
    rnd.shuffle(benign)
    sel = (vuln[:n_per_class] if len(vuln) >= n_per_class else vuln) + \
          (benign[:n_per_class] if len(benign) >= n_per_class else benign)
    rnd.shuffle(sel)
    return sel


def compute_metrics(res_path: Path, out: Path, model: str) -> dict:
    y_true: list[int] = []
    y_pred: list[int] = []
    abstain = 0
    with open(res_path, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            t = 1 if r["truth"] == "vulnerable" else 0
            p = r["predicted"]
            if p == "abstain":
                abstain += 1
                continue
            y_true.append(t)
            y_pred.append(1 if p == "vulnerable" else 0)
    n = len(y_true)
    tp = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 1)
    tn = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 0)
    fp = sum(1 for a, b in zip(y_true, y_pred) if a == 0 and b == 1)
    fn = sum(1 for a, b in zip(y_true, y_pred) if a == 1 and b == 0)
    sens = tp / (tp + fn) if (tp + fn) else 0.0
    spec = tn / (tn + fp) if (tn + fp) else 0.0
    ba = (sens + spec) / 2.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = sens
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom else 0.0
    total = n + abstain
    # 平衡样本平凡基线：全判 vulnerable → P=0.5,R=1.0,F1=0.667,BA=0.5,MCC=0
    trivial_f1 = 0.667 if total else 0.0
    trivial_ba = 0.5
    trivial_mcc = 0.0
    metrics = {
        "model": model, "n_decided": n, "n_abstain": abstain, "n_total": total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "sensitivity": sens, "specificity": spec, "BA": ba,
        "precision": prec, "recall": rec, "F1": f1, "MCC": mcc,
        "trivial_all_vuln_F1": trivial_f1, "trivial_all_vuln_BA": trivial_ba,
        "trivial_all_vuln_MCC": trivial_mcc,
    }
    # 落盘 summary.md
    cov = n / total if total else 0.0
    md = []
    md.append(f"# D2 Devign 外部效度（LocalLLMScorer {model}）")
    md.append("")
    md.append(f"- 生成时间：{datetime.now(timezone.utc).isoformat()}")
    md.append(f"- 样本：决定集 n={n} / abstain={abstain} / 总={total}（平衡采样，每类 250）")
    md.append(f"- 覆盖率（非 abstain）：{cov:.3f}")
    md.append("")
    md.append("## 独立样本指标（McNemar 不适用）")
    md.append("")
    md.append(f"| 指标 | 值 |")
    md.append(f"| --- | --- |")
    md.append(f"| 灵敏度 Sensitivity | {sens:.3f} |")
    md.append(f"| 特异度 Specificity | {spec:.3f} |")
    md.append(f"| **平衡准确率 BA** | **{ba:.3f}** |")
    md.append(f"| 精确率 Precision | {prec:.3f} |")
    md.append(f"| 召回率 Recall | {rec:.3f} |")
    md.append(f"| **F1** | **{f1:.3f}** |")
    md.append(f"| **MCC** | **{mcc:+.3f}** |")
    md.append("")
    md.append("## 平凡基线对照（暴露 F1 陷阱）")
    md.append("")
    md.append(f"- 平衡样本下「全判 vulnerable」：F1=**{trivial_f1:.3f}**、BA={trivial_ba:.3f}、MCC={trivial_mcc:+.3f}")
    md.append(f"- **判定器 F1={f1:.3f} {'>' if f1>trivial_f1 else '<='} 平凡基线 {trivial_f1:.3f}**"
              f"（与 D1 同一口径：F1 在 50% 正类语料失效）")
    md.append(f"- **判定器 MCC={mcc:+.3f}** 接【随机】(0) → 结论：外部基准上 LLM 打分器判别力"
              f"{'显著优于随机' if abs(mcc) > 0.1 else '接近随机'}。")
    md.append("")
    md.append("## 与课题核心 claim 的关系")
    md.append("")
    md.append("- 本结果仅回答「LLM 打分器在通用函数级 vuln 检测上的独立判别力」，")
    md.append("  与 D1「补丁边界判别」是**不同 claim**，不可混用为「CPG 互补/必要」证据。")
    md.append("- C/C++ CPG Scorer 出范围（CodeQL-python 仅覆盖 Python）；PublishedLLMBaseline 需 API Key，依规递延。")
    (out / "summary.md").write_text("\n".join(md), encoding="utf-8")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="Devign data/cpg/jsons 路径")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--model", default="qwen2.5-coder:7b")
    ap.add_argument("--n-per-class", type=int, default=250)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--limit", type=int, default=0, help="仅跑前 N 条（冒烟测试用）")
    args = ap.parse_args()

    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    raw_log = out / "raw_llm_responses.jsonl"
    scorer = LocalLLMScorer(model=args.model, timeout=args.timeout,
                            raw_log=raw_log, seed=args.seed)
    print(f"[info] LocalLLM reachable: {scorer.reachable()} (model={args.model})")

    rows = load_devign(Path(args.data))
    n_vuln = sum(r["target"] for r in rows)
    print(f"[info] loaded {len(rows)} valid devign functions "
          f"(vuln={n_vuln} benign={len(rows) - n_vuln})")
    sel = balanced_sample(rows, args.n_per_class, args.seed)
    if args.limit:
        sel = sel[:args.limit]
    s_vuln = sum(r["target"] for r in sel)
    print(f"[info] sampled {len(sel)} (vuln={s_vuln} benign={len(sel) - s_vuln})")

    res_path = out / "results.csv"
    done: set[str] = set()
    if res_path.exists():
        with open(res_path, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                done.add(r["sample_id"])
    fw = open(res_path, "a", encoding="utf-8", newline="")
    w = csv.writer(fw)
    if not done:
        w.writerow(COLUMNS)

    stats = defaultdict(int)
    for r in sel:
        sid = f"devign-{r['project']}-{r['idx']}"
        if sid in done:
            continue
        ctx = DetectionContext(
            request_info=None,
            advisory_meta={"cwe": r["cwe"], "cve_id": sid},
            code_text=r["func"],
            cpg_slices=None,
        )
        v = scorer.score(ctx)
        pred = v.label
        truth = TRUTH_MAP[r["target"]]
        w.writerow([sid, "d2_devign", "code", "LocalLLMScorer",
                    pred, truth, v.cwe or "", r["cwe"] or "", r["project"]])
        fw.flush()
        stats[pred] += 1
    fw.close()
    print(f"[done] predictions: {dict(stats)}")

    m = compute_metrics(res_path, out, args.model)
    print(f"[metrics] BA={m['BA']:.3f} MCC={m['MCC']:+.3f} F1={m['F1']:.3f} "
          f"abstain={m['n_abstain']}/{m['n_total']} "
          f"(trivial_all_vuln F1={m['trivial_all_vuln_F1']:.3f})")


if __name__ == "__main__":
    main()
