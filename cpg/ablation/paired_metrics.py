"""配对判别指标：修正 F1 在平衡配对语料上的度量缺陷。

问题
----
本课题语料为 74 个 CVE × {vuln, fixed} 的**配对平衡集**（148 版本，正类占比
恰好 50%）。在这种构造下 F1 会奖励过度预测：平凡基线"全判 vulnerable"可得
P=0.500 / R=1.000 / **F1=0.667**，高于本研究报告过的任何 scorer 数值
（最高 14B full = 0.365）。因此单独以 F1 作为主指标无法支撑任何强结论——
必须同时给出对基率不敏感的指标与平凡基线对照。

本脚本补齐三层度量：

1. **常规混淆指标**：F1 / Precision / Recall（与既有报告交叉验证）。
2. **对基率不敏感的指标**：
   - 平衡准确率 BA = (TPR + TNR) / 2，随机猜测 = 0.500
   - 马修斯相关系数 MCC ∈ [-1, 1]，随机猜测 = 0
3. **配对判别指标（本语料的正确度量）**：对每个 CVE 检查判定器能否
   把漏洞版本与其修复版本区分开：

   | 结果 | vuln 版本 | fixed 版本 | 含义 |
   |------|-----------|------------|------|
   | 判别成功 correct | 标记 | 未标记 | 真正区分了打补丁前后 |
   | 反向 inverted | 未标记 | 标记 | 判别方向错误 |
   | 双标记 both | 标记 | 标记 | 无判别力（过度标记） |
   | 双未标 neither | 未标记 | 未标记 | 无判别力（漏检） |

   仅 correct 与 inverted 构成"不一致对"（discordant）。在"判定器无判别力"
   的零假设下，不一致对中 correct 的个数服从 Binomial(n_discordant, 0.5)。
   据此给出单侧精确二项 p 值——这是配对设计下的 McNemar 精确检验，不受
   正负类比例影响，也无法被"全判 vulnerable"这类平凡策略刷高
   （平凡基线的 n_discordant = 0，判别率恒为 0）。

用法
----
    python paired_metrics.py seeds/v8_74/results.csv
    python paired_metrics.py seeds/v8_74/results.csv --mode code --markdown
    python paired_metrics.py --b2 b2_74_14b.json --form truncated

纯标准库，输出确定（random 基线固定 seed=42）。
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import sys
from pathlib import Path

VULN = "vulnerable"


# --------------------------------------------------------------------------
# 指标计算
# --------------------------------------------------------------------------
def confusion(pairs: list[tuple[bool, bool]]) -> dict[str, int]:
    """pairs: [(truth_is_vuln, pred_is_vuln), ...]"""
    tp = sum(1 for t, p in pairs if t and p)
    fp = sum(1 for t, p in pairs if not t and p)
    fn = sum(1 for t, p in pairs if t and not p)
    tn = sum(1 for t, p in pairs if not t and not p)
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def basic_metrics(c: dict[str, int]) -> dict[str, float]:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    tpr = rec
    tnr = tn / (tn + fp) if tn + fp else 0.0
    ba = (tpr + tnr) / 2
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn - fp * fn) / denom) if denom else 0.0
    return {"f1": f1, "precision": prec, "recall": rec, "ba": ba, "mcc": mcc}


def binom_sf(k: int, n: int, p: float = 0.5) -> float:
    """P(X >= k) for X ~ Binomial(n, p)，精确求和。"""
    if n == 0:
        return 1.0
    return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k, n + 1))


def paired_metrics(flags: dict[tuple[str, str], bool], cves: list[str]) -> dict:
    """flags[(cve, version)] = 是否标记为 vulnerable"""
    correct = inverted = both = neither = 0
    correct_ids: list[str] = []
    inverted_ids: list[str] = []
    for cve in cves:
        pv = flags.get((cve, "vuln"))
        pf = flags.get((cve, "fixed"))
        if pv is None or pf is None:
            continue
        if pv and not pf:
            correct += 1
            correct_ids.append(cve)
        elif pf and not pv:
            inverted += 1
            inverted_ids.append(cve)
        elif pv and pf:
            both += 1
        else:
            neither += 1
    n_total = correct + inverted + both + neither
    n_disc = correct + inverted
    return {
        "correct": correct,
        "inverted": inverted,
        "both_flagged": both,
        "neither_flagged": neither,
        "n_cve": n_total,
        "n_discordant": n_disc,
        "discrimination_rate": correct / n_total if n_total else 0.0,
        "net_discrimination": (correct - inverted) / n_total if n_total else 0.0,
        "p_value_exact": binom_sf(correct, n_disc),
        "correct_ids": correct_ids,
        "inverted_ids": inverted_ids,
    }


# --------------------------------------------------------------------------
# 数据装载
# --------------------------------------------------------------------------
def load_results_csv(path: Path, mode: str) -> dict[str, dict]:
    """返回 {scorer: {(cve, version): pred_is_vuln}}"""
    per_scorer: dict[str, dict[tuple[str, str], bool]] = {}
    truth: dict[tuple[str, str], bool] = {}
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if mode and row["mode"] != mode:
                continue
            key = (row["sample_id"], row["version"])
            per_scorer.setdefault(row["scorer"], {})[key] = row["predicted"] == VULN
            truth[key] = row["truth"] == VULN
    return {"scorers": per_scorer, "truth": truth}


def load_b2_json(path: Path, form: str) -> dict[str, dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    per_scorer: dict[str, dict[tuple[str, str], bool]] = {
        f"CPGEvidence[{form}]": {},
        f"LocalLLM[{form}]": {},
    }
    truth: dict[tuple[str, str], bool] = {}
    for s in data["samples"]:
        cve, ver = s["sample"].rsplit("_", 1)
        key = (cve, ver)
        truth[key] = s["truth"] == VULN
        per_scorer[f"CPGEvidence[{form}]"][key] = s.get(f"cpg_{form}") == VULN
        per_scorer[f"LocalLLM[{form}]"][key] = s.get(f"llm_{form}") == VULN
    return {"scorers": per_scorer, "truth": truth, "model": data.get("model", "?")}


def add_trivial_baselines(bundle: dict) -> None:
    """注入三个平凡基线，用于暴露 F1 的度量缺陷。"""
    truth = bundle["truth"]
    keys = list(truth)
    bundle["scorers"]["[平凡]全判vulnerable"] = dict.fromkeys(keys, True)
    bundle["scorers"]["[平凡]全判benign"] = dict.fromkeys(keys, False)
    rng = random.Random(42)
    bundle["scorers"]["[平凡]随机(p=0.5,seed=42)"] = {k: rng.random() < 0.5 for k in keys}


TRIVIAL_BASELINE_MARKERS = ("[平凡]",)


def verify_stat_contract(rows: list[dict]) -> list[str]:
    """统计报告契约：任何对比表必须经此校验，防止回归到 F1-only。

    强制四项：
      1. 含平凡基线行（[平凡]全判vulnerable 等）——暴露 F1 度量缺陷；
      2. 每行含 BA（平衡准确率）；
      3. 每行含 MCC（马修斯相关系数）；
      4. 每行含 McNemar 精确 p（配对判别）。
    返回违例文本列表；空列表=通过。
    """
    violations: list[str] = []
    names = [r["scorer"] for r in rows]
    if not any(m in n for n in names for m in TRIVIAL_BASELINE_MARKERS):
        violations.append("缺少平凡基线行（应含 [平凡]全判vulnerable 等）")
    for r in rows:
        if "ba" not in r or "mcc" not in r:
            violations.append(f"scorer={r.get('scorer')} 缺 BA/MCC 字段")
        paired = r.get("paired") or {}
        if "p_value_exact" not in paired:
            violations.append(f"scorer={r.get('scorer')} 缺 McNemar 精确 p")
    return violations


def self_test() -> int:
    """内置统计契约自测：合成 2 CVE 配对，验证平凡基线注入与契约通过。"""
    keys = [("CVE-X", "vuln"), ("CVE-X", "fixed"),
            ("CVE-Y", "vuln"), ("CVE-Y", "fixed")]
    bundle = {
        "truth": {("CVE-X", "vuln"): True, ("CVE-X", "fixed"): False,
                  ("CVE-Y", "vuln"): True, ("CVE-Y", "fixed"): False},
        "scorers": {
            "Demo": {("CVE-X", "vuln"): True, ("CVE-X", "fixed"): False,
                     ("CVE-Y", "vuln"): True, ("CVE-Y", "fixed"): False},
        },
    }
    add_trivial_baselines(bundle)
    rows = evaluate(bundle)
    violations = verify_stat_contract(rows)
    tv = next(r for r in rows if "全判vulnerable" in r["scorer"])
    ok = (not violations) and abs(tv["f1"] - 2 / 3) < 1e-9
    print(f"self_test: contract_violations={len(violations)} "
          f"trivial_F1={tv['f1']:.3f} -> {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


# --------------------------------------------------------------------------
# 输出
# --------------------------------------------------------------------------
def evaluate(bundle: dict) -> list[dict]:
    truth = bundle["truth"]
    cves = sorted({c for c, _ in truth})
    rows = []
    for name, preds in bundle["scorers"].items():
        pairs = [(truth[k], preds.get(k, False)) for k in truth]
        c = confusion(pairs)
        m = basic_metrics(c)
        pm = paired_metrics(preds, cves)
        rows.append({"scorer": name, **c, **m, "paired": pm})
    return rows


def render(rows: list[dict], markdown: bool) -> str:
    out: list[str] = []
    if markdown:
        out.append("| scorer | F1 | P | R | 平衡准确率 BA | MCC | 判别成功 | 反向 | 双标记 | 双未标 | 判别率 | 精确 p |")
        out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for r in rows:
            p = r["paired"]
            out.append(
                f"| {r['scorer']} | {r['f1']:.3f} | {r['precision']:.3f} | {r['recall']:.3f} "
                f"| {r['ba']:.3f} | {r['mcc']:.3f} | {p['correct']} | {p['inverted']} "
                f"| {p['both_flagged']} | {p['neither_flagged']} "
                f"| {p['discrimination_rate']:.3f} | {p['p_value_exact']:.4f} |"
            )
    else:
        for r in rows:
            p = r["paired"]
            out.append(
                f"{r['scorer']:34s} F1={r['f1']:.3f} P={r['precision']:.3f} R={r['recall']:.3f} "
                f"BA={r['ba']:.3f} MCC={r['mcc']:+.3f} || 配对: 成功={p['correct']:2d} "
                f"反向={p['inverted']:2d} 双标={p['both_flagged']:2d} 双漏={p['neither_flagged']:2d} "
                f"判别率={p['discrimination_rate']:.3f} p={p['p_value_exact']:.4f}"
            )
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv", nargs="?", type=Path, help="run_ablation 产出的 results.csv")
    ap.add_argument("--mode", default="code", help="模式过滤（默认 code，主协议）")
    ap.add_argument("--b2", type=Path, help="改为读取 b2_*.json")
    ap.add_argument("--form", default="full", help="B-2 证据形态（full/sink_only/truncated）")
    ap.add_argument("--markdown", action="store_true")
    ap.add_argument("--no-trivial", action="store_true", help="不注入平凡基线")
    ap.add_argument("--check", action="store_true", help="统计契约违例则退出码非零（CI/评审用）")
    ap.add_argument("--self-test", action="store_true", help="跑内置统计契约自测后退出")
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    if args.self_test:
        raise SystemExit(self_test())

    if args.b2:
        bundle = load_b2_json(args.b2, args.form)
        header = f"{args.b2.name} | {bundle.get('model')} | form={args.form}"
    elif args.csv:
        bundle = load_results_csv(args.csv, args.mode)
        header = f"{args.csv} | mode={args.mode}"
    else:
        ap.error("需提供 results.csv 或 --b2")

    if not args.no_trivial:
        add_trivial_baselines(bundle)

    rows = evaluate(bundle)
    print(f"== {header} | {len(bundle['truth'])} 版本 / {len(bundle['truth']) // 2} CVE\n")
    print(render(rows, args.markdown))

    violations = verify_stat_contract(rows)
    if violations:
        print("\n[统计契约 违例]")
        for v in violations:
            print("  -", v)
    else:
        print("\n[统计契约] 通过：含平凡基线 + BA/MCC + McNemar 精确 p")
    if args.check and violations:
        sys.exit(1)

    if args.json_out:
        args.json_out.write_text(
            json.dumps({"source": header, "rows": rows}, ensure_ascii=False, indent=1),
            encoding="utf-8",
        )
        print(f"\n[written] {args.json_out}")


if __name__ == "__main__":
    main()
