"""从 evaluation_v2_report.json 提取 v2.1 消融对比的 Markdown 表格，便于回填 README。

用法:
  python tests/gen_readme_tables.py [report.json]

输出三块内容:
  1) 各数据集的三模式主表 (攻击级召回/类型精确检出率/误报率/P/R/F1/Acc) + Δ 行
  2) cot 模式按类型拆分表 (用于核对/重写 v2.0 段落)
  3) 各数据集头条数字 (total/攻击/良性/tp/fp/fn/tn/errors/detection_rate/strict/fpr)
"""
import json
import sys
from pathlib import Path

DEFAULT = Path(__file__).parent / "reports" / "evaluation_v2_report.json"


def fmt(v):
    if v is None:
        return "—"
    return f"{v:.1f}"


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT
    report = json.loads(path.read_text(encoding="utf-8"))
    abl = report.get("ablation", {})
    per_mode = report.get("per_mode", {})

    for ds in ("adversarial", "standard"):
        if ds not in abl:
            continue
        entry = abl[ds]
        modes = entry.get("modes", {})
        print(f"\n===== {ds} 数据集 三模式主表 =====")
        print("| 模式 | 攻击级召回 | 类型精确检出率 | 误报率 | Precision | Recall | F1 | Accuracy |")
        print("|---|---|---|---|---|---|---|---|")
        for m in ("cot", "standard", "no-context"):
            if m not in modes:
                continue
            mt = modes[m]
            label = {"cot": "CoT（增强+CoT）", "standard": "Standard（增强）",
                     "no-context": "No-Context（基线）"}.get(m, m)
            print(f"| {label} | {fmt(mt['detection_rate'])}% | {fmt(mt['strict_detection_rate'])}% | "
                  f"{fmt(mt['fpr'])}% | {fmt(mt['precision'])}% | {fmt(mt['recall'])}% | "
                  f"{fmt(mt['f1'])}% | {fmt(mt['accuracy'])}% |")
        for dk, lbl in (("delta_cot_minus_standard", "Δ CoT−Standard"),
                        ("delta_cot_minus_nocontext", "Δ CoT−NoContext")):
            if dk in entry:
                d = entry[dk]
                print(f"| **{lbl}** | {fmt(d['detection_rate'])} | {fmt(d['strict_detection_rate'])} | "
                      f"{fmt(d['fpr'])} | — | — | — | — |")

        # 头条数字
        cot = modes.get("cot", {})
        print(f"\n-- {ds} 头条 (cot) --")
        print(f"  total={cot.get('total')} valid={cot.get('valid')} errors={cot.get('errors')} "
              f"attack={cot.get('attack_samples')} benign={cot.get('benign_samples')}")
        print(f"  tp={cot.get('tp')} tn={cot.get('tn')} fp={cot.get('fp')} fn={cot.get('fn')} "
              f"type_correct={cot.get('type_correct')} wrong_type={cot.get('wrong_type')}")
        print(f"  detection_rate={fmt(cot.get('detection_rate'))}% "
              f"strict={fmt(cot.get('strict_detection_rate'))}% fpr={fmt(cot.get('fpr'))}%")

        # cot 按类型拆分
        key = f"cot/{ds}"
        bc = per_mode.get(key, {}).get("by_category", {})
        if bc:
            print(f"\n-- {ds} cot 按类型拆分 --")
            print("| 类型 | 样本数 | 类型正确率 | 识别为攻击率 | 正确 | 类型错 | 漏报 | 误报 | 错误 |")
            print("|---|---|---|---|---|---|---|---|---|")
            for cat, c in sorted(bc.items()):
                t = c["total"]
                dr = c.get("detection_rate", 0)
                # 类型正确率近似: correct / total (correct 这里指类型也正确)
                tar = round(c["correct"] / t * 100, 1) if t else 0
                print(f"| {cat} | {t} | {tar:.1f}% | {dr:.1f}% | {c['correct']} | "
                      f"{c['wrong_type']} | {c['miss']} | {c['false_positive']} | {c['error']} |")


if __name__ == "__main__":
    main()
