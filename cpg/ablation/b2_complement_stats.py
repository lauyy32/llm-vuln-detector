"""B-2 互补性逐样本交叉统计：把"LLM 兜底"拆成可核对的两类。

动机
----
B-2 报告 §3.1 曾以"LLM 语义补全成功 8 个 vuln 样本"表述互补性，但该表述
混合了两种性质不同的互补事件，且仅覆盖 54 版本 truncated 形态。外部评审
按不同口径重算会得到不同数字（例如仅统计 full 形态、或仅统计"CPG 判错被
LLM 纠正"），造成"兜底只有 1 个样本"之类的争议。

本脚本对每个证据形态（full / sink_only / truncated）分别输出四象限计数，
把互补事件按 CPG 的失败模式拆开：

  正类（truth=vulnerable）
    A1  LLM 独有检出 · CPG 弃权   cpg=abstain      llm=vulnerable
    A2  LLM 独有检出 · CPG 判错   cpg=benign       llm=vulnerable
    B   CPG 独有检出             cpg=vulnerable   llm!=vulnerable
    C   双方检出                 cpg=vulnerable   llm=vulnerable
    D   双方漏检                 均非 vulnerable

  负类（truth=benign）——互补的代价侧
    E1  LLM 独有误报             cpg!=vulnerable  llm=vulnerable
    E2  CPG 独有误报             cpg=vulnerable   llm!=vulnerable
    E3  双方误报                 均 vulnerable

"LLM 兜底" = A1 + A2，其中 A1 是"确定性解析器失明"、A2 是"确定性解析器
给出错误结论"。二者在系统设计上含义不同：A1 支持"降级证据下 LLM 接管"，
A2 才是"LLM 纠正 CPG"。报告须分别列出，不得合并成单一数字。

用法
----
    python b2_complement_stats.py b2_74_7b.json b2_74_14b.json
    python b2_complement_stats.py --markdown b2_74_7b.json > out.md

无外部依赖，纯标准库；输出确定（无随机性）。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

VULN = "vulnerable"
BENIGN = "benign"
ABSTAIN = "abstain"


def _detected(label: str) -> bool:
    """判定是否算作"检出漏洞"。abstain 与 benign 均计未检出（与 metrics 口径一致）。"""
    return label == VULN


def cross_tab(samples: list[dict], form: str) -> dict[str, list[str]]:
    """返回某一证据形态下的四象限样本名清单（便于逐条核对，而非只给计数）。"""
    ck, lk = f"cpg_{form}", f"llm_{form}"
    buckets: dict[str, list[str]] = {
        "A1_llm_only_cpg_abstain": [],
        "A2_llm_only_cpg_wrong": [],
        "B_cpg_only": [],
        "C_both_detect": [],
        "D_both_miss": [],
        "E1_llm_only_fp": [],
        "E2_cpg_only_fp": [],
        "E3_both_fp": [],
    }
    for s in samples:
        name, truth = s["sample"], s["truth"]
        cpg, llm = s.get(ck), s.get(lk)
        if cpg is None or llm is None:
            continue
        cd, ld = _detected(cpg), _detected(llm)
        if truth == VULN:
            if ld and not cd:
                key = "A1_llm_only_cpg_abstain" if cpg == ABSTAIN else "A2_llm_only_cpg_wrong"
                buckets[key].append(name)
            elif cd and not ld:
                buckets["B_cpg_only"].append(name)
            elif cd and ld:
                buckets["C_both_detect"].append(name)
            else:
                buckets["D_both_miss"].append(name)
        else:  # truth == benign
            if ld and not cd:
                buckets["E1_llm_only_fp"].append(name)
            elif cd and not ld:
                buckets["E2_cpg_only_fp"].append(name)
            elif cd and ld:
                buckets["E3_both_fp"].append(name)
    return buckets


def analyse(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "file": path.name,
        "model": data.get("model", "?"),
        "n_versions": len(data["samples"]),
        "forms": {f: cross_tab(data["samples"], f) for f in data["forms"]},
    }


ROW_LABELS = [
    ("A1_llm_only_cpg_abstain", "LLM 独有检出 · CPG 弃权"),
    ("A2_llm_only_cpg_wrong", "LLM 独有检出 · CPG 判错"),
    ("B_cpg_only", "CPG 独有检出"),
    ("C_both_detect", "双方检出"),
    ("D_both_miss", "双方漏检"),
    ("E1_llm_only_fp", "LLM 独有误报（负类）"),
    ("E2_cpg_only_fp", "CPG 独有误报（负类）"),
    ("E3_both_fp", "双方误报（负类）"),
]


def render_markdown(results: list[dict]) -> str:
    out: list[str] = []
    for r in results:
        out.append(f"### {r['model']}（{r['n_versions']} 版本，{r['file']}）\n")
        forms = list(r["forms"].keys())
        out.append("| 象限 | " + " | ".join(forms) + " |")
        out.append("|------|" + "|".join(["------"] * len(forms)) + "|")
        for key, label in ROW_LABELS:
            cells = [str(len(r["forms"][f][key])) for f in forms]
            out.append(f"| {label} | " + " | ".join(cells) + " |")
        out.append("")
        for f in forms:
            a1 = r["forms"][f]["A1_llm_only_cpg_abstain"]
            a2 = r["forms"][f]["A2_llm_only_cpg_wrong"]
            out.append(
                f"- `{f}` LLM 兜底合计 {len(a1) + len(a2)}"
                f"（弃权型 {len(a1)} / 纠错型 {len(a2)}）"
            )
            if a1:
                out.append(f"  - 弃权型：{', '.join(sorted(a1))}")
            if a2:
                out.append(f"  - 纠错型：{', '.join(sorted(a2))}")
        out.append("")
    return "\n".join(out)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("files", nargs="+", help="b2_*.json 结果文件")
    ap.add_argument("--markdown", action="store_true", help="输出 Markdown 表格")
    ap.add_argument("--json-out", type=Path, help="同时写出结构化 JSON")
    args = ap.parse_args()

    results = [analyse(Path(f)) for f in args.files]

    if args.markdown:
        print(render_markdown(results))
    else:
        for r in results:
            print(f"== {r['file']} | {r['model']} | {r['n_versions']} 版本")
            for form, b in r["forms"].items():
                a1, a2 = b["A1_llm_only_cpg_abstain"], b["A2_llm_only_cpg_wrong"]
                print(
                    f"  [{form}] 兜底={len(a1) + len(a2)}"
                    f" (弃权型 {len(a1)}, 纠错型 {len(a2)})"
                    f" | CPG独有={len(b['B_cpg_only'])}"
                    f" | 双检={len(b['C_both_detect'])}"
                    f" | 双漏={len(b['D_both_miss'])}"
                    f" | LLM独误={len(b['E1_llm_only_fp'])}"
                    f" | CPG独误={len(b['E2_cpg_only_fp'])}"
                    f" | 双误={len(b['E3_both_fp'])}"
                )
                if a1:
                    print(f"      弃权型: {', '.join(sorted(a1))}")
                if a2:
                    print(f"      纠错型: {', '.join(sorted(a2))}")

    if args.json_out:
        args.json_out.write_text(
            json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8"
        )
        print(f"\n[written] {args.json_out}")


if __name__ == "__main__":
    main()
