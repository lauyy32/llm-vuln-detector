"""配对完整性检查（④ 新增）：列出语料中 vuln/fixed 任一侧缺失源（空 .py）的 CVE。

背景：v10 重跑中 D1-set 出现假 p=0.031——53500/70485 的 fixed 侧源缺失（0 文件），
LocalLLM 对空 fixed 平凡判 benign，制造"空洞判别"。配对判别度量必须**剔除任一侧源缺失
的 CVE**（无法配对即无判别意义）。74-set 无此问题；D1-set 有 3 个（53500/59224/70485）。

用法：
  python cpg/ablation/pair_completeness.py --dataset cpg/dataset_d1.jsonl
  python cpg/ablation/pair_completeness.py --dataset cpg/dataset.jsonl   # 应为 0 个
"""
import argparse
import json
import os
import sys
from pathlib import Path

SRC = Path(os.environ.get("CPG_DATA_ROOT", "C:/Users/lenovo/cpg_db")) / "corpus_src"


def py_count(d: Path) -> int:
    if not d.is_dir():
        return 0
    return sum(1 for _, _, fs in os.walk(d) for f in fs if f.endswith(".py"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset", required=True)
    args = ap.parse_args()

    cves = sorted({json.loads(l)["cve_id"] for l in open(args.dataset, encoding="utf-8")})
    broken = []
    for c in cves:
        nv = py_count(SRC / f"{c}_vuln")
        nf = py_count(SRC / f"{c}_fixed")
        if nv == 0 or nf == 0:
            broken.append((c, nv, nf))
    print(f"dataset={args.dataset}: {len(cves)} CVE | 任一侧源缺失: {len(broken)}")
    for c, nv, nf in broken:
        print(f"  {c}: vuln={nv} fixed={nf}  <- 须从配对判别度量剔除")
    sys.exit(1 if broken else 0)


if __name__ == "__main__":
    main()
