# -*- coding: utf-8 -*-
"""零差异门禁：检测 corpus 对 vuln/fixed 两侧 .py 字节全同的 CVE。

两侧字节全同 = 修复在 Python 作用域内不可观测，vulnerable/benign 标签对 Python 输入无意义
（跨语言修复或错误收录）。此类样本应标 CROSS_LANGUAGE_OUT_OF_SCOPE，从 Python 确认性分析排除，
不能送进 rebuild_pair（无文件可补）。

用法：python cpg/ablation/zero_diff_check.py [--corpus cpg/corpus_pairs]
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def zero_diff_pairs(corpus: Path) -> list:
    out = []
    if not corpus.is_dir():
        return out
    for d in sorted(corpus.iterdir()):
        if not d.is_dir():
            continue
        vdir, fdir = d / "vuln", d / "fixed"
        if not vdir.is_dir() or not fdir.is_dir():
            continue
        v = {p.relative_to(vdir).as_posix(): p.read_bytes()
             for p in vdir.rglob("*.py")}
        f = {p.relative_to(fdir).as_posix(): p.read_bytes()
             for p in fdir.rglob("*.py")}
        if v and f and v == f:
            out.append((d.name, len(v)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "cpg" / "corpus_pairs"))
    ap.add_argument("--dataset", default="union",
                    help="union | main74 | d1_85（用于与零差异对求交）")
    args = ap.parse_args()

    # 数据集成员（求交范围）
    def load(f):
        out = set()
        for l in open(f, encoding="utf-8"):
            l = l.strip()
            if l:
                try:
                    out.add(json.loads(l)["cve_id"])
                except Exception:
                    pass
        return out

    d74 = load(ROOT / "cpg" / "dataset.jsonl")
    d85 = load(ROOT / "cpg" / "dataset_d1.jsonl")
    if args.dataset == "main74":
        members = d74
    elif args.dataset == "d1_85":
        members = d85
    else:
        members = d74 | d85

    pairs = zero_diff_pairs(Path(args.corpus))
    # 与数据集成员求交（磁盘残留不计入门禁）
    in_dataset = [(c, n) for c, n in pairs if c in members]
    residual = [(c, n) for c, n in pairs if c not in members]

    print(f"零差异对（vuln/fixed .py 字节全同）: {len(pairs)} 例")
    for c, n in pairs:
        mark = " [数据集内]" if c in members else " [磁盘残留]"
        print(f"  {c} ({n} 文件){mark}")
    if residual:
        print(f"\n磁盘残留（不在数据集，不触发门禁）: {len(residual)} 例")
    # 门禁：数据集内零差异对非空 → 退出非零（fail-closed）
    if in_dataset:
        print(f"\n[GATE FAIL] 数据集内零差异对 {len(in_dataset)} 例，须排除: "
              f"{[c for c, _ in in_dataset]}")
        return 1
    print("\n[GATE PASS] 数据集内零差异对 0 例")
    return 0


if __name__ == "__main__":
    sys.exit(main())
