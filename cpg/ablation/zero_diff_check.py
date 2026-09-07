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

    # 读规范 manifest 的排除集（Codex 门禁语义修正：已排除的零差异应验证记录正确后 PASS，
    # 而非 FAIL；只有"纳入样本 ∩ 零差异 ≠ ∅"才 FAIL）
    manifest_path = ROOT / "cpg/ablation/.work/canonical_corpus_manifest.json"
    excluded = set()
    if manifest_path.exists():
        m = json.load(open(manifest_path, encoding="utf-8"))
        excluded = {s["sample_id"] for s in m["samples"] if not s["eligible"]}

    included_zero = [(c, n) for c, n in pairs if c in members and c not in excluded]
    excluded_zero = [(c, n) for c, n in pairs if c in excluded]
    residual = [(c, n) for c, n in pairs if c not in members and c not in excluded]

    print(f"零差异对（vuln/fixed .py 字节全同）: {len(pairs)} 例")
    for c, n in pairs:
        if c in excluded:
            mark = " [已排除(CROSS_LANGUAGE)]"
        elif c in members:
            mark = " [纳入样本·触发门禁]"
        else:
            mark = " [磁盘残留]"
        print(f"  {c} ({n} 文件){mark}")
    if excluded_zero:
        print(f"\n已排除样本的零差异（验证排除记录正确）: {len(excluded_zero)} 例 "
              f"{[c for c, _ in excluded_zero]}")
    if residual:
        print(f"磁盘残留（不在数据集，不触发门禁）: {len(residual)} 例")

    # 门禁：纳入样本 ∩ 零差异非空 → FAIL；否则 PASS（含已排除样本的零差异）
    if included_zero:
        print(f"\n[GATE FAIL] 纳入样本零差异对 {len(included_zero)} 例: "
              f"{[c for c, _ in included_zero]}")
        return 1
    print("\n[GATE PASS] 纳入样本 ∩ 零差异 = ∅"
          + (f"（已排除 {len(excluded_zero)} 例的零差异记录正确）" if excluded_zero else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
