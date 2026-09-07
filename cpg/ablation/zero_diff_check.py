# -*- coding: utf-8 -*-
"""零差异门禁：检测 corpus 对 vuln/fixed 两侧 .py 字节全同的 CVE。

两侧字节全同 = 修复在 Python 作用域内不可观测，vulnerable/benign 标签对 Python 输入无意义
（跨语言修复或错误收录）。此类样本应标 CROSS_LANGUAGE_OUT_OF_SCOPE，从 Python 确认性分析排除，
不能送进 rebuild_pair（无文件可补）。

用法：python cpg/ablation/zero_diff_check.py [--corpus cpg/corpus_pairs]
"""
import argparse
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
    args = ap.parse_args()
    pairs = zero_diff_pairs(Path(args.corpus))
    print(f"零差异对（vuln/fixed .py 字节全同）: {len(pairs)} 例")
    for cve, n in pairs:
        print(f"  {cve} ({n} 文件)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
