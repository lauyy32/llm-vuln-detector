#!/usr/bin/env python3
"""
build_d1_dataset.py - D1 扩语料：从 corpus_pairs 聚合「通过污染校验」的修复前后对，
生成扩展语料集（默认 cpg/dataset_d1.jsonl），用于在不破坏 74-CVE 基线（dataset.jsonl）
的前提下做规模消融（OPEN #18）。

校验纪律（与采集管线一致，显式可审计）：
- 必须 vuln/ + fixed/ 双目录齐全；
- extraction_signal.json 若存在且 blocked==True → 排除（重构式修复，truth 不可靠）；
- extraction_signal missing_ratio >= 0.30 → 排除（vuln 侧缺失过多，等同污染）；
- 已知跨语言/重构污染白名单（memory 记录）强制排除：
  CVE-2026-69248/69249（Rust 修复，Python 侧 diff=0）、
  CVE-2026-55419/55244/55558/73974/68508（重构式修复信号）、
  CVE-2026-47192/48710/49257/59894（blocked-signal）、_poc_seed（归档）。
- 来源分层：每仓库最多 max_per_repo 条，避免单仓库聚集偏见（与 build_index 一致）。

用法：
  python build_d1_dataset.py --out dataset_d1.jsonl --max-per-repo 2
"""
from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS_PAIRS = ROOT / "corpus_pairs"

# 已知污染白名单（强制排除，理由见上方 docstring）
FORCE_EXCLUDE = {
    "CVE-2026-69248", "CVE-2026-69249",   # Rust 修复，Python 侧 diff=0
    "CVE-2026-55419", "CVE-2026-55244", "CVE-2026-55558",
    "CVE-2026-73974", "CVE-2026-68508",   # 重构式修复（missing_ratio>=0.3）
    "CVE-2026-47192", "CVE-2026-48710", "CVE-2026-49257", "CVE-2026-59894",  # blocked-signal
}
ARCHIVE_PREFIX = "_"  # corpus_pairs 中以 _ 开头的目录视为归档


def is_valid_pair(pair_dir: Path) -> tuple[bool, str]:
    """返回 (是否可用, 原因)。"""
    name = pair_dir.name
    if name.startswith(ARCHIVE_PREFIX):
        return False, "archive"
    if name in FORCE_EXCLUDE:
        return False, "force-excluded"
    subs = {p.name for p in pair_dir.iterdir() if p.is_dir()}
    if "vuln" not in subs or "fixed" not in subs:
        return False, "no-both-dirs"
    sig = pair_dir / "extraction_signal.json"
    if sig.exists():
        try:
            s = json.loads(sig.read_text(encoding="utf-8"))
        except Exception:
            return False, "bad-signal"
        if s.get("blocked"):
            return False, "blocked-signal"
        if (s.get("missing_ratio") or 0) >= 0.30:
            return False, f"refactor-missing={s.get('missing_ratio')}"
    meta = pair_dir / "meta.json"
    if not meta.exists():
        return False, "no-meta"
    return True, "ok"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="dataset_d1.jsonl")
    ap.add_argument("--max-per-repo", type=int, default=2,
                    help="每仓库最多收录条数（打散来源聚集）")
    args = ap.parse_args()
    out = ROOT / args.out

    if not CORPUS_PAIRS.exists():
        print("[fail] corpus_pairs missing")
        raise SystemExit(1)

    valid: list[dict] = []
    reasons: dict[str, int] = defaultdict(int)
    for d in sorted(CORPUS_PAIRS.iterdir()):
        if not d.is_dir():
            continue
        ok, why = is_valid_pair(d)
        reasons[why] += 1
        if ok:
            meta = json.loads((d / "meta.json").read_text(encoding="utf-8"))
            valid.append(meta)

    # 来源分层（每仓库最多 max_per_repo，保严重度优先）
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    by_repo: dict[str, list[dict]] = defaultdict(list)
    for m in valid:
        by_repo[m["repo_slug"]].append(m)
    cohort: list[dict] = []
    seen_commit: set[str] = set()
    for repo, items in by_repo.items():
        items.sort(key=lambda r: (sev_rank.get(r.get("severity"), 9),
                                  r.get("published", "")), reverse=True)
        for it in items[: args.max_per_repo]:
            if it["fix_commit"] in seen_commit:
                continue
            seen_commit.add(it["fix_commit"])
            cohort.append(it)

    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in cohort),
                   encoding="utf-8")
    print(f"[ok] {len(cohort)} valid CVE pairs (both versions) -> {out}")
    print(f"     = {len(cohort)*2} versions (目标 >=300 需 {max(0,150-len(cohort))} 更多 CVE)")
    print(f"[diversity] distinct repos: {len(by_repo)}")
    from collections import Counter
    cw = Counter()
    for r in cohort:
        for w in r.get("cwes", []):
            cw[w] += 1
    print(f"[diversity] CWE families: {len(cw)} -> {dict(cw.most_common())}")
    print("[filter] 排除原因统计:")
    for k, v in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"    {v:3d}  {k}")


if __name__ == "__main__":
    main()
