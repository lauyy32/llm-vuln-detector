# -*- coding: utf-8 -*-
"""P0-7 全量语义验收（codex 要求项）：不止查路径对称。

验收项：
1. empty_side_count == 0（两侧都有实际代码的样本数）
2. M/T 文件 vuln/fixed 路径集合对称
3. unrepresentable（UNREPRESENTABLE_BUDGET）显式上报
4. 按 hunk × side 报 FULL/PARTIAL/ABSENT 分母
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation.excerpt_plan import (  # noqa: E402
    build_pair_selection_plan, render_side,
)

V3 = ROOT / "cpg" / "corpus-v3"


def main():
    empty_side = []
    asym = 0
    unrepr_samples = []
    skipped_hunks = 0
    cov_stat = {"FULL": 0, "PARTIAL": 0, "ABSENT": 0}
    m_files = 0

    for pm_path in sorted(V3.glob("*/pair_manifest.json")):
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        cve = pm["sample_id"]
        spec = type("S", (), {"sample_id": cve})()
        plan = build_pair_selection_plan(
            spec, pm, Path("NONEXISTENT"),
            source_dir=V3 / cve, max_chars=8000, hunk_window=20)
        rv = render_side(plan, "vuln").strip()
        rf = render_side(plan, "fixed").strip()
        if not rv or not rf:
            empty_side.append((cve, "vuln" if not rv else "", "fixed" if not rf else ""))
        if plan.unrepresentable:
            unrepr_samples.append((cve, plan.unrepresentable))
        skipped_hunks += len(plan.skipped_hunks)
        vuln_paths = {b.path for b in plan.blocks if b.side == "vuln"}
        fixed_paths = {b.path for b in plan.blocks if b.side == "fixed"}
        for f in pm["files"]:
            if f["status"] in ("M", "T"):
                m_files += 1
                p = f["path"]
                if (p in vuln_paths) != (p in fixed_paths):
                    asym += 1
                    print(f"[不对称] {cve} {p}")
        for _p, side_cov in plan.hunk_coverage.items():
            for _s, st in side_cov.items():
                cov_stat[st] = cov_stat.get(st, 0) + 1

    print("\n=== P0-7 全量语义验收 ===")
    print(f"M/T 文件总数: {m_files}")
    print(f"路径集合不对称: {asym}")
    print(f"双侧空代码样本: {len(empty_side)}")
    for e in empty_side[:10]:
        print(f"   {e}")
    print(f"UNREPRESENTABLE_BUDGET 样本(任一侧空): {len(unrepr_samples)}")
    for u in unrepr_samples[:10]:
        print(f"   {u}")
    print(f"hunk 级最小窗口仍装不下(跳过并报告，不静默丢弃): {skipped_hunks}")
    print(f"hunk×side 覆盖分母: FULL={cov_stat['FULL']} PARTIAL={cov_stat['PARTIAL']} "
          f"ABSENT={cov_stat['ABSENT']}")
    ok = (asym == 0 and not empty_side and not unrepr_samples)
    print(f"\n结果: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
