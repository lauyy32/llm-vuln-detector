# -*- coding: utf-8 -*-
"""验证 P0-7 第3步：全 82 例 vuln/fixed 文件集合对称（排除 A/D/R 预期不对称）。"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation.excerpt_plan import build_pair_selection_plan  # noqa: E402

V3 = ROOT / "cpg" / "corpus-v3"


def main():
    asym = 0
    total = 0
    for pm_path in sorted(V3.glob("*/pair_manifest.json")):
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        cve = pm["sample_id"]
        spec = type("S", (), {"sample_id": cve})()
        plan = build_pair_selection_plan(
            spec, pm, Path("NONEXISTENT"),
            source_dir=V3 / cve, max_chars=8000, hunk_window=20)
        vuln_paths = {b.path for b in plan.blocks if b.side == "vuln"}
        fixed_paths = {b.path for b in plan.blocks if b.side == "fixed"}
        # 预期不对称：A 只 fixed、D 只 vuln、R 用 prev/new 不同 path
        expected_vuln_only = {f["prev"] if f["status"] == "R" else f["path"]
                              for f in pm["files"] if f["status"] == "D"}
        expected_fixed_only = {f["path"] for f in pm["files"] if f["status"] == "A"}
        # R 文件：vuln 侧是 prev，fixed 侧是 path，都算"存在"
        # 检查 M 文件的对称性（核心）
        m_paths = {f["path"] for f in pm["files"] if f["status"] in ("M", "T")}
        for p in m_paths:
            total += 1
            in_v = p in vuln_paths
            in_f = p in fixed_paths
            if in_v != in_f:
                asym += 1
                print(f"[不对称] {cve} {p}: vuln={in_v} fixed={in_f}")
    print(f"\nM/T 文件对称性检查: {total} 个 M 文件，非预期不对称 {asym} 个")
    return 1 if asym else 0


if __name__ == "__main__":
    sys.exit(main())
