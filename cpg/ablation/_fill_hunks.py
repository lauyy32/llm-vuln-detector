# -*- coding: utf-8 -*-
"""补全 corpus-v3 各 pair_manifest 缺失的 changed_hunks（P0-1 修复）。

M/T/R/C 用 git diff -U0；A 记为整文件新增；D 记为空。已有则不覆盖。
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation.rebuild_corpus import _changed_hunks  # noqa: E402

V3 = ROOT / "cpg" / "corpus-v3"


def main():
    updated = 0
    filled = 0
    for pm_path in sorted(V3.glob("*/pair_manifest.json")):
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        changed = False
        for f in pm.get("files", []):
            st = f.get("status")
            path = f.get("path")
            # 总是重算（旧 list 格式 → 新 dict 格式 old_ranges/new_ranges）
            if st in ("M", "T", "R", "C"):
                f["changed_hunks"] = _changed_hunks(
                    pm["repo_slug"], pm["parent_commit"], pm["fix_commit"], path)
            elif st == "A":
                fp = V3 / pm["sample_id"] / "fixed" / path
                n = len(fp.read_text(encoding="utf-8", errors="replace").splitlines()) if fp.exists() else 0
                f["changed_hunks"] = {"hunks": [
                    {"old_start": 0, "old_count": 0, "new_start": 1, "new_count": n}]}
            elif st == "D":
                fp = V3 / pm["sample_id"] / "vuln" / path
                n = len(fp.read_text(encoding="utf-8", errors="replace").splitlines()) if fp.exists() else 0
                f["changed_hunks"] = {"hunks": [
                    {"old_start": 1, "old_count": n, "new_start": 0, "new_count": 0}]}
            changed = True
            filled += 1
        if changed:
            pm_path.write_text(json.dumps(pm, ensure_ascii=False, indent=2), encoding="utf-8")
            updated += 1
    print(f"更新 {updated} 个 pair_manifest，补 {filled} 个 changed_hunks 字段")
    # 校验：所有文件都有 changed_hunks
    missing = 0
    for pm_path in sorted(V3.glob("*/pair_manifest.json")):
        pm = json.loads(pm_path.read_text(encoding="utf-8"))
        for f in pm.get("files", []):
            if "changed_hunks" not in f:
                missing += 1
                print(f"  仍缺: {pm['sample_id']} {f['path']}")
    print(f"校验: 缺 changed_hunks 的文件数 = {missing}")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
