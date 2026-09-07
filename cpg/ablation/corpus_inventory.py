# -*- coding: utf-8 -*-
"""语料集合清单（机器可复算，消除 79/104/108 数字混用）。

统一枚举六个集合，输出大小与关键差集。用途：
  1. 审计"数据集成员 vs 磁盘语料目录 vs git 跟踪语料目录"三者的覆盖关系；
  2. 定位"磁盘有、git 无"的未入库语料（可复现性缺口）；
  3. 为 .gitignore 门禁（git 覆盖集合 == 数据集成员集合）提供断言依据。

用法：python cpg/ablation/corpus_inventory.py
"""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "cpg" / "corpus_pairs"


def load_jsonl_ids(path):
    out = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            out.add(o.get("cve_id") or o.get("cve") or o.get("id"))
        except Exception:
            pass
    return {x for x in out if x}


def git_meta_dirs():
    """git 跟踪的、含 meta.json 的 CVE 目录名。"""
    r = subprocess.run(["git", "ls-files", "cpg/corpus_pairs/*/meta.json"],
                       capture_output=True, text=True, encoding="utf-8")
    out = set()
    for line in r.stdout.splitlines():
        parts = line.split("/")
        # cpg/corpus_pairs/CVE-xxx/meta.json
        if len(parts) >= 3:
            out.add(parts[2])
    return out


def disk_meta_dirs():
    return {d.name for d in CORPUS.iterdir()
            if d.is_dir() and (d / "meta.json").exists()}


def disk_all_dirs():
    return {d.name for d in CORPUS.iterdir() if d.is_dir()}


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="fail-closed 门禁：数据集成员的语料未 git 跟踪即返回非零")
    args = ap.parse_args()

    d1_ids = load_jsonl_ids(ROOT / "cpg" / "dataset_d1.jsonl")
    main_ids = load_jsonl_ids(ROOT / "cpg" / "dataset.jsonl")
    disk_all = disk_all_dirs()
    disk_meta = disk_meta_dirs()
    git_meta = git_meta_dirs()
    union = d1_ids | main_ids

    def show(name, s):
        print(f"  {name:<28} = {len(s)}")

    print("== 集合大小 ==")
    show("disk_all_dirs(顶层目录)", disk_all)
    show("disk_meta_dirs(有meta.json)", disk_meta)
    show("git_tracked_meta_dirs", git_meta)
    show("main_74_ids", main_ids)
    show("d1_85_ids", d1_ids)
    show("union(main∪d1)", union)

    print("\n== 关键差集 ==")
    untracked_meta = disk_meta - git_meta
    print(f"  磁盘有 meta.json 但 git 未跟踪: {len(untracked_meta)}")
    for x in sorted(untracked_meta):
        print(f"    - {x}")

    d1_missing_git = d1_ids - git_meta
    print(f"\n  D1(85) 成员但语料未 git 跟踪: {len(d1_missing_git)}")
    for x in sorted(d1_missing_git):
        print(f"    - {x}")

    main_missing_git = main_ids - git_meta
    print(f"\n  74 主集成员但语料未 git 跟踪: {len(main_missing_git)}")
    for x in sorted(main_missing_git):
        print(f"    - {x}")

    # 磁盘有目录但无 meta.json（可能非 CVE 目录或残留）
    no_meta = disk_all - disk_meta
    print(f"\n  磁盘顶层目录但无 meta.json: {len(no_meta)}")
    for x in sorted(no_meta):
        print(f"    - {x}")

    # 数据集引用了、但磁盘既无目录也无 git 跟踪的
    disk_or_git = disk_all | git_meta
    union_missing_disk = union - disk_or_git
    print(f"\n  数据集成员(∪)但磁盘+git 均无: {len(union_missing_disk)}")
    for x in sorted(union_missing_disk):
        print(f"    - {x}")

    # fail-closed 门禁：数据集成员的语料必须 git 跟踪（防 .gitignore 静默忽略）
    fail = union - git_meta
    if args.check:
        if fail:
            print(f"\n[GATE FAIL] 数据集成员语料未 git 跟踪 {len(fail)} 例: "
                  f"{sorted(fail)}")
            return 1
        print("\n[GATE PASS] 数据集成员语料全部 git 跟踪")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
