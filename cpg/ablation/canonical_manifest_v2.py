# -*- coding: utf-8 -*-
"""canonical manifest v2：从 corpus-v3 + 逐例 pair_manifest 机械重算 provenance。

动因（codex 裁决，采用强化版 B）：
旧 `canonical_corpus_manifest.json` 的 `pair_manifest_sha256` 字段整体陈旧——
f20e516（2026-09-09 17:29）重建 pair manifest 后未同步 manifest，致 82/82 例
字段值与磁盘不符。但**该文件已被 RQ1-R 的 lock_request 逐字节绑定**，
绝不能就地修改（= 事后改动已完成实验的输入锚点）。

因此：
- 旧 manifest **逐字节不变**，永久作为 RQ1-R 历史输入；
- 本脚本生成版本化文件 `canonical_corpus_manifest.v2.json`，含谱系、
  重算后的 pair-manifest SHA 与双侧 tree SHA、修订原因。

用法：
    python cpg/ablation/canonical_manifest_v2.py [--out ...] [--old ...]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation.canonical_manifest import tree_sha_lf  # noqa: E402

OLD = ROOT / "cpg" / "ablation" / "artifacts" / "canonical_corpus_manifest.json"
OUT = ROOT / "cpg" / "ablation" / "artifacts" / "canonical_corpus_manifest.v2.json"
CORPUS_V3 = ROOT / "cpg" / "corpus-v3"
REVISION_REASON = "PAIR_MANIFEST_PROVENANCE_REFRESH"


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rel_or_abs(p: Path) -> str:
    """优先返回相对 ROOT 的 posix 路径；不在 ROOT 下则返回绝对路径（测试/临时文件）。"""
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _git_commit() -> str | None:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def build_v2(old_path: Path = OLD) -> dict:
    old_bytes = old_path.read_bytes()
    old = json.loads(old_bytes.decode("utf-8"))
    samples, errors = [], []
    # P0-3：sample ID 唯一性
    ids = [s.get("sample_id") for s in old.get("samples", [])]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    if dups:
        errors.append(f"重复 sample_id: {dups}")
    for s in old.get("samples", []):
        cve = s.get("sample_id")
        sample = dict(s)
        # P0-1：正式字段 = 当前重算值；旧值只作谱系留档改名 legacy_*
        sample["legacy_pair_manifest_sha256"] = s.get("pair_manifest_sha256")
        sample["legacy_vuln_tree_sha256_lf"] = s.get("vuln_tree_sha256_lf")
        sample["legacy_fixed_tree_sha256_lf"] = s.get("fixed_tree_sha256_lf")
        src = CORPUS_V3 / cve if cve else None
        if src and src.is_dir():
            pm = src / "pair_manifest.json"
            sample["pair_manifest_sha256"] = _sha256(pm.read_bytes()) if pm.exists() else None
            sample["vuln_tree_sha256_lf"] = tree_sha_lf(src / "vuln") or None
            sample["fixed_tree_sha256_lf"] = tree_sha_lf(src / "fixed") or None
            sample["tree_match_legacy"] = (
                sample["vuln_tree_sha256_lf"] == s.get("vuln_tree_sha256_lf")
                and sample["fixed_tree_sha256_lf"] == s.get("fixed_tree_sha256_lf"))
            sample["pair_manifest_match_legacy"] = (
                sample["pair_manifest_sha256"] == s.get("pair_manifest_sha256"))
        else:
            sample["pair_manifest_sha256"] = None
            sample["vuln_tree_sha256_lf"] = None
            sample["fixed_tree_sha256_lf"] = None
            sample["tree_match_legacy"] = None
            sample["pair_manifest_match_legacy"] = None
        # P0-3：eligible 样本必须完整重算（source/pair/两侧 tree 齐备，且 tree 与旧一致）
        if s.get("eligible"):
            if not (src and src.is_dir()):
                errors.append(f"{cve}: eligible 但 corpus-v3 目录缺失")
            elif sample["pair_manifest_sha256"] is None:
                errors.append(f"{cve}: eligible 但 pair_manifest.json 缺失")
            elif not sample["vuln_tree_sha256_lf"] or not sample["fixed_tree_sha256_lf"]:
                errors.append(f"{cve}: eligible 但 tree SHA 为空")
            elif sample["tree_match_legacy"] is not True:
                errors.append(f"{cve}: eligible 但 tree SHA 与旧 manifest 不一致（真漂移）")
        samples.append(sample)
    # P0-3：eligible 精确数量/集合
    old_elig = {s.get("sample_id") for s in old.get("samples", []) if s.get("eligible")}
    new_elig = {s.get("sample_id") for s in samples if s.get("eligible")}
    if old_elig != new_elig:
        errors.append(f"eligible 集合变化: 缺={sorted(old_elig - new_elig)} "
                      f"多={sorted(new_elig - old_elig)}")
    if len(new_elig) != old.get("eligible_total"):
        errors.append(f"eligible 数量 {len(new_elig)} != eligible_total {old.get('eligible_total')}")
    impl = Path(__file__).resolve()
    doc = {
        "schema": "canonical-corpus-manifest/2",
        "supersedes": {
            "path": _rel_or_abs(old_path),
            "sha256": _sha256(old_bytes),
            "note": "旧 manifest 逐字节冻结，永久作为 RQ1-R 历史输入；不得修改",
        },
        "revision_reason": REVISION_REASON,
        "revision_detail": ("旧 pair_manifest_sha256 整体陈旧（f20e516 重建 pair manifest "
                            "后未同步）；本版本按当前 corpus-v3 机械重算，不改任何语料文件"),
        "generator": {
            "git_commit": _git_commit(),
            "implementation": impl.relative_to(ROOT).as_posix(),
            "implementation_sha256": _sha256(impl.read_bytes()),
            "tree_sha_impl": "cpg.ablation.canonical_manifest.tree_sha_lf（复用权威实现）",
        },
        "samples": samples,
        "errors": errors,
    }
    return doc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--old", type=Path, default=OLD)
    ap.add_argument("--out", type=Path, default=OUT)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    doc = build_v2(args.old)
    elig = [s for s in doc["samples"] if s.get("eligible")]
    tree_ok = sum(1 for s in elig if s.get("tree_match_legacy") is True)
    tree_bad = [s["sample_id"] for s in elig if s.get("tree_match_legacy") is not True]
    pm_ok = sum(1 for s in elig if s.get("pair_manifest_match_legacy") is True)
    pm_bad = [s["sample_id"] for s in elig if s.get("pair_manifest_match_legacy") is not True]
    print(f"[v2] eligible={len(elig)} | tree 与旧一致 {tree_ok}/{len(elig)} {tree_bad}")
    print(f"[v2] pair_manifest 与旧一致 {pm_ok}/{len(elig)}（旧字段陈旧样本数 {len(pm_bad)}）")
    if doc["errors"]:
        print("[v2] errors:", doc["errors"][:8])
        print("[v2] FAIL（不写输出，fail-closed）")
        return 1
    # P0-3：全部通过后原子提升
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(args.out.suffix + ".tmp")
    tmp.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    tmp.replace(args.out)
    print(f"[v2] 写入 {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
