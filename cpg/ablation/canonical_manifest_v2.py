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
    for s in old.get("samples", []):
        cve = s.get("sample_id")
        sample = dict(s)  # 保留旧字段（含旧 pair_manifest_sha256，便于对照）
        src = CORPUS_V3 / cve if cve else None
        if src and src.is_dir():
            pm = src / "pair_manifest.json"
            if not pm.exists():
                errors.append(f"{cve}: pair_manifest.json 缺失")
                sample["v2_pair_manifest_sha256"] = None
            else:
                sample["v2_pair_manifest_sha256"] = _sha256(pm.read_bytes())
            sample["v2_vuln_tree_sha256_lf"] = tree_sha_lf(src / "vuln") or None
            sample["v2_fixed_tree_sha256_lf"] = tree_sha_lf(src / "fixed") or None
            sample["v2_tree_match_old"] = (
                sample["v2_vuln_tree_sha256_lf"] == s.get("vuln_tree_sha256_lf")
                and sample["v2_fixed_tree_sha256_lf"] == s.get("fixed_tree_sha256_lf"))
            sample["v2_pair_manifest_match_old"] = (
                sample["v2_pair_manifest_sha256"] == s.get("pair_manifest_sha256"))
        else:
            sample["v2_pair_manifest_sha256"] = None
            sample["v2_vuln_tree_sha256_lf"] = None
            sample["v2_fixed_tree_sha256_lf"] = None
            sample["v2_tree_match_old"] = None
            sample["v2_pair_manifest_match_old"] = None
        samples.append(sample)
    impl = Path(__file__).resolve()
    doc = {
        "schema": "canonical-corpus-manifest/2",
        "supersedes": {
            "path": old_path.relative_to(ROOT).as_posix(),
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
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(doc, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    elig = [s for s in doc["samples"] if s.get("eligible")]
    tree_ok = sum(1 for s in elig if s.get("v2_tree_match_old") is True)
    tree_bad = [s["sample_id"] for s in elig if s.get("v2_tree_match_old") is not True]
    pm_ok = sum(1 for s in elig if s.get("v2_pair_manifest_match_old") is True)
    pm_bad = [s["sample_id"] for s in elig if s.get("v2_pair_manifest_match_old") is not True]
    print(f"[v2] 写入 {args.out}")
    print(f"[v2] eligible={len(elig)} | tree 与旧一致 {tree_ok}/{len(elig)} {tree_bad}")
    print(f"[v2] pair_manifest 与旧一致 {pm_ok}/{len(elig)}（不一致即旧字段陈旧的样本数 "
          f"{len(pm_bad)}）")
    if doc["errors"]:
        print("[v2] errors:", doc["errors"][:5])
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
