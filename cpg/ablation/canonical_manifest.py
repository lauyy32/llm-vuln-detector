# -*- coding: utf-8 -*-
"""生成规范数据集组成表 canonical_corpus_manifest.json（Codex P0-1）。

逐例记录 93 并集样本的 corpus 版本/路径/树哈希/纳入排除/74·85 归属/唯一 fix_commit_group，
并输出恒等式（74 集与 85 集修复后的有效数量，不沿用旧 n=82）。

用法：python cpg/ablation/canonical_manifest.py
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AUDIT = ROOT / "cpg/ablation/.work/upstream_five_state.json"
CACHE = ROOT / "cpg/ablation/.work/upstream_api_cache"


def load_jsonl_ids(path):
    out = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.add(json.loads(line)["cve_id"])
        except Exception:
            pass
    return {x for x in out if x}


def tree_sha(dirpath):
    """目录树哈希：sorted(相对路径 + 文件 sha256) 拼接后 sha256。"""
    if not dirpath.is_dir():
        return None
    parts = []
    for p in sorted(dirpath.rglob("*")):
        if p.is_file():
            rel = p.relative_to(dirpath).as_posix()
            parts.append(rel + ":" + hashlib.sha256(p.read_bytes()).hexdigest())
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def parent_of(cve):
    cache = CACHE / f"{cve}.json"
    if cache.exists():
        d = json.loads(cache.read_text(encoding="utf-8"))
        ps = [p["sha"] for p in d.get("parents", [])]
        if len(ps) == 1:
            return ps[0]
        return ps  # 多 parent 原样返回（供审计）
    return None


def main():
    d74 = load_jsonl_ids(ROOT / "cpg" / "dataset.jsonl")
    d85 = load_jsonl_ids(ROOT / "cpg" / "dataset_d1.jsonl")
    union = d74 | d85
    audit = json.loads(AUDIT.read_text(encoding="utf-8"))

    samples = []
    for cve in sorted(union):
        r = audit.get(cve, {})
        status = r.get("status", "UNKNOWN")
        is_extra = any("EXTRA" in str(m[0]) for m in r.get("mismatches", []))
        if status == "CORPUS_ERROR" and is_extra:
            ver, path, eligible, reason = "v1", f"cpg/corpus_pairs/{cve}", False, \
                "CROSS_LANGUAGE_OUT_OF_SCOPE"
        elif status == "CORPUS_ERROR":
            ver, path, eligible, reason = "v2", f"cpg/corpus-v2/{cve}", True, None
        else:
            ver, path, eligible, reason = "v1", f"cpg/corpus_pairs/{cve}", True, None

        base = ROOT / path
        fix = r.get("commit") or ""
        samples.append({
            "sample_id": cve,
            "fix_commit": fix,
            "parent_commit": parent_of(cve),
            "corpus_version": ver,
            "corpus_path": path,
            "vuln_tree_sha": tree_sha(base / "vuln"),
            "fixed_tree_sha": tree_sha(base / "fixed"),
            "eligible": eligible,
            "exclusion_reason": reason,
            "in_74": cve in d74,
            "in_85": cve in d85,
            "fix_commit_group": fix[:12] if fix else None,
        })

    # 恒等式
    v2 = {s["sample_id"] for s in samples if s["corpus_version"] == "v2"}
    excl = {s["sample_id"] for s in samples if not s["eligible"]}
    m74 = d74 & v2
    m85 = d85 & v2
    x85 = d85 & excl

    manifest = {
        "generated_at": "2026-09-07",
        "union_total": len(union),
        "v1_inherited": len(union) - len(v2) - len(excl),
        "v2_rebuilt": len(v2),
        "excluded_cross_language": sorted(excl),
        "identities": {
            "union": f"{len(union)} = {len(union)-len(v2)-len(excl)} v1 + {len(v2)} v2 + {len(excl)} 排除",
            "main_74": f"{len(d74)} = {len(d74)-len(m74)} v1 + {len(m74)} v2 + {len(d74 & excl)} 排除",
            "d1_85_effective": f"{len(d85)} = {len(d85)-len(m85)-len(x85)} v1 + {len(m85)} v2 + {len(x85)} 排除 → 候选分母 {len(d85)-len(x85)}",
        },
        "samples": samples,
    }

    out = ROOT / "cpg/ablation/.work/canonical_corpus_manifest.json"
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")
    print("恒等式：")
    for k, v in manifest["identities"].items():
        print(f"  {k}: {v}")
    print(f"\n[written] {out} ({len(samples)} 样本)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
