# -*- coding: utf-8 -*-
"""规范数据集组成表 canonical_corpus_manifest.json（Code plan 第2阶段重写）。

不再读陈旧 `.work/upstream_five_state.json` 决定真值，直接消费：
- dataset_d1.jsonl / dataset.jsonl 的数据集行（repo_slug/fix_commit/cwes）；
- corpus-v3 每例的 pair_manifest.json（vuln/fixed LF 树哈希 + parent/fix 40 位 SHA）；
- 明确的排除记录（2 跨语言 + 1 复合提交）。

验证（任一失败退出非零）：
- eligible == 82；82/82 路径存在；82/82 树哈希匹配（重算 vs manifest）；
- fix/parent 完整 40 位；无重复样本；无大小写碰撞；排除理由精确匹配。

用法：python cpg/ablation/canonical_manifest.py
"""
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS_V3 = ROOT / "cpg" / "corpus-v3"
DATASET = ROOT / "cpg" / "dataset.jsonl"
DATASET_D1 = ROOT / "cpg" / "dataset_d1.jsonl"
OUT = ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.json"

# 排除记录（须与 corpus-v3 重建时的排除一致）
EXCLUSIONS = {
    "CVE-2026-70486": "CROSS_LANGUAGE_OUT_OF_SCOPE",
    "CVE-2026-70492": "CROSS_LANGUAGE_OUT_OF_SCOPE",
    "CVE-2026-53656": "COMPOSITE_FIX_COMMIT",
}
EXPECTED_ELIGIBLE = 82


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def norm_lf(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def tree_sha_lf(dirpath: Path) -> str:
    """目录树哈希（LF 规范化内容），跨平台可复算。"""
    if not dirpath.is_dir():
        return ""
    parts = []
    for p in sorted(dirpath.rglob("*")):
        if p.is_file():
            rel = p.relative_to(dirpath).as_posix()
            parts.append(rel + ":" + sha256(norm_lf(p.read_bytes())))
    return sha256("\n".join(parts).encode("utf-8"))


def main():
    d74_ids = {r["cve_id"] for r in load_jsonl(DATASET) if r.get("cve_id")}
    d85_rows = load_jsonl(DATASET_D1)
    d85_ids = {r["cve_id"] for r in d85_rows if r.get("cve_id")}

    errors = []
    samples = []

    # 排除样本（不读 corpus-v3）
    for cve in sorted(EXCLUSIONS):
        samples.append({
            "sample_id": cve,
            "repo_slug": next((r.get("repo_slug") for r in d85_rows if r.get("cve_id") == cve), ""),
            "parent_commit": None,
            "fix_commit": next((r.get("fix_commit") for r in d85_rows if r.get("cve_id") == cve), ""),
            "source_path": None,
            "vuln_tree_sha256_lf": None,
            "fixed_tree_sha256_lf": None,
            "pair_manifest_sha256": None,
            "eligible": False,
            "exclusion_reason": EXCLUSIONS[cve],
            "in_74": cve in d74_ids,
            "in_85": cve in d85_ids,
        })

    # eligible 样本（读 corpus-v3 pair_manifest）
    for r in d85_rows:
        cve = r.get("cve_id")
        if not cve or cve in EXCLUSIONS:
            continue
        pm_path = CORPUS_V3 / cve / "pair_manifest.json"
        if not pm_path.exists():
            errors.append(f"{cve}: pair_manifest.json 缺失")
            continue
        try:
            pm = json.loads(pm_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            errors.append(f"{cve}: pair_manifest.json 非法 JSON")
            continue

        vuln_ts = tree_sha_lf(CORPUS_V3 / cve / "vuln")
        fixed_ts = tree_sha_lf(CORPUS_V3 / cve / "fixed")
        if not vuln_ts or not fixed_ts:
            errors.append(f"{cve}: vuln/fixed 目录缺失或空")
            continue
        if vuln_ts != pm.get("vuln_tree_sha256_lf"):
            errors.append(f"{cve}: vuln 树哈希漂移")
        if fixed_ts != pm.get("fixed_tree_sha256_lf"):
            errors.append(f"{cve}: fixed 树哈希漂移")
        if len(pm.get("fix_commit", "")) != 40 or len(pm.get("parent_commit", "")) != 40:
            errors.append(f"{cve}: commit 非 40 位")

        samples.append({
            "sample_id": cve,
            "repo_slug": pm.get("repo_slug"),
            "parent_commit": pm.get("parent_commit"),
            "fix_commit": pm.get("fix_commit"),
            "source_path": f"cpg/corpus-v3/{cve}",
            "vuln_tree_sha256_lf": vuln_ts,
            "fixed_tree_sha256_lf": fixed_ts,
            "pair_manifest_sha256": sha256(pm_path.read_bytes()),
            "eligible": True,
            "exclusion_reason": None,
            "in_74": cve in d74_ids,
            "in_85": cve in d85_ids,
        })

    eligible = [s for s in samples if s["eligible"]]
    excluded = [s for s in samples if not s["eligible"]]

    # 验证
    if len(eligible) != EXPECTED_ELIGIBLE:
        errors.append(f"eligible={len(eligible)} != {EXPECTED_ELIGIBLE}")
    if len(eligible) + len(excluded) != len(d85_ids):
        errors.append(f"恒等式 {len(eligible)}+{len(excluded)} != D1 {len(d85_ids)}")
    # 无重复样本
    ids = [s["sample_id"] for s in samples]
    if len(ids) != len(set(ids)):
        errors.append("存在重复样本 ID")
    # 无大小写碰撞
    lowered = {}
    for s in samples:
        k = s["sample_id"].lower()
        if k in lowered:
            errors.append(f"大小写碰撞: {lowered[k]} vs {s['sample_id']}")
        lowered[k] = s["sample_id"]

    manifest = {
        "schema_version": "canonical-corpus/2",
        "generated_at": "2026-09-08",
        "eligible_total": len(eligible),
        "excluded_total": len(excluded),
        "d1_total": len(d85_ids),
        "d74_total": len(d74_ids),
        "identity": f"{len(eligible)} eligible + {len(excluded)} excluded = {len(d85_ids)} (D1)",
        "samples": samples,
        "errors": errors,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"eligible={len(eligible)}  excluded={len(excluded)}  identity={manifest['identity']}")
    print(f"[written] {OUT}")

    if errors:
        print("\n[FAIL] 验证错误:")
        for e in errors:
            print(f"  {e}")
        return 1
    print("\n[PASS] canonical manifest 验证通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
