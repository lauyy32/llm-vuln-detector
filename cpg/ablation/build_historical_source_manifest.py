# -*- coding: utf-8 -*-
"""生成历史源码证据清单（side 级 LF 树 SHA），用于指令 5 的 source_status 判定。

证据来源优先级：
1. `git-commit`：从历史基线提交 2133a35 的 `cpg/corpus_pairs/<CVE>/<side>` 重建
   （用 git archive 一次性导出，再本地计算 LF 规范化树哈希）；
2. `private-backup-manifest`：当时未入库的 17 例，消费异地备份目录，
   并用其 manifest-sha256.json 校验原始字节完整性后计算 LF 树哈希；
3. `unavailable`：无权威证据 → tree_sha256_lf=null（后续标 UNKNOWN）。

禁止读取当前工作目录的 corpus_pairs/corpus-v3 后声称它就是历史状态。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HISTORICAL_COMMIT = "2133a35cc54349cf5adc50aefdc4309063907656"
DEFAULT_BACKUP = Path("C:/Users/lenovo/corpus-d1-17-backup-20260907")


def tree_sha_lf(dirpath: Path) -> str:
    """目录树哈希（LF 规范化内容），与 legacy_rq1_r0.tree_sha_lf 一致。"""
    parts = []
    for p in sorted(dirpath.rglob("*")):
        if p.is_file():
            rel = p.relative_to(dirpath).as_posix()
            data = p.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            parts.append(rel + ":" + hashlib.sha256(data).hexdigest())
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def export_historical_corpus(tmpdir: Path) -> Path:
    """git archive 导出 2133a35 的 corpus_pairs（一次性，避免逐文件 git show）。"""
    out = tmpdir / "hist"
    out.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        ["git", "archive", HISTORICAL_COMMIT, "cpg/corpus_pairs"],
        cwd=str(ROOT), capture_output=True)
    if r.returncode != 0:
        raise RuntimeError(f"git archive 失败: {r.stderr[:300]!r}")
    subprocess.run(["tar", "-x", "-C", str(out)], input=r.stdout, check=True)
    return out / "cpg" / "corpus_pairs"


def load_backup(backup: Path):
    """返回 ({(cve, side): Path(目录)}, {side_key: {rel_path: sha256}}, manifest_sha)。

    side_key 形如 "CVE-2026-53500/vuln"，与备份 manifest 的 path 前缀一致。
    """
    if not backup.exists():
        return {}, {}, None
    mpath = backup / "manifest-sha256.json"
    sha_by_side = {}
    manifest_sha = None
    if mpath.exists():
        raw = mpath.read_bytes()
        manifest_sha = hashlib.sha256(raw).hexdigest()
        mf = json.loads(raw.decode("utf-8"))
        for f in mf.get("files", []):
            p = f["path"].replace("\\", "/")
            parts = p.split("/")
            if len(parts) >= 3 and parts[1] in ("vuln", "fixed"):
                key = f"{parts[0]}/{parts[1]}"
                rel = "/".join(parts[2:])
                sha_by_side.setdefault(key, {})[rel] = f["sha256"]
    corpus = backup / "corpus"
    dirs = {}
    if corpus.exists():
        for cve_dir in sorted(corpus.iterdir()):
            if not cve_dir.is_dir():
                continue
            for side in ("vuln", "fixed"):
                sd = cve_dir / side
                # 只收录非空 side：空目录无源码可取证，应标 unavailable 而非误报不一致
                if sd.is_dir() and any(x.is_file() for x in sd.rglob("*")):
                    dirs[(cve_dir.name, side)] = sd
    return dirs, sha_by_side, manifest_sha


def verify_backup_side(side_dir: Path, expected: dict) -> list:
    """校验备份 side 目录：文件集合与每个文件原始 SHA 必须与 manifest 一致。"""
    errors = []
    actual = {}
    for p in sorted(side_dir.rglob("*")):
        if p.is_file():
            actual[p.relative_to(side_dir).as_posix()] = hashlib.sha256(
                p.read_bytes()).hexdigest()
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing:
        errors.append(f"备份缺文件: {missing[:3]}")
    if extra:
        errors.append(f"备份多出文件: {extra[:3]}")
    for rel, want in expected.items():
        if rel in actual and actual[rel] != want:
            errors.append(f"备份 SHA 不符: {rel}")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", required=True,
                    help="JSON 数组文件或逗号分隔的 sample_id 列表")
    ap.add_argument("--backup", type=Path, default=DEFAULT_BACKUP)
    ap.add_argument("--out", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/historical_v1_source_manifest.jsonl")
    args = ap.parse_args()

    sp = Path(args.samples)
    if sp.exists():
        samples = json.loads(sp.read_text(encoding="utf-8"))
    else:
        samples = [s for s in args.samples.split(",") if s]

    backup_dirs, backup_sha, manifest_sha = load_backup(args.backup)
    backup_verified = 0
    rows = []
    with tempfile.TemporaryDirectory() as td:
        hist_root = export_historical_corpus(Path(td))
        for cve in samples:
            for side in ("vuln", "fixed"):
                src = hist_root / cve / side
                if src.is_dir():
                    rows.append({
                        "sample_id": cve, "side": side,
                        "tree_sha256_lf": tree_sha_lf(src),
                        "evidence_type": "git-commit",
                        "evidence_ref": f"{HISTORICAL_COMMIT[:7]}:cpg/corpus_pairs/{cve}/{side}",
                        "historical_commit": HISTORICAL_COMMIT,
                    })
                    continue
                bdir = backup_dirs.get((cve, side))
                if bdir is not None:
                    expected = backup_sha.get(f"{cve}/{side}", {})
                    if not expected:
                        raise RuntimeError(
                            f"备份 manifest 无 {cve}/{side} 的条目，不得按备份取证")
                    errs = verify_backup_side(bdir, expected)
                    if errs:
                        raise RuntimeError(
                            f"备份完整性校验失败 {cve}/{side}: {errs[:3]}")
                    backup_verified += 1
                    rows.append({
                        "sample_id": cve, "side": side,
                        "tree_sha256_lf": tree_sha_lf(bdir),
                        "evidence_type": "private-backup-manifest",
                        # 逻辑引用：不含本机绝对路径（避免泄露用户名且可供第三方解析）
                        "evidence_ref": (
                            f"backup-manifest:{manifest_sha}/{cve}/{side}"
                            if manifest_sha else f"backup-manifest:unknown/{cve}/{side}"),
                        "backup_manifest_sha256": manifest_sha,
                        "backup_files_verified": len(expected),
                        "historical_commit": None,
                    })
                    continue
                rows.append({
                    "sample_id": cve, "side": side,
                    "tree_sha256_lf": None,
                    "evidence_type": "unavailable",
                    "evidence_ref": None,
                    "historical_commit": None,
                })
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                        encoding="utf-8")
    from collections import Counter
    print(f"写出 {len(rows)} 条 → {args.out}")
    print("证据分布:", dict(Counter(r["evidence_type"] for r in rows)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
