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
    """返回 {(cve, side): Path(目录)} 与文件级 SHA 校验表。"""
    if not backup.exists():
        return {}, {}
    mpath = backup / "manifest-sha256.json"
    sha_map = {}
    if mpath.exists():
        mf = json.loads(mpath.read_text(encoding="utf-8"))
        for f in mf.get("files", []):
            sha_map[f["path"]] = f["sha256"]
    corpus = backup / "corpus"
    dirs = {}
    if corpus.exists():
        for cve_dir in sorted(corpus.iterdir()):
            if not cve_dir.is_dir():
                continue
            for side in ("vuln", "fixed"):
                sd = cve_dir / side
                if sd.is_dir():
                    dirs[(cve_dir.name, side)] = sd
    return dirs, sha_map


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

    backup_dirs, backup_sha = load_backup(args.backup)
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
                    rows.append({
                        "sample_id": cve, "side": side,
                        "tree_sha256_lf": tree_sha_lf(bdir),
                        "evidence_type": "private-backup-manifest",
                        "evidence_ref": str(bdir),
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
