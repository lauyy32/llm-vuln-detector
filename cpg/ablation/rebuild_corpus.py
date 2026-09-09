# -*- coding: utf-8 -*-
"""corpus-v3 统一重建（Code plan 第1阶段）。

从上游 parent/fix 用同一个通用生成器重建全部 83 个 eligible 样本，不再维护
"77 v1 + 14 v2" 混合物。解决 Repo state P0：
- git show 用 text=False 保原始 blob 字节（不因 UTF-8 编解码改换行/非 UTF-8 内容）；
- 元数据从 dataset_d1.jsonl 读取，不依赖旧 corpus_pairs/<CVE>/meta.json；
- M/A/D/R/C/T 全部显式处理，未知状态直接失败；
- 输出先写独立临时目录，完整验证后原子提升；
- 任一例失败，批次退出非零（main 不无条件返回 0）；
- 两个跨语言样本只写排除记录，不生成伪 Python pair；
- 禁止任何 CVE 专用分支。

用法：
    python cpg/ablation/rebuild_corpus.py --dataset cpg/dataset_d1.jsonl \
        --all-eligible --from-zero --out cpg/corpus-v3 \
        --manifest cpg/ablation/artifacts/corpus_v3_manifest.json
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import sysconfig
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS_RAW = ROOT / "cpg" / "corpus_raw"
GENERATOR = "rebuild_corpus.py"

# 跨语言排除样本（fix 无 .py 改动，Python 侧不可观测修复）
CROSS_LANGUAGE = {"CVE-2026-70486", "CVE-2026-70492"}

# 唯一 fail 语义的未知状态（不在 M/A/D/R/C/T 内一律失败）
KNOWN_STATUS = {"M", "A", "D", "R", "C", "T"}


@dataclass
class SampleSpec:
    sample_id: str
    repo_slug: str
    fix_commit: str
    cwes: list = field(default_factory=list)
    summary: str = ""
    label: str = "vulnerable_before_fixed"


def load_dataset_rows(dataset_path: Path) -> list[dict]:
    rows = []
    for line in dataset_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def resolve_sample_spec(rows: list[dict], sample_id: str) -> SampleSpec:
    for r in rows:
        if r.get("cve_id") == sample_id:
            return SampleSpec(
                sample_id=sample_id,
                repo_slug=r.get("repo_slug", ""),
                fix_commit=r.get("fix_commit", ""),
                cwes=r.get("cwes") or [],
                summary=r.get("summary") or "",
                label=r.get("label") or "vulnerable_before_fixed",
            )
    raise KeyError(f"sample {sample_id} 不在 dataset 中")


def clone_dir(repo_slug: str) -> Path:
    return CORPUS_RAW / repo_slug.replace("/", "__")


def git_bytes(args: list, cwd: Path, timeout: int = 300):
    """git 命令，返回 stdout bytes（text=False 保字节）；失败返回 None。"""
    r = subprocess.run(["git"] + args, cwd=str(cwd), capture_output=True, timeout=timeout)
    if r.returncode != 0:
        return None
    return r.stdout


def git_text(args: list, cwd: Path, timeout: int = 300):
    r = subprocess.run(["git"] + args, cwd=str(cwd), capture_output=True,
                       text=True, encoding="utf-8", errors="replace", timeout=timeout)
    if r.returncode != 0:
        return None
    return r.stdout


def preflight_repo(spec: SampleSpec) -> tuple[str, str]:
    """返回 (parent_sha, error)。单 parent 断言 + commit 可达。"""
    if not spec.repo_slug or not spec.fix_commit:
        return "", "META_MISSING"
    cd = clone_dir(spec.repo_slug)
    if not cd.exists():
        return "", f"NO_CLONE:{spec.repo_slug}"
    if git_bytes(["cat-file", "-e", spec.fix_commit], cd) is None:
        return "", "FIX_COMMIT_UNREACHABLE"
    out = git_text(["rev-list", "--parents", "-n", "1", spec.fix_commit], cd)
    if out is None:
        return "", "REV_LIST_FAIL"
    parts = out.split()
    if len(parts) != 2:
        return "", f"PARENT_COUNT={len(parts)-1}"
    return parts[1], ""


def name_status(repo_slug: str, parent: str, fix: str) -> tuple[list, str]:
    """git diff-tree -r -M -C -z --name-status，NUL 分隔解析。

    返回 [(status, path, prev_path), ...]，status 取单字符 M/A/D/R/C/T。
    """
    cd = clone_dir(repo_slug)
    raw = git_bytes(["diff-tree", "-r", "-M", "-C", "-z", "--name-status",
                     parent, fix], cd)
    if raw is None:
        return [], "DIFF_TREE_FAIL"
    entries = []
    # NUL 分隔：status\0path\0 或 R100\0old\0new\0
    fields = raw.split(b"\0")
    i = 0
    while i < len(fields):
        f = fields[i]
        if not f:
            i += 1
            continue
        st = f[:1].decode("ascii", "replace")
        if st in ("R", "C"):
            if i + 2 >= len(fields):
                return [], f"PARSE_ERR:{st}"
            old = fields[i + 1].decode("utf-8", "replace")
            new = fields[i + 2].decode("utf-8", "replace")
            entries.append((st, new, old))
            i += 3
        else:
            if i + 1 >= len(fields):
                return [], f"PARSE_ERR:{st}"
            path = fields[i + 1].decode("utf-8", "replace")
            entries.append((st, path, None))
            i += 2
    return entries, ""


def read_blob_bytes(repo_slug: str, commit: str, path: str) -> bytes:
    """git show text=False 保原始字节；缺 blob 返回 None。"""
    cd = clone_dir(repo_slug)
    return git_bytes(["show", f"{commit}:{path}"], cd)


def _parse_hunk_range(s: str):
    """解析 hunk header 的 -a,b / +c,d，返回 (start, count)。"""
    s = s[1:] if s and s[0] in "-+" else s
    if "," in s:
        lo, cnt = s.split(",")
        return int(lo), int(cnt)
    return int(s), 1


def _changed_hunks(repo_slug: str, parent: str, fix: str, path: str) -> dict:
    """git diff -U0 获取逐 hunk 配对坐标（fail-closed）。

    返回 {"hunks": [{"old_start","old_count","new_start","new_count"}, ...]}：
    - **保留 count=0**：纯插入 old_count=0、纯删除 new_count=0，零长度一侧的边界锚点
      （如 `@@ -14,0 +15 @@` 的 old 第 14 行之后）不再丢失；
    - 两个独立列表会丢失"第几个 old hunk 对应第几个 new hunk"，故改为逐 hunk 对象数组；
    - git diff 失败或 hunk header 解析失败一律抛错，禁止退化为"无 hunk"。
    """
    cd = clone_dir(repo_slug)
    out = git_text(["diff", "-U0", parent, fix, "--", path], cd)
    if out is None:
        raise RuntimeError(f"git diff 失败（fail-closed）: {path}")
    hunks = []
    for line in out.splitlines():
        if not line.startswith("@@"):
            continue
        try:
            hdr = line.split("@@")[1].strip()
            old_part, new_part = hdr.split()[:2]
            old_lo, old_cnt = _parse_hunk_range(old_part)
            new_lo, new_cnt = _parse_hunk_range(new_part)
        except (ValueError, IndexError) as e:
            raise RuntimeError(f"hunk header 解析失败（fail-closed）: {line!r}") from e
        hunks.append({"old_start": old_lo, "old_count": old_cnt,
                      "new_start": new_lo, "new_count": new_cnt})
    return {"hunks": hunks}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def norm_lf(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def build_pair_in_staging(spec: SampleSpec, parent: str, staging_dir: Path) -> dict:
    """按 upstream status 从 parent/fix 取 blob 写入 staging/vuln、staging/fixed。"""
    entries, err = name_status(spec.repo_slug, parent, spec.fix_commit)
    if err:
        return {"status": "DIFF_FAIL", "error": err}

    py_entries = [(st, p, prev) for st, p, prev in entries
                  if p.endswith(".py") or (prev and prev.endswith(".py"))]
    if not py_entries:
        return {"status": "CROSS_LANGUAGE_OUT_OF_SCOPE",
                "error": "fix 无 .py 改动"}

    # 大小写碰撞检测（NTFS 不敏感）
    lowered = {}
    for _, p, prev in py_entries:
        for x in (p, prev):
            if x:
                k = x.lower()
                if k in lowered and lowered[k] != x:
                    return {"status": "CASEMAP_COLLISION",
                            "error": f"{lowered[k]} vs {x}"}
                lowered[k] = x

    vuln_dir = staging_dir / "vuln"
    fixed_dir = staging_dir / "fixed"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    fixed_dir.mkdir(parents=True, exist_ok=True)

    files = []
    for st, path, prev in py_entries:
        rec = {"path": path, "status": st}
        if st in ("M", "T"):
            v = read_blob_bytes(spec.repo_slug, parent, path)
            f = read_blob_bytes(spec.repo_slug, spec.fix_commit, path)
            if v is None or f is None:
                return {"status": "UNEXPECTED_MISSING", "error": f"{path} blob 缺失"}
            (vuln_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (fixed_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (vuln_dir / path).write_bytes(v)
            (fixed_dir / path).write_bytes(f)
            rec.update(vuln_sha=sha256(v), fixed_sha=sha256(f),
                       changed_hunks=_changed_hunks(spec.repo_slug, parent, spec.fix_commit, path))
        elif st == "A":
            f = read_blob_bytes(spec.repo_slug, spec.fix_commit, path)
            if f is None:
                return {"status": "UNEXPECTED_MISSING", "error": f"{path} blob 缺失"}
            (fixed_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (fixed_dir / path).write_bytes(f)
            n_lines = len(f.decode("utf-8", errors="replace").splitlines())
            # added：parent 侧无（old_count=0）、fix 侧整文件
            rec.update(fixed_sha=sha256(f), changed_hunks={"hunks": [
                {"old_start": 0, "old_count": 0, "new_start": 1, "new_count": n_lines}]})
        elif st == "D":
            v = read_blob_bytes(spec.repo_slug, parent, path)
            if v is None:
                return {"status": "UNEXPECTED_MISSING", "error": f"{path} blob 缺失"}
            (vuln_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (vuln_dir / path).write_bytes(v)
            n_lines = len(v.decode("utf-8", errors="replace").splitlines())
            # removed：parent 侧整文件、fix 侧无（new_count=0）
            rec.update(vuln_sha=sha256(v), changed_hunks={"hunks": [
                {"old_start": 1, "old_count": n_lines, "new_start": 0, "new_count": 0}]})
        elif st == "R":
            v = read_blob_bytes(spec.repo_slug, parent, prev) if prev else None
            f = read_blob_bytes(spec.repo_slug, spec.fix_commit, path)
            if v is None or f is None:
                return {"status": "UNEXPECTED_MISSING", "error": f"{path} blob 缺失"}
            (vuln_dir / prev).parent.mkdir(parents=True, exist_ok=True)
            (fixed_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (vuln_dir / prev).write_bytes(v)
            (fixed_dir / path).write_bytes(f)
            rec.update(prev=prev, vuln_sha=sha256(v), fixed_sha=sha256(f),
                       changed_hunks=_changed_hunks(spec.repo_slug, parent, spec.fix_commit, path))
        elif st == "C":
            f = read_blob_bytes(spec.repo_slug, spec.fix_commit, path)
            if f is None:
                return {"status": "UNEXPECTED_MISSING", "error": f"{path} blob 缺失"}
            (fixed_dir / path).parent.mkdir(parents=True, exist_ok=True)
            (fixed_dir / path).write_bytes(f)
            if prev:
                v = read_blob_bytes(spec.repo_slug, parent, prev)
                if v is not None:
                    (vuln_dir / prev).parent.mkdir(parents=True, exist_ok=True)
                    (vuln_dir / prev).write_bytes(v)
            rec.update(prev=prev, fixed_sha=sha256(f),
                       changed_hunks=_changed_hunks(spec.repo_slug, parent, spec.fix_commit, path))
        else:
            return {"status": "UNKNOWN_STATUS", "error": f"status={st} path={path}"}
        files.append(rec)

    return {"status": "BUILT", "files": files}


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


def atomic_promote(staging_dir: Path, final_dir: Path):
    if final_dir.exists():
        shutil.rmtree(final_dir)
    staging_dir.replace(final_dir)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True, type=Path)
    ap.add_argument("--all-eligible", action="store_true")
    ap.add_argument("--from-zero", action="store_true", help="重建前清空输出目录")
    ap.add_argument("--out", default=str(ROOT / "cpg" / "corpus-v3"), type=Path)
    ap.add_argument("--manifest", default=str(ROOT / "cpg/ablation/artifacts/corpus_v3_manifest.json"), type=Path)
    ap.add_argument("--cves", nargs="+", help="只重建指定样本（测试用）")
    args = ap.parse_args()

    rows = load_dataset_rows(args.dataset)
    all_ids = {r["cve_id"] for r in rows if r.get("cve_id")}
    if args.cves:
        target_ids = [c for c in args.cves if c in all_ids]
    else:
        target_ids = sorted(all_ids - CROSS_LANGUAGE)

    out_root = args.out
    if args.from_zero and out_root.exists():
        shutil.rmtree(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema_version": "corpus-v3/1",
        "generator": GENERATOR,
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "python_version": sys.version.split()[0],
        "git_version": (git_text(["version"], CORPUS_RAW) or "").strip(),
        "dataset": str(args.dataset),
        "eligible_total": len(target_ids),
        "samples": [],
        "exclusions": [],
    }

    failures = []
    for cve in target_ids:
        spec = resolve_sample_spec(rows, cve)
        parent, err = preflight_repo(spec)
        if err:
            # 多父提交（merge）→ 复合提交，写排除记录，不算基础设施失败
            if err.startswith("PARENT_COUNT"):
                manifest["exclusions"].append(
                    {"sample_id": cve, "reason": "COMPOSITE_FIX_COMMIT",
                     "detail": err})
                print(f"{cve}: EXCLUDED(COMPOSITE) {err}")
                continue
            failures.append((cve, err))
            print(f"{cve}: PREFLIGHT_FAIL {err}")
            continue
        staging = out_root / f".tmp_{cve}"
        if staging.exists():
            shutil.rmtree(staging)
        staging.mkdir(parents=True, exist_ok=True)
        r = build_pair_in_staging(spec, parent, staging)
        if r["status"] == "CROSS_LANGUAGE_OUT_OF_SCOPE":
            manifest["exclusions"].append({"sample_id": cve, "reason": r["error"]})
            print(f"{cve}: EXCLUDED {r['error']}")
            shutil.rmtree(staging, ignore_errors=True)
            continue
        if r["status"] != "BUILT":
            failures.append((cve, f"{r['status']}: {r.get('error')}"))
            print(f"{cve}: {r['status']} {r.get('error')}")
            shutil.rmtree(staging, ignore_errors=True)
            continue
        final = out_root / cve
        atomic_promote(staging, final)
        vuln_ts = tree_sha_lf(final / "vuln")
        fixed_ts = tree_sha_lf(final / "fixed")
        pair_manifest = {
            "sample_id": cve, "repo_slug": spec.repo_slug,
            "parent_commit": parent, "fix_commit": spec.fix_commit,
            "cwes": spec.cwes, "summary": spec.summary[:200],
            "vuln_tree_sha256_lf": vuln_ts, "fixed_tree_sha256_lf": fixed_ts,
            "files": r["files"],
        }
        (final / "pair_manifest.json").write_text(
            json.dumps(pair_manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        manifest["samples"].append(pair_manifest)
        print(f"{cve}: REBUILT ({len(r['files'])} 文件)")

    manifest["n_rebuilt"] = len(manifest["samples"])
    manifest["n_excluded"] = len(manifest["exclusions"])
    manifest["n_failed"] = len(failures)
    manifest_path = args.manifest
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[manifest] {manifest_path}")
    print(f"重建 {manifest['n_rebuilt']} / 排除 {manifest['n_excluded']} / 失败 {manifest['n_failed']}")

    if failures:
        print("\n[FAIL] 存在失败样本，批次退出非零:")
        for cve, e in failures:
            print(f"  {cve}: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
