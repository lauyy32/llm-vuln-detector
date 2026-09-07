# -*- coding: utf-8 -*-
"""通用 status-aware 语料重建（corpus-v2），Codex 最终裁决的 rebuild_pair()。

设计原则（Codex 裁决）：
- **不出现任何 CVE 专用分支**——四类失效模式（modified/added/removed/renamed/copied）
  统一按 upstream status 机械处理；
- 用**本地 Git 对象**（`git diff-tree --name-status` + `git show <commit>:<path>`），
  不用 checkout 工作树、不用 API patch 字段；
- **preflight**（不可推迟）：单 parent 断言、commit 可达、大小写路径碰撞、跨语言检测；
- **unexpected missing 零容忍**：任何本应存在但取不到的 blob 立即失败；
- 写入独立 `corpus-v2/`，**不覆盖 v1**；保存 parent/fix SHA、路径状态、blob SHA、生成器 SHA。

用法：
    python cpg/ablation/rebuild_pair.py --cves CVE-... [--out cpg/corpus-v2]
    python cpg/ablation/rebuild_pair.py --all-missing   # 重建 14 例缺文件样本
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS_RAW = ROOT / "cpg" / "corpus_raw"
CORPUS_V2 = ROOT / "cpg" / "corpus-v2"
sys.path.insert(0, str(ROOT))
from cpg.ablation.upstream_manifest import read_meta  # noqa: E402


def git(args, cwd, timeout=180):
    r = subprocess.run(["git"] + args, cwd=str(cwd), capture_output=True,
                       text=True, encoding="utf-8", timeout=timeout)
    return r


def clone_dir(repo_slug):
    return CORPUS_RAW / repo_slug.replace("/", "__")


def preflight(repo_slug, fix_commit):
    """返回 (parent_sha, error)。单 parent 断言 + commit 可达。"""
    cd = clone_dir(repo_slug)
    if not cd.exists():
        return None, f"NO_CLONE: {cd.name}"
    # commit 可达
    r = git(["cat-file", "-e", fix_commit], cd)
    if r.returncode != 0:
        return None, "FIX_COMMIT_UNREACHABLE"
    # parent 数量（fail-closed：必须单 parent）
    r = git(["rev-list", "--parents", "-n", "1", fix_commit], cd)
    parts = r.stdout.split()
    if len(parts) != 2:
        return None, f"PARENT_COUNT={len(parts)-1} (须单 parent)"
    return parts[1], None


def name_status(repo_slug, parent, fix):
    """git diff-tree --name-status，返回 [(status, path, prev_path), ...]。"""
    cd = clone_dir(repo_slug)
    r = git(["diff-tree", "-r", "-M", "-C", "--name-status", parent, fix], cd)
    if r.returncode != 0:
        return None, f"DIFF_TREE_FAIL: {r.stderr[:80]}"
    entries = []
    for line in r.stdout.splitlines():
        if not line:
            continue
        # status 后跟 \t；R/C 有两个路径
        parts = line.split("\t")
        st = parts[0][0]  # M/A/D/R/C/T...
        paths = parts[1:]
        entries.append((st, paths[-1], paths[0] if len(paths) > 1 else None))
    return entries, None


def show_blob(repo_slug, commit, path, retries=3):
    """git show <commit>:<path> 取 blob；shallow/blob:none clone 触发 lazy fetch，
    失败时显式 fetch 该 commit 后重试。"""
    cd = clone_dir(repo_slug)
    for attempt in range(retries):
        r = git(["show", f"{commit}:{path}"], cd)
        if r.returncode == 0:
            return r.stdout.encode("utf-8")
        # lazy fetch 竞态/超时：显式 fetch 该 commit（补齐 blob）后重试
        git(["fetch", "origin", commit], cd, timeout=300)
    return None


def rebuild_pair(cve, out_root=CORPUS_V2, detect_casemap=True):
    """通用重建。返回 {status, ...}。"""
    meta = read_meta(cve)
    if "_error" in meta:
        return {"status": "META_ERR", "error": meta["_error"]}
    repo = meta.get("repo_slug", "")
    fix = meta.get("fix_commit", "")
    if not repo or not fix:
        return {"status": "META_MISSING"}

    parent, err = preflight(repo, fix)
    if err:
        return {"status": "PREFLIGHT_FAIL", "error": err}

    entries, err = name_status(repo, parent, fix)
    if err:
        return {"status": "DIFF_FAIL", "error": err}

    py_entries = [(st, p, prev) for st, p, prev in entries
                  if p.endswith(".py") or (prev and prev.endswith(".py"))]
    # 跨语言检测：无 .py 改动 → 拒绝生成 Python pair
    if not py_entries:
        return {"status": "CROSS_LANGUAGE_OUT_OF_SCOPE",
                "note": "fix 无 .py 改动，无法生成 Python 补丁对"}

    # 大小写路径碰撞检测（NTFS 大小写不敏感）
    if detect_casemap:
        lowered = {}
        for _, p, prev in py_entries:
            for x in (p, prev):
                if x:
                    k = x.lower()
                    if k in lowered and lowered[k] != x:
                        return {"status": "CASEMAP_COLLISION",
                                "error": f"{lowered[k]} vs {x}"}
                    lowered[k] = x

    out_dir = out_root / cve
    vuln_dir = out_dir / "vuln"
    fixed_dir = out_dir / "fixed"
    if out_dir.exists():
        import shutil
        shutil.rmtree(out_dir)
    vuln_dir.mkdir(parents=True, exist_ok=True)
    fixed_dir.mkdir(parents=True, exist_ok=True)

    manifest = {"cve_id": cve, "repo": repo, "fix_commit": fix,
                "parent_commit": parent, "generator": "rebuild_pair.py",
                "files": []}
    missing = []
    for st, path, prev in py_entries:
        if st in ("M", "T"):  # modified/type-change：两侧都有
            v = show_blob(repo, parent, path)
            f = show_blob(repo, fix, path)
            if v is None or f is None:
                missing.append((path, st)); continue
            write(vuln_dir / path, v); write(fixed_dir / path, f)
            manifest["files"].append({"path": path, "status": st,
                                      "vuln_sha": sha(v), "fixed_sha": sha(f)})
        elif st == "A":  # added：仅 fixed
            f = show_blob(repo, fix, path)
            if f is None:
                missing.append((path, st)); continue
            write(fixed_dir / path, f)
            manifest["files"].append({"path": path, "status": st,
                                      "fixed_sha": sha(f)})
        elif st == "D":  # removed：仅 vuln
            v = show_blob(repo, parent, path)
            if v is None:
                missing.append((path, st)); continue
            write(vuln_dir / path, v)
            manifest["files"].append({"path": path, "status": st,
                                      "vuln_sha": sha(v)})
        elif st == "R":  # renamed：prev 在 vuln，new 在 fixed
            v = show_blob(repo, parent, prev) if prev else None
            f = show_blob(repo, fix, path)
            if v is None or f is None:
                missing.append((path, st)); continue
            write(vuln_dir / prev, v); write(fixed_dir / path, f)
            manifest["files"].append({"path": path, "prev": prev, "status": st,
                                      "vuln_sha": sha(v), "fixed_sha": sha(f)})
        elif st == "C":  # copied：源保留 + 目标
            f = show_blob(repo, fix, path)
            if f is None:
                missing.append((path, st)); continue
            write(fixed_dir / path, f)
            if prev:
                v = show_blob(repo, parent, prev)
                if v is not None:
                    write(vuln_dir / prev, v)
            manifest["files"].append({"path": path, "prev": prev, "status": st,
                                      "fixed_sha": sha(f)})

    if missing:
        import shutil
        shutil.rmtree(out_dir, ignore_errors=True)
        return {"status": "UNEXPECTED_MISSING", "missing": missing}

    # 写 manifest（含 meta 精简）
    mf = {"cve_id": cve, "repo_slug": repo, "fix_commit": fix,
          "cwes": meta.get("cwes"), "summary": meta.get("summary", "")[:200],
          "label": "vulnerable_before_fixed"}
    (out_dir / "meta.json").write_text(json.dumps(mf, ensure_ascii=False, indent=2),
                                       encoding="utf-8")
    (out_dir / "rebuild_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"status": "REBUILT", "n_files": len(manifest["files"]),
            "out": str(out_dir)}


def write(dst, data):
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(data)


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cves", nargs="+")
    ap.add_argument("--all-missing", action="store_true",
                    help="重建 14 例缺文件样本")
    ap.add_argument("--out", default=str(CORPUS_V2))
    args = ap.parse_args()

    cves = args.cves or []
    if args.all_missing:
        audit = json.loads((ROOT / "cpg/ablation/.work/upstream_five_state.json")
                           .read_text(encoding="utf-8"))
        missing = [c for c, r in audit.items()
                   if r["status"] == "CORPUS_ERROR"
                   and not any("EXTRA" in str(m[0]) for m in r["mismatches"])]
        cves = sorted(missing)

    out_root = Path(args.out)
    for cve in cves:
        r = rebuild_pair(cve, out_root)
        print(f"{cve}: {r['status']}"
              + (f" ({r.get('n_files')} 文件)" if r["status"] == "REBUILT" else
                 f" {r.get('error', r.get('note', r.get('missing', '')))}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
