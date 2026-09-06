# -*- coding: utf-8 -*-
"""上游投影 manifest 测量（只读，不生成实验刺激/不启动标注/不调用模型）。

用法：
    python cpg/ablation/upstream_manifest.py [--cves CVE-...] [--out manifest.json] [--no-fetch]

作用：
    对每个 CVE，读 corpus meta.json 的 fix_commit/repo_slug，fetch 上游 commit
    （GitHub REST API，公开只读），机械提取 Python 投影（所有 .py，含 tests、含 .pyi），
    与 corpus 的 .py 文件集做双向差集比对，输出 manifest 初版（仅机器可自动判定的字段）。

    人工字段（advisory/PR 判定、三布尔、三源一致性、标注者）留空待人工补，不在此脚本伪造。

API 说明：
    GET /repos/{owner}/{repo}/commits/{sha} 返回 files[]（filename/status/additions/deletions）
    与 parents[]（父提交 sha）。未认证配额 60/h，15 次调用足够。
    404 / 仓库改名 / 已删除 → 该样本标 unverifiable，不猜测、不用语料顶替。
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "cpg" / "corpus_pairs"
CACHE = ROOT / "cpg" / "ablation" / ".work" / "upstream_api_cache"


def curl_json(url: str, timeout: int = 40) -> dict:
    """通过 curl 走已配置代理 fetch JSON；返回 dict 或 {'_error': msg}。"""
    try:
        r = subprocess.run(
            ["curl", "-sS", "--max-time", str(timeout), url],
            capture_output=True, text=True, encoding="utf-8",
        )
    except Exception as ex:
        return {"_error": f"curl 调用失败: {ex}"}
    if r.returncode != 0:
        return {"_error": f"curl rc={r.returncode} stderr={r.stderr.strip()[:120]}"}
    out = r.stdout.strip()
    if not out:
        return {"_error": "空响应"}
    try:
        return json.loads(out)
    except Exception:
        return {"_error": f"非 JSON 响应前 120 字: {out[:120]}"}


def api_url(repo_slug: str, sha: str) -> str:
    return f"https://api.github.com/repos/{repo_slug}/commits/{sha}"


def read_meta(cve: str) -> dict:
    p = CORPUS / cve / "meta.json"
    if not p.exists():
        return {"_error": f"无 meta.json: {p}"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as ex:
        return {"_error": f"meta.json 解析失败: {ex}"}


def corpus_py_files(meta: dict) -> set:
    """从 meta.json 的 files 列表提取 corpus 的 .py 文件集（去 vuln/fixed 前缀、去重）。"""
    out = set()
    for f in meta.get("files", []):
        # 形如 corpus_pairs\\CVE-xxx\\fixed\\a\\b.py 或含 vuln/
        norm = f.replace("\\", "/")
        # 去掉 "corpus_pairs/CVE-xxx/fixed/" 或 "/vuln/" 前缀
        for seg in ("/fixed/", "/vuln/"):
            if seg in norm:
                norm = norm.split(seg, 1)[1]
                break
        if norm.endswith(".py"):
            out.add(norm)
    return out


def upstream_py_files(files: list) -> set:
    """上游 commit files[] 的 Python 投影 = 所有 .py（含 tests、含 .pyi）。"""
    return {f["filename"] for f in files if f["filename"].endswith(".py")}


def classify_files(files: list) -> dict:
    py, nonpy = [], []
    added = deleted = renamed = 0
    for f in files:
        if f["filename"].endswith(".py"):
            py.append(f)
        else:
            nonpy.append(f["filename"])
        st = f.get("status", "")
        if st == "added":
            added += 1
        elif st == "removed":
            deleted += 1
        elif st == "renamed":
            renamed += 1
    return {"py": py, "nonpy": nonpy, "added": added,
            "deleted": deleted, "renamed": renamed}


def tokens_estimate(lines: int) -> int:
    """粗略 token 估算（改动行数 × 8，明确 PROXY；后续接真实 tokenizer 重标定）。"""
    return max(1, int(lines * 8))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cves", nargs="+", required=True)
    ap.add_argument("--out", default="cpg/ablation/.work/upstream_manifest.json")
    ap.add_argument("--no-fetch", action="store_true",
                    help="只读缓存，不发起网络请求")
    args = ap.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = {"generated_from": {"git_commit": subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True,
        encoding="utf-8").stdout.strip()}, "samples": {}}

    rows = []  # 汇总表行
    for cve in args.cves:
        meta = read_meta(cve)
        if "_error" in meta:
            manifest["samples"][cve] = {"error": meta["_error"]}
            rows.append((cve, "META_ERR", "", "", "", "", "", ""))
            continue

        repo = meta.get("repo_slug", "")
        sha = meta.get("fix_commit", "")
        if not repo or not sha:
            manifest["samples"][cve] = {"error": "meta 缺 repo_slug/fix_commit"}
            rows.append((cve, "META_MISSING", "", "", "", "", "", ""))
            continue

        corpus_py = corpus_py_files(meta)

        # fetch（带缓存）
        cache_file = CACHE / f"{cve}.json"
        d = None
        if args.no_fetch and cache_file.exists():
            d = json.loads(cache_file.read_text(encoding="utf-8"))
        elif cache_file.exists():
            d = json.loads(cache_file.read_text(encoding="utf-8"))
        else:
            d = curl_json(api_url(repo, sha))
            if "_error" not in d:
                cache_file.write_text(json.dumps(d, ensure_ascii=False),
                                      encoding="utf-8")

        if d is None or "_error" in d:
            err = (d or {}).get("_error", "fetch 失败")
            manifest["samples"][cve] = {"repo": repo, "fix_commit": sha,
                                        "status": "unverifiable", "error": err}
            rows.append((cve, "UNVERIFIABLE", repo, sha[:12], "", "", "", err[:40]))
            continue

        if "files" not in d or "parents" not in d:
            msg = d.get("message", "无 files/parents 字段")
            manifest["samples"][cve] = {"repo": repo, "fix_commit": sha,
                                        "status": "unverifiable", "error": msg}
            rows.append((cve, "UNVERIFIABLE", repo, sha[:12], "", "", "", msg[:40]))
            continue

        files = d["files"]
        parents = [p["sha"] for p in d.get("parents", [])]
        parents_count = len(parents)
        # git 语义 merge = parents_count > 1；message 含 Merge 仅是复合提交线索
        is_merge = parents_count > 1
        msg_head = (d.get("commit", {}).get("message", "") or "").split("\n")[0]

        cls = classify_files(files)
        up_py = upstream_py_files(files)
        p_minus_c = sorted(up_py - corpus_py)   # 投影有、语料无
        c_minus_p = sorted(corpus_py - up_py)   # 语料有、投影无
        delta_zero = (len(p_minus_c) == 0 and len(c_minus_p) == 0)

        total_lines = sum(f.get("additions", 0) + f.get("deletions", 0)
                          for f in cls["py"])

        sample = {
            "cve_id": cve, "repository": repo, "fix_commit": sha,
            "parent_commits": parents, "parents_count": parents_count,
            "is_merge": is_merge, "commit_message_head": msg_head,
            "upstream_total_files": len(files),
            "python_projection_files": sorted(up_py),
            "python_projection_n": len(up_py),
            "non_python_excluded_n": len(cls["nonpy"]),
            "added/deleted/renamed": {"added": cls["added"],
                                      "deleted": cls["deleted"],
                                      "renamed": cls["renamed"]},
            "corpus_py_n": len(corpus_py),
            "delta_p_minus_c": p_minus_c, "delta_c_minus_p": c_minus_p,
            "delta_zero": delta_zero,
            "changed_lines": total_lines,
            "token_estimate": tokens_estimate(total_lines),
            # 以下字段待人工补，脚本不伪造：
            "advisory_url": "", "selected_base_commit": "",
            "selected_base_reason": "", "co_fixed_cves": [],
            "composite_fix_commit": None,
            "security_critical_non_python_change": None,
            "python_projection_sufficient": None,
            "candidate_patch_base_commit": "", "prompt_source_commit": "",
            "cpg_context_source_commit": "", "cpg_rebuild_required": None,
            "relevant_source_files_byte_equivalent": None,
            "patch_apply_clean_to_prompt_source": None,
            "reviewer_1": "", "reviewer_2": "", "adjudication": "",
            "exclusion_reason": "",
        }
        manifest["samples"][cve] = sample
        rows.append((cve, "OK", repo, sha[:12], str(len(up_py)),
                     str(len(corpus_py)), str(len(p_minus_c)) + "/" + str(len(c_minus_p)),
                     "Δ=0" if delta_zero else "Δ≠0",
                     str(sample["token_estimate"])))

    # 汇总打印
    hdr = f"{'CVE':<17} {'状态':<13} {'repo':<26} {'commit':<11} {'PyP':>3} {'PyC':>3} {'P\\C/C\\P':>7} {'Δ':<5} {'tok':>6}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        if r[1] == "OK":
            cve, st, repo, sha, pyp, pyc, delta, dz, tok = r
            print(f"{cve:<17} {st:<13} {repo[:25]:<26} {sha:<11} {pyp:>3} {pyc:>3} {delta:>7} {dz:<5} {tok:>6}")
        else:
            cve, st, a, b, c_, d_, e_, f_ = r
            print(f"{cve:<17} {st:<13} {str(a)[:24]:<26} {str(b):<11}   {str(f_)[:58]}")

    n_ok = sum(1 for r in rows if r[1] == "OK")
    n_delta0 = sum(1 for r in rows if r[1] == "OK" and r[7] == "Δ=0")
    n_unverifiable = sum(1 for r in rows if r[1] == "UNVERIFIABLE")
    print(f"\n[汇总] OK={n_ok} Δ=0={n_delta0} Δ≠0={n_ok-n_delta0} "
          f"UNVERIFIABLE={n_unverifiable}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    print(f"[manifest] 已写 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
