# -*- coding: utf-8 -*-
"""上游投影 manifest 测量（只读，不生成实验刺激/不启动标注/不调用模型）。

用法：
    python cpg/ablation/upstream_manifest.py [--cves CVE-...] [--out manifest.json]
        [--no-fetch] [--no-content]

两级 delta（分层，勿把"路径一致"当"内容完整"）：
  L1 路径级：上游 Python 投影文件集 vs 语料 .py 文件集，双向差集。
  L2 内容级：对交集文件，fetch 上游 parent/fix 的 raw blob，与 corpus vuln/fixed
     按【归一化行尾】后字节比对。区分"字节级等价"与"内容级等价"（corpus 在 Windows
     checkout 下 LF→CRLF，属环境行尾差，非内容差）。

权威性说明（Codex 要求）：本脚本用 raw.githubusercontent.com 按 commit sha 取原始
文件内容（完整 blob，非 API 的 patch 字段——patch 可能分页/截断）。请求元数据
（URL/HTTP 状态/时间/原始 JSON SHA-256）落盘，供复现门禁核验。
"""
import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "cpg" / "corpus_pairs"
CACHE = ROOT / "cpg" / "ablation" / ".work" / "upstream_api_cache"


def norm_eol(b: bytes) -> bytes:
    """归一化行尾（CRLF→LF），区分内容差与 checkout 环境行尾差。"""
    return b.replace(b"\r\n", b"\n")


_TOKEN_CACHE = {"token": None}


def get_github_token() -> str:
    """从 git credential fill 读 GitHub token（提升 API 配额到 5000/h，避免 60/h 限流）。"""
    if _TOKEN_CACHE["token"] is not None:
        return _TOKEN_CACHE["token"]
    token = ""
    try:
        r = subprocess.run(["git", "credential", "fill"],
                           input="protocol=https\nhost=github.com\n\n",
                           capture_output=True, text=True, encoding="utf-8")
        for line in r.stdout.splitlines():
            if line.startswith("password="):
                token = line.split("=", 1)[1]
    except Exception:
        token = ""
    _TOKEN_CACHE["token"] = token
    return token


def _curl_auth(timeout: int) -> list:
    """构造 curl 命令，带 token（若有）。"""
    cmd = ["curl", "-sS", "--max-time", str(timeout)]
    token = get_github_token()
    if token:
        cmd += ["-H", f"Authorization: token {token}"]
    return cmd


def curl_json(url: str, timeout: int = 40) -> dict:
    try:
        r = subprocess.run(_curl_auth(timeout) + [url],
                           capture_output=True, text=True, encoding="utf-8")
    except Exception as ex:
        return {"_error": f"curl 失败: {ex}"}
    if r.returncode != 0:
        return {"_error": f"curl rc={r.returncode}"}
    out = r.stdout.strip()
    if not out:
        return {"_error": "空响应"}
    try:
        return json.loads(out)
    except Exception:
        return {"_error": f"非 JSON: {out[:120]}"}


def curl_raw(url: str, timeout: int = 60, retries: int = 3) -> dict:
    """fetch raw 文件内容；返回 {status, body(bytes), sha256, url, time}。

    非 200/404 状态（如 429 限流）退避重试，避免连续快速请求触发 raw 限流。
    """
    last = None
    for attempt in range(retries):
        try:
            r = subprocess.run(["curl", "-sS", "--max-time", str(timeout), "-w",
                                "\n%{http_code}", url], capture_output=True)
        except Exception as ex:
            last = {"status": -1, "body": b"", "error": str(ex), "url": url}
            break
        out = r.stdout
        if out.endswith(b"\n"):
            out = out[:-1]
        if out.rfind(b"\n") >= 0 and out.rsplit(b"\n", 1)[-1].isdigit():
            code = int(out.rsplit(b"\n", 1)[-1])
            body = out.rsplit(b"\n", 1)[0]
        else:
            code = 0
            body = out
        if code in (200, 404) or attempt == retries - 1:
            return {"status": code, "body": body,
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "url": url, "time": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "attempts": attempt + 1}
        time.sleep(1.0 * (attempt + 1))  # 退避：1s、2s
        last = {"status": code, "body": body, "url": url}
    return last


def raw_url(repo: str, sha: str, filename: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{sha}/{filename}"


def api_url(repo: str, sha: str) -> str:
    return f"https://api.github.com/repos/{repo}/commits/{sha}"


def read_meta(cve: str) -> dict:
    p = CORPUS / cve / "meta.json"
    if not p.exists():
        return {"_error": f"无 meta.json: {p}"}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception as ex:
        return {"_error": f"meta.json 解析失败: {ex}"}


def corpus_py_files(meta: dict) -> set:
    out = set()
    for f in meta.get("files", []):
        norm = f.replace("\\", "/")
        for seg in ("/fixed/", "/vuln/"):
            if seg in norm:
                norm = norm.split(seg, 1)[1]
                break
        if norm.endswith(".py"):
            out.add(norm)
    return out


def upstream_py_files(files: list) -> set:
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
    """改动行数 × 8，明确 PROXY；后续接真实 tokenizer 重标定。"""
    return max(1, int(lines * 8))


def read_corpus_file(cve: str, side: str, filename: str):
    """读 corpus vuln/fixed 文件；不存在返回 None。side ∈ {vuln, fixed}。"""
    p = CORPUS / cve / side / filename
    if not p.exists():
        return None
    return p.read_bytes()


def content_compare(cve: str, repo: str, parent: str, fix: str,
                    up_py: list, no_fetch: bool) -> dict:
    """L2 内容级：对每个上游 python 文件比对 corpus 与上游 blob（归一化行尾）。"""
    base_mismatch = []      # corpus vuln ≠ 上游 parent（归一化后仍不等）
    fixed_mismatch = []     # corpus fixed ≠ 上游 fix（归一化后仍不等）
    line_ending_diff = []   # 行尾符不同（CRLF vs LF）
    base_presence = []      # parent 与 corpus vuln 存在性不一致
    fixed_presence = []     # fix 与 corpus fixed 存在性不一致
    fetch_err = []          # raw fetch 失败的文件

    for filename in up_py:
        c_vuln = read_corpus_file(cve, "vuln", filename)
        c_fixed = read_corpus_file(cve, "fixed", filename)
        if no_fetch:
            continue
        p_raw = curl_raw(raw_url(repo, parent, filename))
        f_raw = curl_raw(raw_url(repo, fix, filename))
        if p_raw["status"] not in (200, 404) or f_raw["status"] not in (200, 404):
            fetch_err.append(filename)
            continue
        up_base = p_raw["body"] if p_raw["status"] == 200 else None
        up_fix = f_raw["body"] if f_raw["status"] == 200 else None

        # 存在性一致
        if (up_base is None) != (c_vuln is None):
            base_presence.append(filename)
        if (up_fix is None) != (c_fixed is None):
            fixed_presence.append(filename)

        # 内容等价（归一化行尾）
        if up_base is not None and c_vuln is not None:
            if norm_eol(c_vuln) != norm_eol(up_base):
                base_mismatch.append(filename)
            if (b"\r\n" in c_vuln) != (b"\r\n" in up_base):
                line_ending_diff.append(filename)
        if up_fix is not None and c_fixed is not None:
            if norm_eol(c_fixed) != norm_eol(up_fix):
                fixed_mismatch.append(filename)
            if (b"\r\n" in c_fixed) != (b"\r\n" in up_fix):
                line_ending_diff.append(filename)

    content_equivalent = (not base_mismatch and not fixed_mismatch
                          and not base_presence and not fixed_presence
                          and not fetch_err)
    return {
        "delta_base_blobs": sorted(base_mismatch),
        "delta_fixed_blobs": sorted(fixed_mismatch),
        "delta_base_presence": sorted(base_presence),
        "delta_fixed_presence": sorted(fixed_presence),
        "line_ending_diff": sorted(set(line_ending_diff)),
        "fetch_error": sorted(fetch_err),
        "content_equivalent": content_equivalent,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cves", nargs="+", required=True)
    ap.add_argument("--out", default="cpg/ablation/.work/upstream_manifest.json")
    ap.add_argument("--no-fetch", action="store_true")
    ap.add_argument("--no-content", action="store_true")
    args = ap.parse_args()

    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = {"generated_from": {
        "git_commit": subprocess.run(["git", "rev-parse", "HEAD"],
                                     capture_output=True, text=True,
                                     encoding="utf-8").stdout.strip(),
        "content_compare": not args.no_content,
        "line_ending_normalized": True,
        "note": "L2 内容级按归一化行尾(CRLF→LF)比对；原始字节差异见 line_ending_diff",
    }, "samples": {}}

    rows = []
    for cve in args.cves:
        meta = read_meta(cve)
        if "_error" in meta:
            manifest["samples"][cve] = {"error": meta["_error"]}
            rows.append((cve, "META_ERR", "", "", "", "", "", "", "", ""))
            continue

        repo = meta.get("repo_slug", "")
        sha = meta.get("fix_commit", "")
        if not repo or not sha:
            manifest["samples"][cve] = {"error": "meta 缺 repo_slug/fix_commit"}
            rows.append((cve, "META_MISSING", "", "", "", "", "", "", "", ""))
            continue

        corpus_py = corpus_py_files(meta)

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
            rows.append((cve, "UNVERIFIABLE", repo, sha[:12], "", "", "", "",
                         err[:30], ""))
            continue

        if "files" not in d or "parents" not in d:
            msg = d.get("message", "无 files/parents")
            manifest["samples"][cve] = {"repo": repo, "fix_commit": sha,
                                        "status": "unverifiable", "error": msg}
            rows.append((cve, "UNVERIFIABLE", repo, sha[:12], "", "", "", "",
                         msg[:30], ""))
            continue

        files = d["files"]
        parents = [p["sha"] for p in d.get("parents", [])]
        parents_count = len(parents)
        is_merge = parents_count > 1
        msg_head = (d.get("commit", {}).get("message", "") or "").split("\n")[0]

        cls = classify_files(files)
        up_py = sorted(upstream_py_files(files))
        p_minus_c = sorted(set(up_py) - corpus_py)
        c_minus_p = sorted(corpus_py - set(up_py))
        delta_zero = (len(p_minus_c) == 0 and len(c_minus_p) == 0)
        total_lines = sum(f.get("additions", 0) + f.get("deletions", 0)
                          for f in cls["py"])

        # L2 内容级比较（仅当有唯一 parent，否则无法定 base）
        cc = None
        if not args.no_content and parents_count == 1:
            cc = content_compare(cve, repo, parents[0], sha, up_py,
                                 args.no_fetch)
        elif parents_count != 1:
            cc = {"content_equivalent": False,
                  "note": f"parents_count={parents_count}，无法唯一定 base，跳过内容级"}

        sample = {
            "cve_id": cve, "repository": repo, "fix_commit": sha,
            "parent_commits": parents, "parents_count": parents_count,
            "is_merge": is_merge, "commit_message_head": msg_head,
            "upstream_total_files": len(files),
            "python_projection_files": up_py,
            "python_projection_n": len(up_py),
            "non_python_excluded_n": len(cls["nonpy"]),
            "added/deleted/renamed": {"added": cls["added"],
                                      "deleted": cls["deleted"],
                                      "renamed": cls["renamed"]},
            "corpus_py_n": len(corpus_py),
            # L1 路径级
            "delta_paths": {"p_minus_c": p_minus_c, "c_minus_p": c_minus_p,
                            "path_set_equivalent": delta_zero},
            # L2 内容级
            "content": cc,
            "changed_lines": total_lines,
            "token_estimate": tokens_estimate(total_lines),
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

        ce = (cc or {}).get("content_equivalent", None)
        ce_s = "?" if ce is None else ("内容=" if ce else "内容≠")
        rows.append((cve, "OK", repo, sha[:12], str(len(up_py)),
                     str(len(corpus_py)),
                     f"{len(p_minus_c)}/{len(c_minus_p)}",
                     "路径=" if delta_zero else "路径≠",
                     ce_s, str(sample["token_estimate"])))

    pc_label = "P\\C/C\\P"
    hdr = f"{'CVE':<17} {'repo':<24} {'commit':<11} {'PyP':>3} {'PyC':>3} {pc_label:>7} {'路径':<5} {'内容':<5} {'tok':>6}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        if r[1] == "OK":
            cve, st, repo, sha, pyp, pyc, dp, path, ce, tok = r
            print(f"{cve:<17} {repo[:23]:<24} {sha:<11} {pyp:>3} {pyc:>3} {dp:>7} {path:<5} {ce:<5} {tok:>6}")
        else:
            cve, st, a, b, c_, d_, e_, f_, g_, h_ = r
            print(f"{cve:<17} {st:<13} {str(a)[:22]:<24} {str(b):<11}  {str(g_)[:50]}")

    n_ok = sum(1 for r in rows if r[1] == "OK")
    n_path0 = sum(1 for r in rows if r[1] == "OK" and r[7] == "路径=")
    n_cont = sum(1 for r in rows if r[1] == "OK" and r[8] == "内容=")
    n_unv = sum(1 for r in rows if r[1] == "UNVERIFIABLE")
    print(f"\n[汇总] OK={n_ok} 路径= {n_path0}/{n_ok}  内容= {n_cont}/{n_ok}  "
          f"UNVERIFIABLE={n_unv}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    print(f"[manifest] 已写 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
