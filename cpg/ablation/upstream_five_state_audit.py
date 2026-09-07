# -*- coding: utf-8 -*-
"""全量 upstream 五态审计（status-aware，定影响面）。

按上游 fix commit 的 files[].status 对语料 corpus_pairs 逐 .py 文件核验存在性，
输出样本级影响表。这是 Codex 第 2-5 步的核心：先定"哪些历史结果仍有效"。

五态规则（Codex）：
    modified → vuln/fixed 两侧都必须存在
    added    → vuln 应不存在、fixed 必须存在
    removed   → vuln 必须存在、fixed 应不存在
    renamed   → old(previous_filename) 在 vuln、new 在 fixed
    copied    → 按 git 状态（本语料罕见，单独记录）
任一"非预期缺失/多余" → unexpected_mismatch，样本标记"语料错误"。

用法：
    python cpg/ablation/upstream_five_state_audit.py [--cves ...] [--out ...]
    默认审计 74 ∪ 85 并集。
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "cpg" / "corpus_pairs"
sys.path.insert(0, str(ROOT))
from cpg.ablation.upstream_manifest import (  # noqa: E402
    curl_json, api_url, read_meta, corpus_py_files,
    curl_raw, raw_url, norm_eol,
)


def load_jsonl_ids(path):
    out = set()
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
            out.add(o.get("cve_id") or o.get("cve"))
        except Exception:
            pass
    return {x for x in out if x}


def file_exists(cve, side, fn):
    return (CORPUS / cve / side / fn).exists()


def audit_one(cve, cache_dir):
    """返回 {status, repo, commit, mismatches, nonpy_removed/added}。"""
    meta = read_meta(cve)
    if "_error" in meta:
        return {"status": "META_ERR", "error": meta["_error"]}
    repo = meta.get("repo_slug", "")
    sha = meta.get("fix_commit", "")
    if not repo or not sha:
        return {"status": "META_MISSING"}

    cache_file = cache_dir / f"{cve}.json"
    d = None
    if cache_file.exists():
        d = json.loads(cache_file.read_text(encoding="utf-8"))
    else:
        d = curl_json(api_url(repo, sha))
        if "_error" not in d:
            cache_file.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")

    if d is None or "_error" in d or "files" not in d:
        return {"status": "UNVERIFIABLE", "error": (d or {}).get("_error", "no files")}

    mismatches = []
    nonpy = []
    content_mismatches = []
    parents = [p["sha"] for p in d.get("parents", [])]
    parent_sha = parents[0] if len(parents) == 1 else None
    for f in d["files"]:
        fn = f["filename"]
        st = f.get("status", "")
        if not fn.endswith(".py"):
            nonpy.append((fn, st))
            continue
        v_ex = file_exists(cve, "vuln", fn)
        f_ex = file_exists(cve, "fixed", fn)
        if st == "modified":
            exp_v, exp_f = True, True
        elif st == "added":
            exp_v, exp_f = False, True
        elif st == "removed":
            exp_v, exp_f = True, False
        elif st == "renamed":
            # previous_filename 应在 vuln 存在，new 在 fixed 存在
            prev = f.get("previous_filename")
            if prev:
                exp_v = file_exists(cve, "vuln", prev)
            else:
                exp_v = None
            exp_f = True
            if exp_v is False or not f_ex:
                mismatches.append((fn, st, f"vuln_prev={exp_v} fixed={f_ex}"))
            continue
        elif st == "copied":
            # copied：原路径保留、新路径在 fix 出现（罕见，单独记录不计 mismatch）
            nonpy.append((fn, "copied"))
            continue
        else:
            continue  # 未知态单独记录
        if v_ex != exp_v or f_ex != exp_f:
            mismatches.append((fn, st, f"vuln={v_ex}(exp {exp_v}) fixed={f_ex}(exp {exp_f})"))
            continue
        # 内容核验（Codex 门禁 1）：modified 且两侧都存在时，比对 blob 内容（归一化行尾）
        if st == "modified" and v_ex and f_ex and parent_sha:
            v_bytes = (CORPUS / cve / "vuln" / fn).read_bytes()
            f_bytes = (CORPUS / cve / "fixed" / fn).read_bytes()
            p_raw = curl_raw(raw_url(repo, parent_sha, fn))
            x_raw = curl_raw(raw_url(repo, sha, fn))
            if p_raw["status"] == 200 and norm_eol(v_bytes) != norm_eol(p_raw["body"]):
                content_mismatches.append((fn, "vuln-blob≠upstream-parent"))
            if x_raw["status"] == 200 and norm_eol(f_bytes) != norm_eol(x_raw["body"]):
                content_mismatches.append((fn, "fixed-blob≠upstream-fix"))

    status = "OK" if (not mismatches and not content_mismatches) else "CORPUS_ERROR"
    return {"status": status, "repo": repo, "commit": sha,
            "mismatches": mismatches, "content_mismatches": content_mismatches,
            "nonpy": nonpy}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cves", nargs="+")
    ap.add_argument("--out", default="cpg/ablation/.work/upstream_five_state.json")
    ap.add_argument("--dataset", default="union",
                    help="union | main74 | d1_85（默认 union=74∪85）")
    args = ap.parse_args()

    if args.cves:
        cves = set(args.cves)
    else:
        d74 = load_jsonl_ids(ROOT / "cpg" / "dataset.jsonl")
        d85 = load_jsonl_ids(ROOT / "cpg" / "dataset_d1.jsonl")
        if args.dataset == "main74":
            cves = d74
        elif args.dataset == "d1_85":
            cves = d85
        else:
            cves = d74 | d85

    cache_dir = ROOT / "cpg" / "ablation" / ".work" / "upstream_api_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    results = {}
    counts = {"OK": 0, "CORPUS_ERROR": 0, "UNVERIFIABLE": 0, "META_ERR": 0, "META_MISSING": 0}
    for cve in sorted(cves):
        r = audit_one(cve, cache_dir)
        results[cve] = r
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    # 打印样本级影响表
    print(f"{'CVE':<17} {'状态':<14} {'mismatch 数':<11} 详情")
    print("-" * 90)
    for cve in sorted(cves):
        r = results[cve]
        st = r["status"]
        if st == "CORPUS_ERROR":
            ms = r["mismatches"]
            print(f"{cve:<17} {st:<14} {len(ms):<11} {ms[0][0][:40]} ..." if ms else f"{cve:<17} {st}")
            for fn, st_, detail in ms:
                print(f"    - {fn} [{st_}] {detail}")
        elif st == "OK":
            pass  # 不打印，汇总即可
        else:
            print(f"{cve:<17} {st:<14} {str(r.get('error',''))[:50]}")

    print("\n== 汇总（并集 %d 例）==" % len(cves))
    for k, v in sorted(counts.items()):
        print(f"  {k}: {v}")
    # 列出 CORPUS_ERROR 的 CVE 清单
    err_ids = sorted(c for c, r in results.items() if r["status"] == "CORPUS_ERROR")
    print(f"\nCORPUS_ERROR 清单（{len(err_ids)} 例）: {err_ids}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\n[written] {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
