#!/usr/bin/env python3
"""
corpus_builder.py - 真实 Python CVE 语料采集器（CPG 阶段 §5）

数据来源：GitHub Global Advisory Database（官方，含 CVE 编号 + CWE + 受影响包 + 修复 commit）
不依赖 CVEFixes 12.7GB 全量；每条语料都是真实 CVE 的「修复前/修复后」代码对。

设计纪律（来自长期研究支撑协议）：
- 只用真实 CVE 修复（禁用 SARD/Juliet 合成集）
- 每条语料必须带 CVE 编号 + CWE + 修复 commit（可复现、可验证）
- 修复前 = fix_commit 的 parent；修复后 = fix_commit（天然配对）
- 同名函数/文件用 <cve_id>/<repo_slug>/ 双层目录区分，避免语料库级单 DB 冲突

用法：
  # 1. 拉取 pip 生态 advisory（缓存到 raw_advisories.json，减少 API quota 消耗）
  python corpus_builder.py fetch --eco pip --pages 5

  # 2. 筛选带 GitHub 修复 commit 的，生成候选清单
  python corpus_builder.py select --out candidates.jsonl

  # 3. 克隆并提取修复前后文件对（默认取前 N 条）
  python corpus_builder.py extract --candidates candidates.jsonl --limit 10

  # 4. 汇总成 corpus_index.jsonl
  python corpus_builder.py index
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_ADVISORIES = ROOT / "raw_advisories.json"
CORPUS_RAW = ROOT / "corpus_raw"          # git clones（gitignored）
CORPUS_PAIRS = ROOT / "corpus_pairs"      # 提取的修复前后对（保留）
CORPUS_INDEX = ROOT / "corpus_index.jsonl"

GH_COMMIT_RE = re.compile(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})")
GH_REPO_RE = re.compile(r"github\.com/([^/]+/[^/]+?)(?:\.git)?$")

API_BASE = "https://api.github.com/advisories"
# GitHub Advisory API 需要指定 API 版本才返回 cwe_ids 等完整字段
API_ACCEPT = "application/vnd.github+json"
API_VERSION = "2022-11-28"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def fetch_advisories(eco: str, pages: int):
    """拉取某生态的 GitHub advisory，缓存到本地。无 token 限流 60/hr，pages*100<=6000。"""
    all_advs = []
    for page in range(1, pages + 1):
        url = f"{API_BASE}?ecosystem={eco}&per_page=100&page={page}&sort=published"
        r = run(["curl", "-sS", "-m", "30", "-H", f"Accept: {API_ACCEPT}",
                 "-H", f"X-GitHub-Api-Version: {API_VERSION}", url])
        if r.returncode != 0:
            print(f"[warn] curl failed page {page}: {r.stderr[:200]}")
            break
        try:
            batch = json.loads(r.stdout)
        except json.JSONDecodeError:
            print(f"[warn] non-JSON page {page}: {r.stdout[:200]}")
            break
        if not isinstance(batch, list) or not batch:
            print(f"[info] page {page} empty, stop.")
            break
        all_advs.extend(batch)
        print(f"[fetch] page {page}: +{len(batch)} (total {len(all_advs)})")
    RAW_ADVISORIES.write_text(json.dumps(all_advs, indent=1), encoding="utf-8")
    print(f"[ok] saved {len(all_advs)} advisories -> {RAW_ADVISORIES}")
    return all_advs


def parse_references(adv: dict):
    """从 references 提取 GitHub 修复 commit + repo。"""
    refs = adv.get("references") or []
    for ref in refs:
        url = ref.get("url") if isinstance(ref, dict) else str(ref)
        m = GH_COMMIT_RE.search(url)
        if m:
            repo_slug = m.group(1)
            commit = m.group(2)
            return repo_slug, commit, url
    return None, None, None


def cwe_list(adv: dict):
    """GitHub advisory 的 CWE 字段是 'cwes'，结构是 [{'cwe_id': 'CWE-79', 'name': ...}]。"""
    cwes = adv.get("cwes") or []
    out = []
    for c in cwes:
        if isinstance(c, dict):
            cid = c.get("cwe_id")
            if cid:
                out.append(cid)
        elif isinstance(c, str):
            out.append(c)
    return out


def select_candidates(out_path: str, max_per_repo: int = 2, seed: int = 0):
    """筛选带 GitHub 修复 commit + CWE 的候选，并按仓库分层（每仓库最多 max_per_repo），
    避免单仓库聚集导致的「模版化」偏见。输出按发布时间倒序，保证时间可信度。

    设计纪律：真实语料的核心论证力来自「来源多样 + 类型覆盖 + 时间跨度」。
    单仓库聚集（如 32/78 来自 open-webui）会让评审直接判为套路化，必须打散。
    """
    if not RAW_ADVISORIES.exists():
        print("[fail] raw_advisories.json missing, run fetch first")
        sys.exit(1)
    advs = json.loads(RAW_ADVISORIES.read_text(encoding="utf-8"))
    by_repo = defaultdict(list)
    seen = set()
    seen_commit = set()  # 同一修复 commit 只收一次（避免多 CVE 共用一 fix 被算成多条）
    for adv in advs:
        repo_slug, commit, ref_url = parse_references(adv)
        if not commit:
            continue
        if commit in seen_commit:
            continue
        cve = adv.get("cve_id")
        if not cve or cve in seen:
            continue
        # 只接受带 CWE 的（保证多样性可量化、论证度足够）
        cwes = cwe_list(adv)
        if not cwes:
            continue
        seen.add(cve)
        seen_commit.add(commit)
        sev = (adv.get("severity") or "unknown").lower()
        pub = adv.get("published_at") or adv.get("published") or ""
        by_repo[repo_slug].append({
            "cve_id": cve,
            "ghsa_id": adv.get("ghsa_id"),
            "repo_slug": repo_slug,
            "fix_commit": commit,
            "ref_url": ref_url,
            "cwes": cwes,
            "severity": sev,
            "published": pub[:10] if pub else "",
            "summary": (adv.get("summary") or "").strip(),
            "language": "python",
        })
    # 每仓库内按 严重度 > 时间 排序，优先收严重 + 近期
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    for repo, items in by_repo.items():
        items.sort(key=lambda c: (sev_rank.get(c["severity"], 9), c["published"]), reverse=True)
    # 仓库间轮转（round-robin），每仓库最多 max_per_repo，最大化来源多样性
    rng = random.Random(seed)
    repos = list(by_repo.keys())
    rng.shuffle(repos)
    selected = []
    for _ in range(max_per_repo):
        for r in repos:
            if by_repo[r]:
                selected.append(by_repo[r].pop(0))
    # 最终按发布时间倒序，便于人工审查时间分布
    selected.sort(key=lambda c: (c["published"], sev_rank.get(c["severity"], 9)), reverse=True)
    out = ROOT / out_path
    out.write_text("\n".join(json.dumps(c, ensure_ascii=False) for c in selected), encoding="utf-8")
    print(f"[ok] {len(selected)} stratified candidates (max {max_per_repo}/repo, seed={seed}) -> {out}")
    # 多样性报告
    from collections import Counter
    cw, rp = Counter(), Counter()
    for c in selected:
        for w in c["cwes"]:
            cw[w] += 1
        rp[c["repo_slug"]] += 1
    print(f"[diversity] distinct repos: {len(rp)} / {len(selected)} entries")
    for r, n in rp.most_common(12):
        print(f"  {n:2d}  {r}")
    print("[diversity] CWE distribution:")
    for w, n in cw.most_common(20):
        print(f"  {w}: {n}")
    return selected


def clone_and_extract(repo_slug: str, fix_commit: str, pair_dir: Path):
    """clone（blob:none 省空间）→ checkout fix + parent 的同名文件对。
    返回提取到的文件列表；失败返回空。"""
    CORPUS_RAW.mkdir(parents=True, exist_ok=True)
    repo_dir = CORPUS_RAW / repo_slug.replace("/", "__")
    # 用 mirror/本地缓存避免重复网络拉取
    if not repo_dir.exists():
        clone = run([
            "git", "clone", "--filter=blob:none", "--no-checkout",
            f"https://github.com/{repo_slug}.git", str(repo_dir)
        ], cwd=str(ROOT))
        if clone.returncode != 0:
            print(f"    [fail] clone {repo_slug}: {clone.stderr[:160]}")
            return []
    # 确保 fix_commit 可达
    fetch = run(["git", "fetch", "--depth", "2", "origin", fix_commit],
                cwd=str(repo_dir))
    if fetch.returncode != 0:
        print(f"    [fail] fetch {fix_commit[:8]} in {repo_slug}: {fetch.stderr[:160]}")
        return []
    # 提取修复后文件列表（从 fix_commit 的 tree）
    show = run(["git", "ls-tree", "-r", "--name-only", fix_commit], cwd=str(repo_dir))
    if show.returncode != 0:
        return []
    files = [f for f in show.stdout.splitlines()
             if f.endswith(".py") and ("test" not in f.lower() or "tests" not in f.lower())]
    # 优先取改动文件；退化取全部 py
    diff = run(["git", "diff", "--name-only", f"{fix_commit}^", fix_commit],
               cwd=str(repo_dir))
    changed = [f for f in diff.stdout.splitlines() if f.endswith(".py")] if diff.returncode == 0 else []
    targets = changed or files[:20]
    extracted = []
    for f in targets:
        fixed_path = pair_dir / "fixed" / f
        vuln_path = pair_dir / "vuln" / f
        for commit, dst in ((fix_commit, fixed_path), (f"{fix_commit}^", vuln_path)):
            dst.parent.mkdir(parents=True, exist_ok=True)
            cp = run(["git", "checkout", commit, "--", f], cwd=str(repo_dir))
            if cp.returncode == 0:
                # 把 checkout 出的文件移到目标位置
                src = repo_dir / f
                if src.exists():
                    dst.write_bytes(src.read_bytes())
                    run(["git", "checkout", "HEAD", "--", f], cwd=str(repo_dir))  # 复位
                    extracted.append(str(dst.relative_to(ROOT)))
    return extracted


def extract(candidates_path: str, limit: int, exclude_repos=None):
    cands = [json.loads(l) for l in (ROOT / candidates_path).read_text(encoding="utf-8").splitlines() if l.strip()]
    cands = cands[:limit]
    exclude_repos = set(exclude_repos or [])
    CORPUS_PAIRS.mkdir(parents=True, exist_ok=True)
    done = 0
    for c in cands:
        if c["repo_slug"] in exclude_repos:
            print(f"[skip-repo] {c['cve_id']} ({c['repo_slug']}) excluded")
            continue
        pair_dir = CORPUS_PAIRS / c["cve_id"]
        if (pair_dir / "meta.json").exists():
            print(f"[skip] {c['cve_id']} already extracted")
            done += 1
            continue
        print(f"[extract] {c['cve_id']} ({c['repo_slug']} @{c['fix_commit'][:8]}) cwe={c['cwes']}")
        files = clone_and_extract(c["repo_slug"], c["fix_commit"], pair_dir)
        if not files:
            print(f"    [empty] no py files extracted, skip")
            continue
        meta = {
            "cve_id": c["cve_id"],
            "ghsa_id": c["ghsa_id"],
            "repo_slug": c["repo_slug"],
            "fix_commit": c["fix_commit"],
            "cwes": c["cwes"],
            "severity": c["severity"],
            "summary": c["summary"],
            "language": "python",
            "files": files,
            "label": "vulnerable_before_fixed",  # 修复前含漏洞，修复后无
        }
        (pair_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        done += 1
    print(f"[ok] extracted {done}/{len(cands)} pairs into {CORPUS_PAIRS}")


def build_index(max_per_repo: int = None):
    """汇总所有 pair 的 meta.json 成 corpus_index.jsonl。
    若指定 --max-per-repo，则额外写出 dataset.jsonl（实验用分层队列，
    每仓库最多 N 条），作为消融实验的权威语料集，避免单仓库聚集偏见。
    以 _ 开头的目录视为归档（如 _poc_seed），不计入实验集。
    """
    if not CORPUS_PAIRS.exists():
        print("[fail] corpus_pairs missing")
        sys.exit(1)
    rows = []
    for d in sorted(CORPUS_PAIRS.iterdir()):
        if d.name.startswith("_"):
            continue
        meta = d / "meta.json"
        if meta.exists():
            rows.append(json.loads(meta.read_text(encoding="utf-8")))
    CORPUS_INDEX.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows), encoding="utf-8")
    print(f"[ok] {len(rows)} corpus entries -> {CORPUS_INDEX}")
    from collections import Counter
    cw = Counter()
    for r in rows:
        for w in r["cwes"]:
            cw[w] += 1
    print("[diversity] CWE distribution in corpus:")
    for w, n in cw.most_common():
        print(f"  {w}: {n}")
    if max_per_repo:
        sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
        by_repo = defaultdict(list)
        for r in rows:
            by_repo[r["repo_slug"]].append(r)
        cohort = []
        seen_commit = set()  # 同 fix_commit 只入一次（多 CVE 共用一修复）
        for repo, items in by_repo.items():
            items.sort(key=lambda r: (sev_rank.get(r["severity"], 9), r.get("published", "")), reverse=True)
            for it in items[:max_per_repo]:
                if it["fix_commit"] in seen_commit:
                    continue
                seen_commit.add(it["fix_commit"])
                cohort.append(it)
        DATASET = ROOT / "dataset.jsonl"
        DATASET.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in cohort), encoding="utf-8")
        rp = Counter(r["repo_slug"] for r in cohort)
        cw2 = Counter()
        for r in cohort:
            for w in r["cwes"]:
                cw2[w] += 1
        print(f"[dataset] {len(cohort)} entries (max {max_per_repo}/repo) -> {DATASET}")
        print(f"[dataset] distinct repos: {len(rp)}")
        for r2, n in rp.most_common():
            print(f"    {n:2d}  {r2}")
        print(f"[dataset] CWE families: {len(cw2)} -> {dict(cw2.most_common())}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("fetch"); pf.add_argument("--eco", default="pip"); pf.add_argument("--pages", type=int, default=5)
    ps = sub.add_parser("select")
    ps.add_argument("--out", default="candidates.jsonl")
    ps.add_argument("--max-per-repo", type=int, default=2, help="每仓库最多收录 CVE 数（打散来源聚集）")
    ps.add_argument("--seed", type=int, default=0, help="仓库轮转随机种子（可复现）")
    pe = sub.add_parser("extract"); pe.add_argument("--candidates", default="candidates.jsonl"); pe.add_argument("--limit", type=int, default=10)
    pe.add_argument("--exclude-repo", action="append", default=[], help="跳过指定仓库（如 open-webui/open-webui），避免重复来源")
    pi = sub.add_parser("index"); pi.add_argument("--max-per-repo", type=int, default=None, help="写出 dataset.jsonl 分层实验集（每仓库最多 N 条）")
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch_advisories(args.eco, args.pages)
    elif args.cmd == "select":
        select_candidates(args.out, args.max_per_repo, args.seed)
    elif args.cmd == "extract":
        extract(args.candidates, args.limit, args.exclude_repo)
    elif args.cmd == "index":
        build_index(args.max_per_repo)


if __name__ == "__main__":
    main()
