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
    """subprocess.run 包装：超时返回 returncode=124（调用处按非零处理跳过）。"""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, stdout="", stderr="[timeout]")


def fetch_advisories(eco: str, pages: int, merge: bool = True, start_page: int = 1):
    """拉取某生态的 GitHub advisory，缓存到本地。无 token 限流 60/hr，pages*100<=6000。

    GITHUB_TOKEN 环境变量可用时注入认证头（5000/hr 配额）。
    ``merge``（默认 True）：新拉取的 advisory 与现有缓存**合并去重**（按 ghsa_id），
    使多轮 fetch 可累积不同页的数据——网络中断重试不会丢已有缓存。
    ``start_page``：从指定页码开始拉（API 按 published 倒序，页码越大越老），
    用于分轮拉取历史深度数据（如 --start-page 20 拉 2000-3000 区间）。
    """
    all_advs = []
    token = os.environ.get("GITHUB_TOKEN", "")
    auth = ["-H", f"Authorization: Bearer {token}"] if token else []
    for page in range(start_page, start_page + pages):
        url = f"{API_BASE}?ecosystem={eco}&per_page=100&page={page}&sort=published"
        r = run(["curl", "-sS", "-m", "30", "-H", f"Accept: {API_ACCEPT}",
                 "-H", f"X-GitHub-Api-Version: {API_VERSION}", *auth, url])
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
    if merge and RAW_ADVISORIES.exists() and all_advs:
        try:
            cached = json.loads(RAW_ADVISORIES.read_text(encoding="utf-8"))
            by_id = {a.get("ghsa_id"): a for a in cached if a.get("ghsa_id")}
            for a in all_advs:
                by_id[a.get("ghsa_id")] = a
            all_advs = list(by_id.values())
            print(f"[merge] merged with cache: {len(cached)} -> {len(all_advs)} unique")
        except Exception as exc:
            print(f"[warn] cache merge failed ({exc}); overwrite with new batch")
    if all_advs:
        # 仅在成功拉到数据时覆盖缓存；失败（网络中断拉 0 条）时保留旧缓存，
        # 避免把已有缓存清空导致后续 select 无源可用。
        RAW_ADVISORIES.write_text(json.dumps(all_advs, indent=1), encoding="utf-8")
        print(f"[ok] saved {len(all_advs)} advisories -> {RAW_ADVISORIES}")
    else:
        print(f"[warn] fetched 0 advisories; keep existing cache "
              f"({RAW_ADVISORIES.stat().st_size if RAW_ADVISORIES.exists() else 0} bytes)")
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
    返回提取到的文件列表；失败返回空。

    fetch 策略修正（2026-08-28）：``blob:none`` 过滤克隆已包含**全量 commit 元数据**
    （仅 blob 延迟加载），无需再 ``git fetch --depth 2 <commit>``——该命令在浅克隆
    服务端常报 ``upload-pack: not our ref``（即使 commit 在 GitHub 上真实存在，
    因服务端不允许浅 fetch 指定任意 commit）。改为直接 ``git cat-file -e`` 检查
    本地对象；缺失时才尝试 fetch（失败则按数据源失效处理）。
    """
    CORPUS_RAW.mkdir(parents=True, exist_ok=True)
    repo_dir = CORPUS_RAW / repo_slug.replace("/", "__")
    # 用 mirror/本地缓存避免重复网络拉取
    if not repo_dir.exists():
        clone = run([
            "git", "clone", "--filter=blob:none", "--no-checkout",
            f"https://github.com/{repo_slug}.git", str(repo_dir)
        ], cwd=str(ROOT), timeout=300)
        if clone.returncode != 0:
            print(f"    [fail] clone {repo_slug}: {clone.stderr[:160]}")
            return []
    # 检查 fix_commit 本地可达性（blob:none 克隆已含全部 commit 对象）
    check = run(["git", "cat-file", "-e", f"{fix_commit}^{{commit}}"],
                cwd=str(repo_dir), timeout=30)
    if check.returncode != 0:
        # 回退 1：全分支拉取（fix_commit 可能在非默认分支，单分支 blob:none 克隆漏掉）
        fb = run(["git", "fetch", "origin", "+refs/heads/*:refs/remotes/origin/*"],
                 cwd=str(repo_dir), timeout=240)
        if fb.returncode == 0:
            check = run(["git", "cat-file", "-e", f"{fix_commit}^{{commit}}"],
                        cwd=str(repo_dir), timeout=30)
        # 回退 2：直接按 SHA fetch（GitHub 公开仓库若对象仍存在则允许；否则即数据源失效）
        if check.returncode != 0:
            fetch = run(["git", "fetch", "origin", fix_commit], cwd=str(repo_dir), timeout=180)
            if fetch.returncode != 0:
                print(f"    [fail] commit {fix_commit[:8]} unavailable in {repo_slug} "
                      f"(dangling/not our ref): {fetch.stderr[:120]}")
                return []
    # 提取修复后文件列表（从 fix_commit 的 tree）
    show = run(["git", "ls-tree", "-r", "--name-only", fix_commit], cwd=str(repo_dir), timeout=60)
    if show.returncode != 0:
        return []
    files = [f for f in show.stdout.splitlines()
             if f.endswith(".py") and ("test" not in f.lower() or "tests" not in f.lower())]
    # 优先取改动文件；修复 diff 不含 .py 变更（如跨语言修复在 Rust/C）时跳过——
    # 此时 vuln/fixed 的 Python 侧完全相同，truth 标签无意义，属污染样本。
    diff = run(["git", "diff", "--name-only", f"{fix_commit}^", fix_commit],
               cwd=str(repo_dir), timeout=60)
    changed = [f for f in diff.stdout.splitlines() if f.endswith(".py")] if diff.returncode == 0 else []
    if not changed:
        print(f"    [skip] fix diff has no .py changes (cross-language fix), skip")
        return []
    targets = changed[:20]
    extracted = []
    missing_vuln: list[str] = []   # vuln（fix^）侧缺失的 changed 文件——重构式修复信号
    for f in targets:
        fixed_path = pair_dir / "fixed" / f
        vuln_path = pair_dir / "vuln" / f
        for commit, dst in ((fix_commit, fixed_path), (f"{fix_commit}^", vuln_path)):
            dst.parent.mkdir(parents=True, exist_ok=True)
            cp = run(["git", "checkout", commit, "--", f], cwd=str(repo_dir), timeout=90)
            if cp.returncode == 0:
                # 把 checkout 出的文件移到目标位置
                src = repo_dir / f
                if src.exists():
                    dst.write_bytes(src.read_bytes())
                    run(["git", "checkout", "HEAD", "--", f], cwd=str(repo_dir), timeout=60)  # 复位
                    extracted.append(str(dst.relative_to(ROOT)))
                else:
                    missing_vuln.append(f)
            elif commit == f"{fix_commit}^":
                # vuln 侧该文件在 fix^ 不存在——修复可能是重构式（文件移动/新增），
                # 漏洞代码可能位于 fix^ 的其他路径，提取的 vuln 侧不完整
                missing_vuln.append(f)
    # 双侧完整性校验（55419 教训，2026-08-28 升级为阻断）：
    # 修复 diff 改动文件中，vuln 侧缺失率 ≥30% 视为重构式修复（文件移动/拆分），
    # 此时"同名文件 checkout"策略漏掉 vuln 侧漏洞代码，truth 标签不可靠——
    # **直接返回空，不写入 meta.json，阻止污染样本入库**。
    # 少量缺失（<30%）允许但记录信号供人工核查。
    if missing_vuln and len(targets) > 0:
        ratio = len(missing_vuln) / len(targets)
        sig_path = pair_dir / "extraction_signal.json"
        if ratio >= 0.3:
            sig_path.write_text(json.dumps({
                "vuln_side_missing": missing_vuln,
                "missing_ratio": round(ratio, 2),
                "note": "重构式修复或文件移动：vuln 侧漏洞代码可能未提取，truth 不可靠，已阻断入库",
                "blocked": True,
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"    [BLOCKED] 重构式修复，vuln 侧缺失 {len(missing_vuln)}/{len(targets)} "
                  f"文件: {missing_vuln[:4]} —— 阻断入库")
            # 清理半成品，避免 index 时误收
            import shutil
            if pair_dir.exists():
                shutil.rmtree(pair_dir, ignore_errors=True)
            return []
        sig_path.write_text(json.dumps({
            "vuln_side_missing": missing_vuln,
            "missing_ratio": round(ratio, 2),
            "note": "少量 vuln 侧缺失，可接受，人工核查",
            "blocked": False,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"    [小错位] vuln 侧缺失 {len(missing_vuln)}/{len(targets)} 文件: {missing_vuln[:4]}")
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
    pf.add_argument("--no-merge", action="store_true", help="覆盖缓存而非合并（默认合并去重）")
    pf.add_argument("--start-page", type=int, default=1, help="起始页码（按 published 倒序，越大越老）")
    ps = sub.add_parser("select")
    ps.add_argument("--out", default="candidates.jsonl")
    ps.add_argument("--max-per-repo", type=int, default=2, help="每仓库最多收录 CVE 数（打散来源聚集）")
    ps.add_argument("--seed", type=int, default=0, help="仓库轮转随机种子（可复现）")
    pe = sub.add_parser("extract"); pe.add_argument("--candidates", default="candidates.jsonl"); pe.add_argument("--limit", type=int, default=10)
    pe.add_argument("--exclude-repo", action="append", default=[], help="跳过指定仓库（如 open-webui/open-webui），避免重复来源")
    pi = sub.add_parser("index"); pi.add_argument("--max-per-repo", type=int, default=None, help="写出 dataset.jsonl 分层实验集（每仓库最多 N 条）")
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch_advisories(args.eco, args.pages, merge=not args.no_merge, start_page=args.start_page)
    elif args.cmd == "select":
        select_candidates(args.out, args.max_per_repo, args.seed)
    elif args.cmd == "extract":
        extract(args.candidates, args.limit, args.exclude_repo)
    elif args.cmd == "index":
        build_index(args.max_per_repo)


if __name__ == "__main__":
    main()
