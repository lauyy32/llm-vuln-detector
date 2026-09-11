# -*- coding: utf-8 -*-
"""A-5：RQ1-R 正式化（列联表 / exact CI / CPG 分层 / 匿名发布副本）。

**纪律**：
  - 本模块**不重算**权威数字，只**消费** `strict_recompute_out.json`（由
    `strict_recompute.py` 产出，含 fail-closed 完整性断言）与 `claims.json`（数字账本）；
  - 报告中每个数字都必须能**逐条对账**到 `claims.json` 的 `expect`，否则 fail-closed；
  - 发布副本必须**匿名**：不含用户名、本机绝对路径、GitHub 账号等可反查信息。

strict 口径（与预注册 P1-13 §3 一致）：判别 = vuln 显式 `vulnerable` **且**
fixed 显式 `benign`；`abstain` 不计入任何一侧。lenient 仅作规则敏感性申报。
"""
from __future__ import annotations

import csv
import glob
import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "cpg" / "ablation" / "artifacts" / "v4"

WORK = ROOT / "cpg" / "ablation" / ".work"
AUTH_OUT = WORK / "strict_recompute_out.json"
CLAIMS = WORK / "claims.json"
SEEDS_GLOB = "cpg/ablation/seeds/*/results.csv"

# 空源样本（与 strict_recompute.py 的 INCOMPLETE 一致）
INCOMPLETE = {"CVE-2026-53500", "CVE-2026-59224", "CVE-2026-70485"}

# 匿名化：禁止出现在发布副本中的模式（**顺序敏感**：URL 必须先于用户名替换）
_PII_PATTERNS = [
    (re.compile(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", re.I), "<REPO_URL>"),
    (re.compile(r"[A-Za-z]:[\\/]{1,2}Users[\\/]{1,2}[^\\/\s\"']+", re.I), "<USER_HOME>"),
    (re.compile(r"/c/Users/[^/\s\"']+", re.I), "<USER_HOME>"),
    (re.compile(r"\blauyy32\b", re.I), "<ANON>"),
]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rel(p) -> str:
    p = Path(p)
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.resolve().as_posix()


# ---------------------------------------------------------------------------
# 1) 权威输入
# ---------------------------------------------------------------------------
def load_authoritative() -> dict:
    """读取权威复算输出 + 数字账本（缺任一份即 fail-closed）。"""
    missing = [str(p) for p in (AUTH_OUT, CLAIMS) if not p.exists()]
    if missing:
        raise FileNotFoundError(f"缺权威输入: {missing}")
    return {
        "recompute": json.loads(AUTH_OUT.read_text(encoding="utf-8")),
        "claims": json.loads(CLAIMS.read_text(encoding="utf-8")),
        "sources": {"recompute": _rel(AUTH_OUT), "recompute_sha256": _sha(AUTH_OUT.read_bytes()),
                    "claims": _rel(CLAIMS), "claims_sha256": _sha(CLAIMS.read_bytes())},
    }


def verify_against_claims(auth: dict) -> list:
    """逐条把报告将引用的数字对账到 claims.expect（fail-closed）。"""
    errs, rec, claims = [], auth["recompute"], {c["id"]: c for c in auth["claims"]["claims"]}

    def _chk(cid, got):
        it = claims.get(cid)
        if it is None:
            errs.append(f"claims 缺 {cid}")
            return
        want = it["expect"]
        if got != want:
            errs.append(f"{cid}: 复算 {got} != claims {want}")

    _chk("local7b_strict_disc_d1", rec["disc_strict"]["7B v9 D1"]["strict_count"])
    _chk("local14b_strict_disc_74", rec["disc_strict"]["14B v9 74"]["strict_count"])
    _chk("frontier_strict_disc_r1", rec["disc_strict"]["DS r1"]["strict_count"])
    m = rec["mcnemar"]["DS r1"]
    _chk("frontier_vs_local_mcnemar", {"b": m["b"], "c": m["c"], "p": m["p"]})
    d1 = rec["directional"]["DS r1"]
    _chk("frontier_directional_r1", {"correct": d1["correct"], "inverted": d1["inverted"],
                                     "answered_pairs": d1["answered_pairs"], "p": d1["p"]})
    d2 = rec["directional"]["DS r2"]
    _chk("frontier_directional_r2", {"correct": d2["correct"], "inverted": d2["inverted"],
                                     "answered_pairs": d2["answered_pairs"], "p": d2["p"]})
    ab = rec["abstain"]
    _chk("frontier_abstain_genuine_rate",
         {"genuine": ab["genuine"], "total": ab["total"], "rate": ab["rate"]})
    return errs


# ---------------------------------------------------------------------------
# 2) 列联表（按 scorer × mode）
# ---------------------------------------------------------------------------
def load_rows(seeds: list | None = None) -> list:
    """加载 seeds CSV。

    **重要**：`seeds/*/results.csv` 是**不同实验配置**（A1/A2/A3、B*、v8_*、v9_*、v13_*…），
    同一 `(scorer, sample_id, version)` 会在多个配置中出现。**跨配置直接叠加会重复计数**
    （曾导致 41× 重复）。因此：
      - 传入 `seeds`（目录名列表）时只读这些配置；
      - 不传时返回**全部**行，但每行带 `_seed` 标记，供调用方分组/去重。
    """
    rows = []
    for p in sorted(glob.glob(str(ROOT / SEEDS_GLOB))):
        seed = Path(p).parent.name
        if seeds is not None and seed not in seeds:
            continue
        with open(p, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                r["_seed"] = seed
                rows.append(r)
    return rows


def seed_index() -> list:
    """列出所有可用 seed 配置目录名。"""
    return sorted({Path(p).parent.name for p in glob.glob(str(ROOT / SEEDS_GLOB))})


def contingency(rows: list) -> dict:
    """列联表：`(scorer, mode)` → {truth → {predicted → count}}，并附完整性断言。"""
    tbl = defaultdict(lambda: defaultdict(Counter))
    for r in rows:
        if r.get("sample_id") in INCOMPLETE:
            continue
        tbl[(r["scorer"], r["mode"])][r["truth"]][r["predicted"]] += 1
    out = {}
    for (scorer, mode), bytruth in sorted(tbl.items()):
        out[f"{scorer}|{mode}"] = {t: dict(sorted(c.items())) for t, c in sorted(bytruth.items())}
    return out


# 工具族横评的权威配置（74 集 × 2 版本 × 5 个 scorer，全 code 模式）
REFERENCE_TOOL_FAMILY_SEED = "v8_74"


def pairing_integrity(rows: list, strict_seeds: list | None = None) -> list:
    """配对完整性检查（**按 seed 分组**，不同配置互不干扰）。

    真实数据中部分配置只跑了单侧（如 devign 样本无配对），因此：
      - 返回**违规清单**；调用方决定处置；
      - `strict_seeds` 中的配置若出现任何非配对条目，视为**硬错误**（由调用方 fail-closed）。
    """
    errs = []
    by = defaultdict(Counter)
    for r in rows:
        if r.get("sample_id") in INCOMPLETE or r["mode"] != "code":
            continue
        by[(r.get("_seed", "?"), r["scorer"], r["sample_id"])][r["version"]] += 1
    for (seed, scorer, sid), c in by.items():
        bad = c.get("vuln", 0) != 1 or c.get("fixed", 0) != 1
        if not bad:
            continue
        msg = f"{seed}/{scorer}/{sid}: vuln={c.get('vuln',0)} fixed={c.get('fixed',0)}"
        if strict_seeds and seed in set(strict_seeds):
            errs.append(msg)
        else:
            errs.append(f"[non-reference] {msg}")
    return errs


def strict_pairing_errors(rows: list, seeds: list) -> list:
    """参考配置下**必须**配对完整：任何异常都是硬错误。"""
    by = defaultdict(Counter)
    for r in rows:
        if r.get("sample_id") in INCOMPLETE or r["mode"] != "code":
            continue
        if r.get("_seed") not in set(seeds):
            continue
        by[(r.get("_seed"), r["scorer"], r["sample_id"])][r["version"]] += 1
    errs = []
    for (seed, scorer, sid), c in by.items():
        if c.get("vuln", 0) != 1 or c.get("fixed", 0) != 1:
            errs.append(f"{seed}/{scorer}/{sid}: vuln={c.get('vuln',0)} fixed={c.get('fixed',0)}")
    return errs


# ---------------------------------------------------------------------------
# 3) CPG 分层（工具族 + 漏洞族）
# ---------------------------------------------------------------------------
CPG_TOOL_FAMILIES = {
    "CPGEvidenceScorer": "cpg_evidence",
    "CodeQLBaselineScorer": "codeql_baseline",
    "LocalLLMScorer": "local_llm",
    "StructuralHeuristicScorer": "structural_heuristic",
    "ConfigSigScorer": "config_signature",
}


def strict_discrimination_by_group(rows: list, key: str, seeds: list | None = None) -> dict:
    """分层 strict 判别数。

    **统计单位（P0-2 修复）**：`v8_74` 中同一 `sample_id/version` 有 **5 个 scorer**；
    若只用 `[group][sample_id][version]` 建字典，**后读的 scorer 会静默覆盖先读的**，
    得到的不是分层结果而是"某一行序 scorer"的结果。

    因此本函数**显式声明统计单位**：
      - `key="scorer"` → 每 scorer 一个单元（内部再按 sample/version 聚合，安全）；
      - `key="group"`  → 输出 **scorer × vuln_group 二维分层**（每个 scorer 内再分组）；
      - `key="seed"`   → 每 seed 一个单元。
    第二维固定为 `scorer`，**不再让 scorer 之间互相覆盖**。
    """
    if key not in ("scorer", "group", "seed"):
        raise ValueError("key 只能是 scorer / group / seed")
    present = {r.get("_seed") for r in rows if r.get("_seed")}
    if seeds is None and len(present) > 1:
        raise ValueError(f"rows 含 {len(present)} 个 seed 配置，必须显式指定 seeds（防重复计数）")
    use = rows if seeds is None else [r for r in rows if r.get("_seed") in set(seeds)]

    # 二维键：主维度 × scorer（scorer 永远是第二维，杜绝静默覆盖）
    by = defaultdict(lambda: defaultdict(dict))
    for r in use:
        if r.get("sample_id") in INCOMPLETE or r["mode"] != "code":
            continue
        main = r[key]
        by[(main, r["scorer"])][r["sample_id"]][r["version"]] = r["predicted"]

    # 输出：scorer 层聚合 + （key=group 时）主维度再分解
    per_scorer = defaultdict(lambda: defaultdict(dict))
    for (main, scorer), samples in by.items():
        per_scorer[scorer][main] = samples
    out = {}
    for scorer, groups in sorted(per_scorer.items()):
        label_s = CPG_TOOL_FAMILIES.get(scorer, scorer) if key == "scorer" else scorer
        if key == "scorer":
            n = ok = inv = 0
            for _g, samples in groups.items():
                a, b, c = _count_samples(samples)
                n += a; ok += b; inv += c
            lo, hi = clopper_pearson(ok, n)
            out[label_s] = {"n": n, "strict_disc": ok, "inverted": inv,
                            "rate": round(ok / n, 6) if n else None, "ci95_exact": [lo, hi]}
        else:
            for main, samples in sorted(groups.items()):
                label_m = CPG_TOOL_FAMILIES.get(main, main) if key == "seed" else main
                n, ok, inv = _count_samples(samples)
                lo, hi = clopper_pearson(ok, n)
                out[f"{label_s}|{label_m}"] = {
                    "scorer": label_s, "unit": label_m,
                    "n": n, "strict_disc": ok, "inverted": inv,
                    "rate": round(ok / n, 6) if n else None, "ci95_exact": [lo, hi]}
    return out


def _count_samples(samples: dict) -> tuple:
    """统计一个 {sample_id: {version: predicted}} 组的 (n, strict, inverted)。"""
    n = ok = inv = 0
    for _sid, v in samples.items():
        if "vuln" not in v or "fixed" not in v:
            continue
        n += 1
        if v["vuln"] == "vulnerable" and v["fixed"] == "benign":
            ok += 1
        elif v["vuln"] == "benign" and v["fixed"] == "vulnerable":
            inv += 1
    return n, ok, inv


# ---------------------------------------------------------------------------
# 4) exact CI / McNemar（与 strict_recompute.py 同口径纯实现）
# ---------------------------------------------------------------------------
def _binom_cdf_le(x: int, n: int, p: float) -> float:
    """P(X <= x)（二项）—— 与 strict_recompute.py 的 ble 同口径。"""
    return sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(0, x + 1))


def _binom_sf_ge(x: int, n: int, p: float) -> float:
    """P(X >= x)（二项）—— 与 strict_recompute.py 的 bge 同口径。"""
    return sum(math.comb(n, k) * p ** k * (1 - p) ** (n - k) for k in range(x, n + 1))


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple:
    """**委托 `v4_scaffold` 的唯一实现**（避免两份 CP 实现产生口径分歧）。

    历史：此处曾有一份 Beta 连分数实现，在 `a≫b`（如 k=7,n=82）时不收敛返回 1.0；
    已废弃并统一到 scaffold 的二项尾概率二分实现（与权威脚本逐位一致）。
    """
    from cpg.ablation.v4_scaffold import clopper_pearson as _cp
    return _cp(k, n, alpha)


def mcnemar_one_sided(b: int, c: int) -> float:
    """单侧精确 McNemar（与 strict_recompute.py 口径一致）。"""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    return sum(math.comb(n, i) for i in range(0, k + 1)) / (2 ** n)


# ---------------------------------------------------------------------------
# 5) 匿名化
# ---------------------------------------------------------------------------
def anonymize(obj):
    """递归把可反查信息替换为中性占位符（字符串/键名均处理）。"""
    if isinstance(obj, dict):
        return {anonymize(k) if isinstance(k, str) else k: anonymize(v)
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [anonymize(x) for x in obj]
    if isinstance(obj, str):
        s = obj
        for pat, rep in _PII_PATTERNS:
            s = pat.sub(rep, s)
        return s
    return obj


def anonymize_check(doc) -> list:
    """fail-closed：发布副本中不得残留任何 PII 模式。"""
    text = json.dumps(doc, ensure_ascii=False)
    errs = []
    for pat, rep in _PII_PATTERNS:
        m = pat.search(text)
        if m:
            errs.append(f"残留 PII 模式 {rep}: {m.group(0)[:40]}")
    return errs


# ---------------------------------------------------------------------------
# 6) 报告
# ---------------------------------------------------------------------------
def build_report(publish: bool = False) -> dict:
    """生成 RQ1-R 正式报告（`publish=True` 时输出匿名副本）。"""
    auth = load_authoritative()
    errs = verify_against_claims(auth)
    if errs:
        raise ValueError("数字对账失败（fail-closed）: " + "; ".join(errs[:5]))

    available = seed_index()
    if REFERENCE_TOOL_FAMILY_SEED not in available:
        raise ValueError(f"缺工具族横评配置 {REFERENCE_TOOL_FAMILY_SEED}（无法做 CPG 分层）")
    ref_rows = load_rows(seeds=[REFERENCE_TOOL_FAMILY_SEED])
    # 参考配置：**硬要求**配对完整（否则 fail-closed）
    ref_err = strict_pairing_errors(ref_rows, [REFERENCE_TOOL_FAMILY_SEED])
    if ref_err:
        raise ValueError(f"参考配置配对完整性失败（fail-closed）: {ref_err[:3]}")
    # 其它配置：真实数据中存在单侧样本，仅记录为 warning，不影响参考分析
    warnings = [w for w in pairing_integrity(load_rows()) if w.startswith("[non-reference]")]

    rec, claims = auth["recompute"], auth["claims"]["claims"]
    doc = {
        # P0-1：本报告基于**历史** claims/seeds 口径，**不是** canonical r1 的正式结果
        "schema": "v4-rq1r-historical-supplement/1",
        "artifact_kind": "historical_tool_family_supplement",
        "NOT_THE_CANONICAL_RQ1R": True,
        "disclaimer": (
            "本工件为**历史口径补充分析**（数据源：strict_recompute_out.json / claims.json / "
            "seeds/v8_74），**不得**用作 RQ1-R 正式主结果。正式主结果必须消费新的 canonical "
            "运行目录（rq1-r-canonical-v4/：protocol.json / lock_request.json / "
            "review_approval.json / results.jsonl / summary.json）。两者数字不同 "
            "（历史 2/82 vs canonical 1/82），混用会造成口径污染。"),
        "protocol": {
            "strict_rule": "判别 = vuln 显式 vulnerable 且 fixed 显式 benign；abstain 不计任何一侧",
            "lenient_note": "lenient（abstain→非 vuln）仅作规则敏感性申报，不用于结论",
            "incomplete_excluded": sorted(INCOMPLETE),
        },
        "data_scope": {
            "tool_family_reference_seed": REFERENCE_TOOL_FAMILY_SEED,
            "tool_family_reason": "该配置为 74 集 × 2 版本 × 5 个工具族（全 code 模式），"
                                  "是唯一覆盖全部工具族的横评配置",
            "available_seeds": available,
            "cross_seed_note": "不同 seed 为不同实验配置，**不得跨配置叠加计数**",
        },
        "sources": auth["sources"],
        "claims_reconciled": True,
        "headline": {
            "local_7b_strict": rec["disc_strict"]["7B v9 D1"],
            "local_14b_strict": rec["disc_strict"]["14B v9 74"],
            "frontier_r1_strict": rec["disc_strict"]["DS r1"],
            "frontier_r2_strict": rec["disc_strict"]["DS r2"],
            "mcnemar_frontier_vs_local_r1": rec["mcnemar"]["DS r1"],
            "directional_r1": rec["directional"]["DS r1"],
            "directional_r2": rec["directional"]["DS r2"],
            "abstain_genuine": rec["abstain"],
        },
        "exact_ci": {
            "local_7b": clopper_pearson(rec["disc_strict"]["7B v9 D1"]["strict_count"],
                                        rec["disc_strict"]["7B v9 D1"]["n"]),
            "local_14b": clopper_pearson(rec["disc_strict"]["14B v9 74"]["strict_count"],
                                         rec["disc_strict"]["14B v9 74"]["n"]),
            "frontier_r1": clopper_pearson(rec["disc_strict"]["DS r1"]["strict_count"],
                                           rec["disc_strict"]["DS r1"]["n"]),
            "frontier_r2": clopper_pearson(rec["disc_strict"]["DS r2"]["strict_count"],
                                           rec["disc_strict"]["DS r2"]["n"]),
        },
        "stratified_by_tool_family": strict_discrimination_by_group(
            ref_rows, "scorer", seeds=[REFERENCE_TOOL_FAMILY_SEED]),
        "stratified_by_vuln_group": strict_discrimination_by_group(
            ref_rows, "group", seeds=[REFERENCE_TOOL_FAMILY_SEED]),
        "contingency_by_scorer_mode": contingency(ref_rows),
        "pairing_integrity_ok": True,
        "non_reference_pairing_warnings": {
            "n": len(warnings),
            "note": "非参考配置中存在单侧样本（真实数据特性）；参考配置已硬校验通过",
            "sample": warnings[:5],
        },
        "claims_ledger": [{"id": c["id"], "desc": c["desc"], "expect": c["expect"]}
                          for c in claims],
    }
    if publish:
        pub = anonymize(doc)
        pub["schema"] = "v4-rq1r-historical-supplement-public/1"
        pub["artifact_kind"] = "historical_tool_family_supplement"
        pub["anonymized"] = True
        aerr = anonymize_check(pub)
        if aerr:
            raise ValueError("匿名化失败（fail-closed）: " + "; ".join(aerr))
        return pub
    return doc


def write_reports() -> dict:
    """写两份：内部版 + 匿名发布版（**历史补充**命名，避免与正式 RQ1-R 混淆）。"""
    internal = build_report(publish=False)
    public = build_report(publish=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "rq1r_historical_supplement.json").write_bytes(
        (json.dumps(internal, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    (OUT / "rq1r_historical_supplement_public.json").write_bytes(
        (json.dumps(public, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return {"internal": internal, "public": public}
