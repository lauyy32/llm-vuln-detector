# -*- coding: utf-8 -*-
"""指令 5：历史 prompt 等价门禁（只生成与比较 prompt，严禁调用模型）。

比较历史 `v10_d1_7b` 的 170 份 prompt 与当前 `legacy-rq1-r0 + corpus-v3` 重生成
prompt，判断历史表示能否字节级复现。

范围恒等式（机器断言）：
    历史 85 × 2 = 170 = 当前 eligible 82 × 2 (=164) + 排除 3 × 2 (=6)

source_status 必须**按 side** 比较历史树 SHA 与 v3 树 SHA：
    UNCHANGED / CHANGED / UNKNOWN
禁止用 `in_85` 或"14 个修复样本名单"作为判定依据（只可作交叉核验）。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# 与 prompt_renderer 实际渲染一致（已核实：prompt_renderer.py:59/64/25）
CODE_START = "\n# 目标代码（节选）\n```\n"
CODE_END = "\n```\n"
CPG_START = "\n# 代码级上下文（CPG 污点切片）\n"
OUTPUT_START = "\n# 输出要求\n"

HISTORICAL_COMMIT = "2133a35cc54349cf5adc50aefdc4309063907656"
EXCLUDED = {
    "CVE-2026-53656": "COMPOSITE_FIX_COMMIT",
    "CVE-2026-70486": "CROSS_LANGUAGE_OUT_OF_SCOPE",
    "CVE-2026-70492": "CROSS_LANGUAGE_OUT_OF_SCOPE",
}


def sha_text(value):
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


_TREE_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def valid_tree_sha(value):
    """合法 tree SHA：非空、64 位小写 hex。canonical 的 eligible side 必须满足。"""
    return isinstance(value, str) and _TREE_SHA_RE.fullmatch(value) is not None


def load_historical_index(raw_path: Path, results_path: Path, expect: int = 170):
    """raw 与 results.csv 的 LocalLLMScorer 行按索引连接（不假设奇偶 side）。"""
    raw_rows = [json.loads(l) for l in
                raw_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    with results_path.open(encoding="utf-8", newline="") as fh:
        result_rows = [r for r in csv.DictReader(fh)
                       if r.get("scorer") == "LocalLLMScorer"]
    if len(raw_rows) != expect or len(result_rows) != expect:
        raise RuntimeError(
            f"历史行数错误: raw={len(raw_rows)}, LocalLLM={len(result_rows)}, 期望 {expect}")
    index = {}
    for i, (raw, res) in enumerate(zip(raw_rows, result_rows)):
        if raw["cve_id"] != res["sample_id"]:
            raise RuntimeError(f"第{i}行 CVE 不一致: {raw['cve_id']} vs {res['sample_id']}")
        if raw["mode"] != res["mode"]:
            raise RuntimeError(f"第{i}行 mode 不一致")
        side = res["version"]
        if side not in ("vuln", "fixed"):
            raise RuntimeError(f"第{i}行 side 非法: {side}")
        key = (raw["cve_id"], side, raw["mode"])
        if key in index:
            raise RuntimeError(f"历史键重复: {key}")
        index[key] = {"historical_row_index": i, "prompt": raw["prompt"]}
    return index


def split_prompt(prompt: str) -> dict:
    """分层解析 prompt（不靠正则猜 side/版本）。"""
    code_text = None
    cpg_text = None
    if CODE_START in prompt:
        _, after = prompt.split(CODE_START, 1)
        if CODE_END not in after:
            raise RuntimeError("代码围栏未闭合")
        code_text, remainder = after.split(CODE_END, 1)
    else:
        remainder = prompt
    if CPG_START in remainder:
        _, after_cpg = remainder.split(CPG_START, 1)
        if OUTPUT_START not in after_cpg:
            raise RuntimeError("CPG 段缺少输出契约")
        cpg_text, _ = after_cpg.split(OUTPUT_START, 1)
    return {"code_text": code_text, "cpg_slices": cpg_text}


def parse_flow_blocks(cpg_text):
    """解析完整 flow block（以 '### CWE' 开头，至下一个块或结束）。

    不能按"所有文本行排序"比较：那会把不同块的行重新拼配后误报等价。
    """
    if not cpg_text:
        return []
    blocks = []
    cur = None
    for line in cpg_text.splitlines(keepends=True):
        if line.startswith("### "):
            if cur is not None:
                blocks.append(cur)
            cur = line
        elif cur is not None:
            cur += line
    if cur is not None:
        blocks.append(cur)
    return blocks


def classify_source(old_sha, new_sha):
    """按 side 判定：无权威历史证据 → UNKNOWN（不得默认 unchanged）。"""
    if not old_sha:
        return "UNKNOWN"
    if old_sha == new_sha:
        return "UNCHANGED"
    return "CHANGED"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", type=Path,
                    default=ROOT / "cpg/ablation/seeds/v10_d1_7b/raw_llm_responses.jsonl")
    ap.add_argument("--results", type=Path,
                    default=ROOT / "cpg/ablation/seeds/v10_d1_7b/results.csv")
    ap.add_argument("--regenerated-manifest", type=Path, required=True,
                    help="新目录 prompt_manifest.jsonl（prepare 产出）")
    ap.add_argument("--canonical-manifest", type=Path, required=True,
                    help="canonical_corpus_manifest.json（成员与排除原因的唯一权威）")
    ap.add_argument("--historical-source", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/historical_v1_source_manifest.jsonl")
    ap.add_argument("--expect-historical", type=int, default=170,
                    help="历史记录数期望（真实为 170；测试可传 fixture 实际条数）")
    ap.add_argument("--out", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/historical_prompt_equivalence.jsonl")
    ap.add_argument("--summary", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/historical_prompt_equivalence_summary.json")
    args = ap.parse_args(argv)

    index = load_historical_index(args.raw, args.results, args.expect_historical)

    # canonical 是成员与排除原因的唯一权威；硬编码表降级为交叉断言
    cm = json.loads(args.canonical_manifest.read_text(encoding="utf-8"))
    canon_elig = {s["sample_id"] for s in cm["samples"] if s.get("eligible")}
    canon_excl = {s["sample_id"]: (s.get("exclusion_reason") or "UNSPECIFIED")
                  for s in cm["samples"] if not s.get("eligible")}
    canon_tree = {(s["sample_id"], side): s.get(f"{side}_tree_sha256_lf")
                  for s in cm["samples"] for side in ("vuln", "fixed")}
    if set(EXCLUDED) != set(canon_excl):
        print(f"[FAIL] 硬编码排除表与 canonical 不一致: "
              f"表多={sorted(set(EXCLUDED) - set(canon_excl))} "
              f"canonical多={sorted(set(canon_excl) - set(EXCLUDED))}")
        return 2
    # 缺口4：canonical 每个 eligible side 的树 SHA 必须合法 64 位 hex，缺失/非法即独立失败
    for c in sorted(canon_elig):
        for side in ("vuln", "fixed"):
            v = canon_tree.get((c, side))
            if not valid_tree_sha(v):
                print(f"[FAIL] canonical 树 SHA 缺失/非法: {c}/{side} = {v!r}")
                return 2

    # 历史源码证据（side 级；缺失即 UNKNOWN）
    hist_src = {}
    if args.historical_source.exists():
        for line in args.historical_source.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                key = (r["sample_id"], r["side"])
                if key in hist_src:
                    print(f"[FAIL] 历史 source manifest 重复键: {key}")
                    return 2
                hist_src[key] = r.get("tree_sha256_lf")

    # 重生成 manifest
    regen = {}
    for line in args.regenerated_manifest.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            key = (r["sample_id"], r["side"])
            if key in regen:
                print(f"[FAIL] 重生成 manifest 重复键: {key}")
                return 1
            regen[key] = r

    # regen 集合必须恰好等于 canonical eligible × {vuln, fixed}（不多不少）
    regen_keys = set(regen)
    want_keys = {(c, s) for c in canon_elig for s in ("vuln", "fixed")}
    if regen_keys != want_keys:
        print(f"[FAIL] regen 集合 != canonical eligible×sides: "
              f"多={sorted(regen_keys - want_keys)[:3]} "
              f"缺={sorted(want_keys - regen_keys)[:3]}")
        return 2

    run_dir = args.regenerated_manifest.parent
    comparisons = []
    excluded_rows = []
    for (cve, side, mode), h in sorted(index.items()):
        row = {
            "sample_id": cve, "side": side, "mode": mode,
            "historical_row_index": h["historical_row_index"],
            "historical_prompt_sha256": sha_text(h["prompt"]),
        }
        # 排除判定以 canonical eligible 为准（硬编码表已交叉断言为一致）
        if cve not in canon_elig:
            row["exclusion_reason"] = canon_excl.get(cve, "NOT_IN_CANONICAL")
            excluded_rows.append(row)
            continue
        reg = regen.get((cve, side))
        if reg is None:
            print(f"[FAIL] 重生成缺失: {cve}/{side}")
            return 2
        # 重生成 prompt：先校验磁盘内容与冻结 SHA 一致
        ppath = run_dir / reg["prompt_path"]
        actual = sha_text(ppath.read_text(encoding="utf-8"))
        if actual != reg["prompt_sha256"]:
            print(f"[FAIL] 重生成 prompt SHA 漂移: {cve}/{side}")
            return 2
        # regen 的 source_tree_sha 必须等于 canonical 对应 side 树哈希（want_tree 已保证合法）
        want_tree = canon_tree.get((cve, side))
        if reg.get("source_tree_sha256") != want_tree:
            print(f"[FAIL] regen source_tree_sha 与 canonical 不符: {cve}/{side} "
                  f"(regen={reg.get('source_tree_sha256')!r} want={want_tree!r})")
            return 2
        regen_prompt = ppath.read_text(encoding="utf-8")
        hs = split_prompt(h["prompt"])
        rs = split_prompt(regen_prompt)
        row.update({
            "historical_tree_sha256_lf": hist_src.get((cve, side)),
            "canonical_tree_sha256_lf": reg.get("source_tree_sha256"),
            "source_status": classify_source(hist_src.get((cve, side)),
                                             reg.get("source_tree_sha256")),
            "regenerated_prompt_sha256": actual,
            "prompt_exact_match": h["prompt"] == regen_prompt,
            "historical_code_text_sha256": sha_text(hs["code_text"]),
            "regenerated_code_text_sha256": sha_text(rs["code_text"]),
            "code_text_changed": hs["code_text"] != rs["code_text"],
            "historical_cpg_slices_sha256": sha_text(hs["cpg_slices"]),
            "regenerated_cpg_slices_sha256": sha_text(rs["cpg_slices"]),
            "cpg_slices_changed": hs["cpg_slices"] != rs["cpg_slices"],
        })
        layers = []
        if row["source_status"] != "UNCHANGED":
            layers.append("source")
        if row["code_text_changed"]:
            layers.append("code_text")
        if row["cpg_slices_changed"]:
            layers.append("cpg_slices")
        if not row["prompt_exact_match"] and not layers:
            layers.append("renderer_or_metadata")
        row["mismatch_layer"] = layers
        # 次级诊断：区分"仅 CPG 流块顺序不同"与真实内容差异。
        # 仅用于解释失败，不改变 Gate 判定（UNCHANGED 侧不字节相等即 FAIL）。
        if row["prompt_exact_match"]:
            row["difference_type"] = None
            row["semantic_multiset_match"] = True
        elif (hs["code_text"] == rs["code_text"]
              and Counter(parse_flow_blocks(hs["cpg_slices"]))
                == Counter(parse_flow_blocks(rs["cpg_slices"]))):
            # block 级多重集合相同 → 仅顺序不同（CodeQL 流顺序跨运行不稳定）
            row["difference_type"] = "CPG_ORDER_ONLY"
            row["semantic_multiset_match"] = True
        else:
            row["difference_type"] = "CONTENT_DIFF"
            row["semantic_multiset_match"] = False
        row["ordered_exact_match"] = row["prompt_exact_match"]
        comparisons.append(row)

    # 范围恒等式
    if len(comparisons) + len(excluded_rows) != args.expect_historical:
        print(f"[FAIL] 范围恒等式失败: {len(comparisons)} + {len(excluded_rows)} "
              f"!= {args.expect_historical}")
        return 2
    # 排除记录必须恰好 = canonical 排除 CVE 数 × 2 side（缺口3：不得隐式固定为 6）
    expected_excluded = 2 * len(canon_excl)
    if len(excluded_rows) != expected_excluded:
        print(f"[FAIL] 排除记录应为 {expected_excluded}，实际 {len(excluded_rows)}")
        return 2

    gate_errors = []
    for r in comparisons:
        if r["source_status"] == "UNCHANGED" and not r["prompt_exact_match"]:
            gate_errors.append(
                f"{r['sample_id']}/{r['side']}: UNCHANGED source 但 prompt 不等价"
                f"（层={r['mismatch_layer']}）")
    unchanged = [r for r in comparisons if r["source_status"] == "UNCHANGED"]
    summary = {
        "historical_total": args.expect_historical,
        "eligible_prompt_total": len(comparisons),
        "excluded_historical_total": len(excluded_rows),
        "unchanged_total": len(unchanged),
        "unchanged_exact_match": sum(1 for r in unchanged if r["prompt_exact_match"]),
        "changed_total": sum(1 for r in comparisons if r["source_status"] == "CHANGED"),
        "unknown_total": sum(1 for r in comparisons if r["source_status"] == "UNKNOWN"),
        "code_text_changed_total": sum(1 for r in comparisons if r["code_text_changed"]),
        "cpg_slices_changed_total": sum(1 for r in comparisons if r["cpg_slices_changed"]),
        "prompt_mismatch_total": sum(1 for r in comparisons if not r["prompt_exact_match"]),
        "gate_pass": not gate_errors,
        "gate_errors": gate_errors[:20],
        "historical_commit": HISTORICAL_COMMIT,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                  for r in comparisons + excluded_rows) + "\n",
                        encoding="utf-8")
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["gate_pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
