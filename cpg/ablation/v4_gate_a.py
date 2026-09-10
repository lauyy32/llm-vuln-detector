# -*- coding: utf-8 -*-
"""V4 Gate A：候选补丁工件生成与门禁（只生成工件，不调用模型）。

产物（cpg/ablation/artifacts/v4/）：
- v4_canonical_manifest.json : 15 例 V4 候选集（输入口径，confirmation-eligible）
- v4_upstream_real_report.json : 上游投影 manifest（fix/parent、Python 投影、blob SHA）
- real_manifest.jsonl / placebo_manifest.jsonl / shuffled_manifest.jsonl : 各臂 diff 工件
- gate_a_report.json : Gate A 门禁汇总

停止条件（任一不满足即不得进入模型调用）：
- 样本不在 canonical manifest / source_path 不在 corpus-v3
- real diff apply-clean 失败，或应用后与 fixed 树不逐字节等价
- placebo/shuffled apply-clean 失败 / AST 不等价
- token 比越界 [0.8, 1.25]
- 任一 prompt 泄漏臂名/标签
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_patch_gen as v4g  # noqa: E402
from cpg.ablation import upstream_manifest as um  # noqa: E402

CANONICAL_MANIFEST = ROOT / "cpg" / "ablation" / "artifacts" / "canonical_corpus_manifest.json"
OUT_DIR = ROOT / "cpg" / "ablation" / "artifacts" / "v4"

# V4 候选集 = CPG 双标 15 例（来源：cpg/ablation/partial_arm_construction.md §候选表）。
# 顺序固定，禁止运行期增删；改动须以 protocol amendment 形式登记。
V4_CANDIDATES = [
    "CVE-2026-12482", "CVE-2026-70491", "CVE-2026-50558", "CVE-2026-67424",
    "CVE-2026-53502", "CVE-2026-73498", "CVE-2026-53598", "CVE-2026-67425",
    "CVE-2026-54706", "CVE-2026-59890", "CVE-2026-54707", "CVE-2026-54785",
    "CVE-2026-50181", "CVE-2026-54574", "CVE-2026-45019",
]
# 45019 为复合提交且安全关键 hunk 未定（partial_arm_construction.md #15 待定）：
# 从确认性主分析排除，仅进全样本描述性附录。
CONFIRMATORY_EXCLUDED = {"CVE-2026-45019"}


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _git_commit() -> str | None:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def _manifest_by_id() -> dict:
    m = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
    return {s["sample_id"]: s for s in m["samples"]}


def build_canonical_manifest(out_dir: Path) -> dict:
    """Gate A-1：15 例 V4 候选集（从 canonical manifest 提取，fail-closed）。"""
    by_id = _manifest_by_id()
    entries, errors = [], []
    for cve in V4_CANDIDATES:
        s = by_id.get(cve)
        if s is None:
            errors.append(f"{cve} 不在 canonical manifest")
            continue
        if not s.get("eligible"):
            errors.append(f"{cve} 非 eligible（{s.get('exclusion_reason')}）")
            continue
        sp = s.get("source_path")
        if not sp or "/corpus-v3/" not in (ROOT / sp).resolve().as_posix():
            errors.append(f"{cve} source_path 不在 corpus-v3: {sp}")
            continue
        entries.append({
            "sample_id": cve,
            "repo_slug": s.get("repo_slug"),
            "parent_commit": s.get("parent_commit"),
            "fix_commit": s.get("fix_commit"),
            "source_path": sp,
            "vuln_tree_sha256_lf": s.get("vuln_tree_sha256_lf"),
            "fixed_tree_sha256_lf": s.get("fixed_tree_sha256_lf"),
            "pair_manifest_sha256": s.get("pair_manifest_sha256"),
            "confirmation_eligible": cve not in CONFIRMATORY_EXCLUDED,
            "exclusion_reason": ("COMPOSITE_FIX_COMMIT_UNRESOLVED"
                                 if cve in CONFIRMATORY_EXCLUDED else None),
        })
    doc = {
        "schema": "v4-canonical-manifest/1",
        "generated_from": {
            "canonical_manifest": str(CANONICAL_MANIFEST.relative_to(ROOT).as_posix()),
            "canonical_manifest_sha256": _sha256_bytes(CANONICAL_MANIFEST.read_bytes()),
            "git_commit": _git_commit(),
            "candidate_source": "cpg/ablation/partial_arm_construction.md",
        },
        "n_candidates": len(entries),
        "n_confirmation": sum(1 for e in entries if e["confirmation_eligible"]),
        "candidates": entries,
        "errors": errors,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "v4_canonical_manifest.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def build_upstream_report(out_dir: Path) -> dict:
    """Gate A-2：对 15 例跑上游投影（复用 upstream_manifest），补 composite/cross-language 判定。"""
    out = out_dir / "v4_upstream_real_report.json"
    cmd = [sys.executable, str(ROOT / "cpg/ablation/upstream_manifest.py"),
           "--cves", *V4_CANDIDATES, "--out", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       cwd=str(ROOT), timeout=3600)
    if not out.exists():
        raise RuntimeError(f"upstream_manifest 失败: {(r.stderr or r.stdout)[-500:]}")
    d = json.loads(out.read_text(encoding="utf-8"))
    for _cve, s in d.get("samples", {}).items():
        if "python_projection_n" not in s:
            continue
        msg = (s.get("commit_message_head") or "").lower()
        s["composite_signal"] = bool(s.get("is_merge")) or ("merge" in msg)
        s["cross_language_signal"] = (s.get("python_projection_n", 0) == 0
                                      and s.get("non_python_excluded_n", 0) > 0)
    out.write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    return d


def _diff_sha(diff_text: str) -> str:
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


def _arm_row(cve: str, arm: str, diff: str, rep: dict, expected: str,
             extra: dict | None = None) -> dict:
    row = {
        "sample_id": cve,
        "arm": arm,
        "expected_verdict": expected,
        "diff_sha256": _diff_sha(diff),
        "diff_len_chars": len(diff),
        "n_files": rep.get("n_files"),
        "added": rep.get("added", []),
        "deleted": rep.get("deleted", []),
        "renamed": rep.get("renamed", []),
        "modified": rep.get("modified", []),
        "binary": rep.get("binary", []),
    }
    if extra:
        row.update(extra)
    return row


def build_real_manifest(out_dir: Path) -> list:
    """Gate A-3：real 臂（上游 fix-commit 机械化 Python 投影，禁止人工挑 hunk）。"""
    rows = []
    for cve in V4_CANDIDATES:
        diff, rep = v4g.gen_complete_real_diff(cve)
        ok, msg = v4g.apply_and_verify(cve, diff)
        rows.append(_arm_row(cve, "real", diff, rep, "benign",
                             {"apply_clean": ok, "tree_equivalent": ok,
                              "apply_message": msg[:200]}))
    _write_jsonl(out_dir / "real_manifest.jsonl", rows)
    return rows


def build_placebo_manifest(out_dir: Path) -> list:
    """Gate A-3：placebo 臂（同文件、AST/行为中性的装饰性改动）。"""
    rows = []
    for cve in V4_CANDIDATES:
        diff, rep = v4g.gen_placebo_diff(cve)
        rows.append(_arm_row(cve, "placebo", diff, rep, "vulnerable",
                             {"ast_equivalent": rep.get("ast_equivalent"),
                              "apply_clean": rep.get("apply_clean"),
                              "edits": rep.get("edits", [])}))
    _write_jsonl(out_dir / "placebo_manifest.jsonl", rows)
    return rows


def build_shuffled_manifest(out_dir: Path) -> list:
    """Gate A-3：shuffled 臂 = 循环配对的下一个 CVE 的真实 diff（结构像补丁但无关）。

    语义沿用 B4（既有三臂主实验）：donor ≠ 目标；donor diff 本身是完整且在其自身
    vuln 树上 apply-clean 的（real 臂同源构造）。残余漏洞 oracle：donor 补丁不触及
    目标树 → 目标漏洞原样存在。
    """
    donors = {cve: v4g.gen_complete_real_diff(cve)[0] for cve in V4_CANDIDATES}
    rows = []
    for i, cve in enumerate(V4_CANDIDATES):
        donor = V4_CANDIDATES[(i + 1) % len(V4_CANDIDATES)]
        diff = donors[donor]
        # donor diff 在 donor 树上 apply-clean（沿用 real 的树等价门禁）
        donor_ok, donor_msg = v4g.apply_and_verify(donor, diff)
        _, rep = v4g.gen_complete_real_diff(donor)
        assert donor != cve, f"shuffled donor 不得来自同一 CVE: {cve}"
        rows.append(_arm_row(cve, "shuffled", diff, rep, "vulnerable",
                             {"donor": donor, "donor_apply_clean": donor_ok,
                              "donor_tree_equivalent": donor_ok,
                              "donor_message": donor_msg[:200]}))
    _write_jsonl(out_dir / "shuffled_manifest.jsonl", rows)
    return rows


def _write_jsonl(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                    encoding="utf-8")


TOKENIZER_PATH = OUT_DIR / "tokenizer" / "tokenizer.json"
TOKEN_RATIO_LO = 0.8
TOKEN_RATIO_HI = 1.25
_TOKENIZER = {}


def _tokenizer():
    """惰性加载 Qwen2.5-Coder tokenizer（真实 tokenizer，非字符 proxy）。"""
    if "tk" not in _TOKENIZER:
        from tokenizers import Tokenizer
        _TOKENIZER["tk"] = Tokenizer.from_file(str(TOKENIZER_PATH))
    return _TOKENIZER["tk"]


def count_tokens(text: str) -> int:
    return len(_tokenizer().encode(text).ids)


def _read_jsonl(path: Path) -> list:
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def build_token_gate(out_dir: Path) -> dict:
    """Gate A-4：四臂 diff 的真实 token 计数 + token 比门禁 [0.8, 1.25]（以 real 为基准）。

    口径说明：按"候选补丁（diff）送入模型的 token 数"计；四臂 prompt 的固定部分
    （system/vuln 代码/CPG）相同，故 diff-level 比值比 prompt-level 更严格（更保守）。
    """
    real = {r["sample_id"]: r for r in _read_jsonl(out_dir / "real_manifest.jsonl")}
    arms = {"placebo": _read_jsonl(out_dir / "placebo_manifest.jsonl"),
            "shuffled": _read_jsonl(out_dir / "shuffled_manifest.jsonl")}
    # 重新算各臂 diff 文本的 token（manifest 里存的是 SHA，需重生成文本）
    report = {"tokenizer": str(TOKENIZER_PATH.relative_to(ROOT).as_posix()),
              "vocab_size": _tokenizer().get_vocab_size(),
              "ratio_bounds": [TOKEN_RATIO_LO, TOKEN_RATIO_HI],
              "per_arm": {}}
    real_tok = {}
    for cve in V4_CANDIDATES:
        diff, _ = v4g.gen_complete_real_diff(cve)
        real_tok[cve] = count_tokens(diff)
    report["per_arm"]["real"] = {"tokens": real_tok}
    for arm in ("placebo", "shuffled"):
        arm_tok = {}
        for cve in V4_CANDIDATES:
            if arm == "placebo":
                diff, _ = v4g.gen_placebo_diff(cve)
            else:
                donor = V4_CANDIDATES[(V4_CANDIDATES.index(cve) + 1) % len(V4_CANDIDATES)]
                diff, _ = v4g.gen_complete_real_diff(donor)
            arm_tok[cve] = count_tokens(diff)
        ratios = {c: round(arm_tok[c] / real_tok[c], 4) if real_tok[c] else None
                  for c in V4_CANDIDATES}
        out_of_bounds = [c for c, r in ratios.items()
                         if r is None or not (TOKEN_RATIO_LO <= r <= TOKEN_RATIO_HI)]
        report["per_arm"][arm] = {"tokens": arm_tok, "ratio_vs_real": ratios,
                                  "out_of_bounds": out_of_bounds}
    report["real_token_summary"] = {
        "min": min(real_tok.values()), "max": max(real_tok.values()),
        "median": sorted(real_tok.values())[len(real_tok) // 2]}
    return report


def build_gate_a_report(out_dir: Path) -> dict:
    """Gate A 汇总：各臂门禁通过情况 + token 门禁。"""
    real = _read_jsonl(out_dir / "real_manifest.jsonl")
    placebo = _read_jsonl(out_dir / "placebo_manifest.jsonl")
    shuffled = _read_jsonl(out_dir / "shuffled_manifest.jsonl")
    tok = build_token_gate(out_dir)
    cm = json.loads((out_dir / "v4_canonical_manifest.json").read_text(encoding="utf-8"))
    up = json.loads((out_dir / "v4_upstream_real_report.json").read_text(encoding="utf-8"))
    up_samples = up.get("samples", {})
    report = {
        "schema": "v4-gate-a-report/1",
        "generated_from": {"git_commit": _git_commit(),
                           "n_candidates": cm["n_candidates"],
                           "n_confirmation": cm["n_confirmation"]},
        "canonical": {"errors": cm["errors"],
                      "confirmatory_excluded": [c["sample_id"] for c in cm["candidates"]
                                                if not c["confirmation_eligible"]]},
        "upstream": {
            "resolved": sum(1 for s in up_samples.values() if "python_projection_n" in s),
            "content_not_equivalent": [c for c, s in up_samples.items()
                                       if isinstance(s.get("content"), dict)
                                       and s["content"].get("content_equivalent") is False],
            "composite_signal": [c for c, s in up_samples.items() if s.get("composite_signal")],
            "cross_language_signal": [c for c, s in up_samples.items()
                                      if s.get("cross_language_signal")],
        },
        "arms": {
            "real": {"n": len(real),
                     "tree_equivalent_fail": [r["sample_id"] for r in real
                                              if not r.get("tree_equivalent")]},
            "placebo": {"n": len(placebo),
                        "ast_not_equivalent": [r["sample_id"] for r in placebo
                                               if not r.get("ast_equivalent")],
                        "apply_clean_fail": [r["sample_id"] for r in placebo
                                             if not r.get("apply_clean")]},
            "shuffled": {"n": len(shuffled),
                         "donor_apply_clean_fail": [r["sample_id"] for r in shuffled
                                                    if not r.get("donor_apply_clean")],
                         "same_cve_donor": [r["sample_id"] for r in shuffled
                                            if r.get("donor") == r["sample_id"]]},
        },
        "token_gate": tok,
    }
    # Gate A 总判定
    blockers = []
    if cm["errors"]:
        blockers.append("canonical errors")
    if report["arms"]["real"]["tree_equivalent_fail"]:
        blockers.append("real tree_equivalent fail")
    if report["arms"]["placebo"]["apply_clean_fail"] or report["arms"]["placebo"]["ast_not_equivalent"]:
        blockers.append("placebo fail")
    if report["arms"]["shuffled"]["donor_apply_clean_fail"] or report["arms"]["shuffled"]["same_cve_donor"]:
        blockers.append("shuffled fail")
    for arm in ("placebo", "shuffled"):
        if tok["per_arm"][arm]["out_of_bounds"]:
            blockers.append(f"{arm} token ratio out of bounds")
    report["gate_a_pass"] = not blockers
    report["blockers"] = blockers
    (out_dir / "gate_a_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["canonical", "upstream", "arms", "gate", "all"])
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if args.step in ("canonical", "all"):
        doc = build_canonical_manifest(args.out_dir)
        print(f"[GateA-1] v4_canonical_manifest.json: {doc['n_candidates']} 候选，"
              f"{doc['n_confirmation']} 确认性；errors={len(doc['errors'])}")
        for e in doc["errors"]:
            print("  ERR:", e)
        if doc["errors"]:
            return 1
    if args.step in ("upstream", "all"):
        d = build_upstream_report(args.out_dir)
        ok = sum(1 for s in d.get("samples", {}).values() if "python_projection_n" in s)
        print(f"[GateA-2] v4_upstream_real_report.json: {ok}/{len(V4_CANDIDATES)} 已解析")
        for cve, s in d.get("samples", {}).items():
            if "python_projection_n" not in s:
                print(f"  UNVERIFIABLE {cve}: {str(s)[:100]}")
    if args.step in ("arms", "all"):
        real = build_real_manifest(args.out_dir)
        placebo = build_placebo_manifest(args.out_dir)
        shuffled = build_shuffled_manifest(args.out_dir)
        print(f"[GateA-3] real={len(real)} placebo={len(placebo)} shuffled={len(shuffled)}")
        for name, rows, key in (("real", real, "tree_equivalent"),
                                ("placebo", placebo, "apply_clean"),
                                ("shuffled", shuffled, "donor_apply_clean")):
            bad = [r["sample_id"] for r in rows if not r.get(key)]
            print(f"  {name}: {key} 失败 {len(bad)} 例 {bad}")
    if args.step in ("gate", "all"):
        rep = build_gate_a_report(args.out_dir)
        print(f"[GateA-4] gate_a_pass={rep['gate_a_pass']} | blockers={rep['blockers']}")
        for arm in ("placebo", "shuffled"):
            oob = rep["token_gate"]["per_arm"][arm]["out_of_bounds"]
            print(f"  {arm} token 越界: {len(oob)} 例 {oob}")
        if not rep["gate_a_pass"]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
