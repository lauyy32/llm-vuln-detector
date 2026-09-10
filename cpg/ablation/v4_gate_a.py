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
    """Gate A-1：15 例 V4 候选集（从 canonical manifest 提取，fail-closed）。

    P0-3 强化：重复 sample 检测、必填字段校验（repo/parent/fix/两侧 tree SHA/
    pair_manifest SHA）、**从磁盘重算两侧 tree SHA**、pair_manifest SHA 校验、
    source_path 位于唯一 corpus-v3 根、目录名 == sample_id。
    """
    from cpg.ablation.canonical_manifest import tree_sha_lf as _tree_sha_lf  # 权威实现
    raw = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
    samples = raw.get("samples", [])
    ids = [s.get("sample_id") for s in samples]
    dups = sorted({i for i in ids if ids.count(i) > 1})
    by_id = {}
    for s in samples:
        by_id.setdefault(s.get("sample_id"), s)
    v3_root = (ROOT / "cpg" / "corpus-v3").resolve()
    entries, errors = [], []
    pm_drift = []
    if dups:
        errors.append(f"canonical manifest 重复 sample: {dups}")
    for cve in V4_CANDIDATES:
        s = by_id.get(cve)
        if s is None:
            errors.append(f"{cve} 不在 canonical manifest")
            continue
        if not s.get("eligible"):
            errors.append(f"{cve} 非 eligible（{s.get('exclusion_reason')}）")
            continue
        missing = [k for k in ("repo_slug", "parent_commit", "fix_commit", "source_path",
                               "vuln_tree_sha256_lf", "fixed_tree_sha256_lf",
                               "pair_manifest_sha256") if not s.get(k)]
        if missing:
            errors.append(f"{cve} 缺必填字段: {missing}")
            continue
        src_dir = (ROOT / s["source_path"]).resolve()
        if src_dir.parent != v3_root:
            errors.append(f"{cve} source_path 父目录非唯一 corpus-v3 根: {src_dir.parent}")
            continue
        if src_dir.name != cve:
            errors.append(f"{cve} 目录名 != sample_id: {src_dir.name}")
            continue
        drift = []
        for side, key in (("vuln", "vuln_tree_sha256_lf"), ("fixed", "fixed_tree_sha256_lf")):
            disk = _tree_sha_lf(src_dir / side)
            if disk != s[key]:
                drift.append(f"{side}: 磁盘 {disk[:12]} != manifest {s[key][:12]}")
        if drift:
            errors.append(f"{cve} tree SHA 漂移 {'; '.join(drift)}")
            continue
        pm = src_dir / "pair_manifest.json"
        if not pm.exists():
            errors.append(f"{cve} 缺 pair_manifest.json")
            continue
        pm_sha = _sha256_bytes(pm.read_bytes())
        if pm_sha != s["pair_manifest_sha256"]:
            # 经查证：canonical manifest 的 pair_manifest_sha256 为陈旧字段
            # （f20e516 于 2026-09-09 17:29 重建 pair_manifest 后未同步 manifest；
            #  该值与磁盘 raw、LF 归一、以及任何 git 历史版本均不符）。
            # 语料权威锚定是 tree_sha256_lf（上面已独立重算并通过），故此处
            # **记录为 drift（非阻断）**，并在 gate 报告中显式列出，待 reviewer 决定
            # 是否回填 manifest。不擅自修改权威工件。
            pm_drift.append({"sample_id": cve,
                             "manifest": s["pair_manifest_sha256"],
                             "disk_raw": pm_sha})
        entries.append({
            "sample_id": cve,
            "repo_slug": s.get("repo_slug"),
            "parent_commit": s.get("parent_commit"),
            "fix_commit": s.get("fix_commit"),
            "source_path": s.get("source_path"),
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
        "pair_manifest_drift": pm_drift,
        "candidates": entries,
        "errors": errors,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "v4_canonical_manifest.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def build_upstream_report(out_dir: Path) -> dict:
    """Gate A-2：对 15 例跑上游投影（复用 upstream_manifest），补 composite/cross-language 判定。

    P0-2 fail-closed：输出到唯一临时文件；校验子进程 returncode、15 例**精确键集**、
    每例证据（单 parent、路径级等价、内容级等价、无 fetch_error），任一不满足即抛异常；
    通过后原子提升到最终路径。**绝不读取陈旧输出。**
    """
    final = out_dir / "v4_upstream_real_report.json"
    tmp = out_dir / "v4_upstream_real_report.tmp.json"
    out_dir.mkdir(parents=True, exist_ok=True)
    if tmp.exists():
        tmp.unlink()
    cmd = [sys.executable, str(ROOT / "cpg/ablation/upstream_manifest.py"),
           "--cves", *V4_CANDIDATES, "--out", str(tmp)]
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       cwd=str(ROOT), timeout=3600)
    if r.returncode != 0:
        raise RuntimeError(f"upstream_manifest rc={r.returncode}: "
                           f"{(r.stderr or r.stdout)[-500:]}")
    if not tmp.exists():
        raise RuntimeError("upstream_manifest 未产出输出文件（rc=0 但无输出）")
    d = json.loads(tmp.read_text(encoding="utf-8"))
    sm = d.get("samples", {})
    if set(sm) != set(V4_CANDIDATES):
        raise RuntimeError(f"upstream 样本键不匹配: 缺={sorted(set(V4_CANDIDATES) - set(sm))} "
                           f"多={sorted(set(sm) - set(V4_CANDIDATES))}")
    for cve in V4_CANDIDATES:
        s = sm[cve]
        if "python_projection_n" not in s:
            raise RuntimeError(f"{cve} upstream 未解析: {str(s)[:120]}")
        if s.get("parents_count") != 1:
            raise RuntimeError(f"{cve} parents_count={s.get('parents_count')}（V4 要求单 parent）")
        dp = s.get("delta_paths") or {}
        if dp.get("path_set_equivalent") is not True:
            raise RuntimeError(f"{cve} 路径级不等价: {dp}")
        cc = s.get("content")
        if not isinstance(cc, dict):
            raise RuntimeError(f"{cve} 缺内容级证据")
        if cc.get("fetch_error"):
            raise RuntimeError(f"{cve} fetch_error: {cc['fetch_error']}")
        if cc.get("content_equivalent") is not True:
            raise RuntimeError(f"{cve} 内容级不等价: {cc}")
        msg = (s.get("commit_message_head") or "").lower()
        # ⚠️ "Merge commit from fork" 是 GitHub 从 fork 合并 PR 的**固定消息**，
        # parents_count 仍为 1（非真 merge）——**不能**据此判复合提交（假阳性）。
        # 仅记录为 exact 名称的弱信号，供人工裁决，不作门禁判据。
        s["fork_merge_message"] = ("merge commit from fork" in msg)
        s["composite_signal"] = None  # 复合性须人工裁决（见 partial_arm_construction.md）
        s["cross_language_signal"] = (s.get("python_projection_n", 0) == 0
                                      and s.get("non_python_excluded_n", 0) > 0)
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    tmp.replace(final)  # 原子提升
    return d


def _diff_sha(diff_text: str) -> str:
    return hashlib.sha256(diff_text.encode("utf-8")).hexdigest()


PATCHES_REL = "patches"


def persist_patch(out_dir: Path, arm: str, cve: str, diff_text: str) -> dict:
    """P0-1：把 exact diff 落盘为 patches/{arm}/{cve}.diff（字节写入，保 LF/CRLF）。

    返回绑定信息（相对路径 + 原始字节 SHA-256 + 字节数）。后续所有阶段（token 计数、
    prompt 组装、审计）**只能读取该文件**，禁止重新生成 diff——保证
    "apply-clean 验证的 diff == 计 token 的 diff == 进入 prompt 的 diff"。
    """
    rel = f"{PATCHES_REL}/{arm}/{cve}.diff"
    p = out_dir / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(diff_text.encode("utf-8"))
    b = p.read_bytes()
    return {"patch_path": rel, "patch_sha256": _sha256_bytes(b), "patch_bytes": len(b)}


def read_patch(out_dir: Path, rel: str) -> str:
    """P0-1：按冻结相对路径读取 exact diff（校验存在）。"""
    p = out_dir / rel
    if not p.exists():
        raise FileNotFoundError(f"冻结 patch 缺失: {rel}（禁止重生成，须先跑 arms）")
    return p.read_bytes().decode("utf-8")


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
        extra = persist_patch(out_dir, "real", cve, diff)
        extra.update({"apply_clean": ok, "tree_equivalent": ok,
                      "apply_message": msg[:200]})
        rows.append(_arm_row(cve, "real", diff, rep, "benign", extra))
    _write_jsonl(out_dir / "real_manifest.jsonl", rows)
    return rows


def build_placebo_manifest(out_dir: Path) -> list:
    """Gate A-3：placebo 臂（同文件、AST/行为中性的装饰性改动）。"""
    rows = []
    for cve in V4_CANDIDATES:
        diff, rep = v4g.gen_placebo_diff(cve)
        extra = persist_patch(out_dir, "placebo", cve, diff)
        extra.update({"ast_equivalent": rep.get("ast_equivalent"),
                      "apply_clean": rep.get("apply_clean"),
                      "edits": rep.get("edits", [])})
        rows.append(_arm_row(cve, "placebo", diff, rep, "vulnerable", extra))
    _write_jsonl(out_dir / "placebo_manifest.jsonl", rows)
    return rows


def build_shuffled_manifest(out_dir: Path, donors: dict | None = None) -> list:
    """Gate A-3：shuffled 臂 = 循环配对的下一个 CVE 的真实 diff（结构像补丁但无关）。

    语义沿用 B4（既有三臂主实验）：donor ≠ 目标；donor diff 本身是完整且在其自身
    vuln 树上 apply-clean 的（real 臂同源构造）。残余漏洞 oracle：donor 补丁不触及
    目标树 → 目标漏洞原样存在。

    注：token matching donor 属 P0-5 有效性升级项，本函数当前仅实现 B4 语义（机械工件）。
    """
    if donors is None:
        donors = {cve: v4g.gen_complete_real_diff(cve)[0] for cve in V4_CANDIDATES}
    rows = []
    for i, cve in enumerate(V4_CANDIDATES):
        donor = V4_CANDIDATES[(i + 1) % len(V4_CANDIDATES)]
        diff = donors[donor]
        donor_ok, donor_msg = v4g.apply_and_verify(donor, diff)
        _, rep = v4g.gen_complete_real_diff(donor)
        assert donor != cve, f"shuffled donor 不得来自同一 CVE: {cve}"
        extra = persist_patch(out_dir, "shuffled", cve, diff)
        extra.update({"donor": donor, "donor_apply_clean": donor_ok,
                      "donor_tree_equivalent": donor_ok,
                      "donor_message": donor_msg[:200]})
        rows.append(_arm_row(cve, "shuffled", diff, rep, "vulnerable", extra))
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
    """Gate A-4：四臂 token 计量 + token 比门禁 [0.8, 1.25]（以 real 为基准）。

    P0-1/P0-4 修正：
    - token 一律从**冻结的 patches/{arm}/{cve}.diff 文件**读取计算，禁止重生成
      （保证与 apply-clean 验证、将来 prompt 使用的 diff 是同一份字节）。
    - 界内判定用**未舍入原始比值**（舍入后的值仅作展示）。

    口径警示（P0-4）：本函数计量的是 **patch（候选补丁）token**，不是冻结协议 A4b
    要求的**最终 prompt token**。最终 prompt 比值与 context-fit 须由 G0 prompt 草案
    另行计量（见 build_prompt_draft / feasibility 表），二者不可互相替代。
    """
    manifests = {"real": _read_jsonl(out_dir / "real_manifest.jsonl"),
                 "placebo": _read_jsonl(out_dir / "placebo_manifest.jsonl"),
                 "shuffled": _read_jsonl(out_dir / "shuffled_manifest.jsonl")}
    report = {"tokenizer": str(TOKENIZER_PATH.relative_to(ROOT).as_posix()),
              "vocab_size": _tokenizer().get_vocab_size(),
              "metric": "patch_token（非 final_prompt_token，见 P0-4 警示）",
              "ratio_bounds": [TOKEN_RATIO_LO, TOKEN_RATIO_HI],
              "per_arm": {}}
    patch_tok = {}
    for arm, rows in manifests.items():
        patch_tok[arm] = {}
        for r in rows:
            diff = read_patch(out_dir, r["patch_path"])
            # 校验冻结文件未被篡改（与 manifest 绑定 SHA 一致）
            if _sha256_bytes(diff.encode("utf-8")) != r["patch_sha256"]:
                raise RuntimeError(f"{arm}/{r['sample_id']} 冻结 patch SHA 漂移")
            patch_tok[arm][r["sample_id"]] = count_tokens(diff)
        report["per_arm"][arm] = {"tokens": patch_tok[arm]}
    real_tok = patch_tok["real"]
    for arm in ("placebo", "shuffled"):
        ratios_raw = {}
        ratios_shown = {}
        for c in V4_CANDIDATES:
            if real_tok.get(c):
                rr = patch_tok[arm][c] / real_tok[c]
                ratios_raw[c] = rr
                ratios_shown[c] = round(rr, 4)
            else:
                ratios_raw[c] = None
                ratios_shown[c] = None
        oob = [c for c, r in ratios_raw.items()
               if r is None or not (TOKEN_RATIO_LO <= r <= TOKEN_RATIO_HI)]
        report["per_arm"][arm]["ratio_vs_real"] = ratios_shown
        report["per_arm"][arm]["out_of_bounds"] = oob
    report["real_token_summary"] = {
        "min": min(real_tok.values()), "max": max(real_tok.values()),
        "median": sorted(real_tok.values())[len(real_tok) // 2]}
    # P0-4：patch 级 context-fit（不含源码/CPG/system/输出；仅下界预警）
    report["patch_context_fit"] = {
        "num_ctx": _num_ctx(),
        "over_num_ctx": sorted([c for c, t in real_tok.items() if t > _num_ctx()]),
        "note": "仅 patch token；最终 prompt 还须加源码/CPG/system/num_predict",
    }
    return report


def _num_ctx() -> int:
    from cpg.ablation.model_client import NUM_CTX
    return NUM_CTX


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
                                       and s["content"].get("content_equivalent") is not True],
            "fetch_error": sorted({f for s in up_samples.values()
                                   if isinstance(s.get("content"), dict)
                                   for f in (s["content"].get("fetch_error") or [])}),
            "path_not_equivalent": [c for c, s in up_samples.items()
                                    if (s.get("delta_paths") or {}).get("path_set_equivalent") is not True],
            "parents_abnormal": [c for c, s in up_samples.items()
                                 if s.get("parents_count") != 1],
            "composite_signal": [c for c, s in up_samples.items() if s.get("composite_signal")],
            "fork_merge_message": [c for c, s in up_samples.items() if s.get("fork_merge_message")],
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
    up = report["upstream"]
    if up["resolved"] != len(V4_CANDIDATES):
        blockers.append(f"upstream resolved {up['resolved']}/{len(V4_CANDIDATES)}")
    if up["content_not_equivalent"]:
        blockers.append(f"upstream content_not_equivalent: {up['content_not_equivalent']}")
    if up["fetch_error"]:
        blockers.append(f"upstream fetch_error: {up['fetch_error']}")
    if up["path_not_equivalent"]:
        blockers.append(f"upstream path_not_equivalent: {up['path_not_equivalent']}")
    if up["parents_abnormal"]:
        blockers.append(f"upstream parents_abnormal: {up['parents_abnormal']}")
    if report["arms"]["real"]["tree_equivalent_fail"]:
        blockers.append("real tree_equivalent fail")
    if report["arms"]["placebo"]["apply_clean_fail"] or report["arms"]["placebo"]["ast_not_equivalent"]:
        blockers.append("placebo fail")
    if report["arms"]["shuffled"]["donor_apply_clean_fail"] or report["arms"]["shuffled"]["same_cve_donor"]:
        blockers.append("shuffled fail")
    for arm in ("placebo", "shuffled"):
        if tok["per_arm"][arm]["out_of_bounds"]:
            blockers.append(f"{arm} token ratio out of bounds")
    # P0-4：patch 级 context-fit 下界预警（最终 prompt 还须加源码/CPG/system/输出）
    if tok["patch_context_fit"]["over_num_ctx"]:
        blockers.append(f"real patch 超 num_ctx: {tok['patch_context_fit']['over_num_ctx']}")
    report["gate_a_pass"] = not blockers
    report["blockers"] = blockers
    (out_dir / "gate_a_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


def build_feasibility_table(out_dir: Path) -> dict:
    """P0-4：V4 可行性表（真实 tokenizer）。

    ⚠️ 口径修正（codex P0）：本表是把 real diff 涉及文件的**完整源码**计入的
    **full-file estimate**，不是下界——正式 prompt 会用摘录/窗口表示，源码部分
    可能显著小于完整文件。因此**只有与摘录无关的情形才判"确定超限"**：

      patch_tokens + num_predict > num_ctx   → 确定超（不含任何源码/系统开销）

    其余样本一律标 `needs_renderer`：必须由真实 G0 renderer 渲染后精确计数再判。
    `prompt_overhead` 是人工常数下界，**不作为门禁**。
    """
    from cpg.ablation.model_client import NUM_CTX, NUM_PREDICT
    OVERHEAD = 600  # 人工常数下界（仅参考，非门禁）
    real_rows = {r["sample_id"]: r for r in _read_jsonl(out_dir / "real_manifest.jsonl")}
    rows = []
    for cve in V4_CANDIDATES:
        r = real_rows[cve]
        src = sample_dir_path(cve) / "vuln"
        src_tok = 0
        for rel in sorted(set(r.get("modified", [])) | set(r.get("added", []))):
            p = src / rel
            if p.exists():
                src_tok += count_tokens(p.read_bytes().decode("utf-8", errors="replace"))
        patch_tok = count_tokens(read_patch(out_dir, r["patch_path"]))
        # 确定超限：仅 patch + 输出预算（与摘录无关）
        firm_over = (patch_tok + NUM_PREDICT) > NUM_CTX
        rows.append({"sample_id": cve,
                     "patch_tokens": patch_tok,
                     "full_file_src_tokens": src_tok,       # 仅参考，非下界
                     "num_predict": NUM_PREDICT,
                     "patch_plus_output": patch_tok + NUM_PREDICT,
                     "num_ctx": NUM_CTX,
                     "firm_over_num_ctx": firm_over,
                     "verdict": ("FIRM_OVER" if firm_over else "needs_renderer"),
                     "confirmation_eligible": cve not in CONFIRMATORY_EXCLUDED})
    doc = {"metric": "firm_over = patch_tokens + num_predict > num_ctx（与摘录无关）",
           "full_file_estimate_note": "full_file_src_tokens 为完整文件估算，非下界、非门禁",
           "prompt_overhead_constant": OVERHEAD,
           "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
           "n_firm_over": sum(1 for x in rows if x["firm_over_num_ctx"]),
           "firm_over": [x["sample_id"] for x in rows if x["firm_over_num_ctx"]],
           "rows": rows}
    (out_dir / "v4_feasibility_table.json").write_text(
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return doc


def sample_dir_path(cve: str):
    """候选样本的 corpus-v3 目录（复用 v4_patch_gen.sample_dir 的 fail-closed 校验）。"""
    return v4g.sample_dir(cve)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["canonical", "upstream", "arms", "gate", "feasibility", "all"])
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
    if args.step in ("feasibility", "all"):
        f = build_feasibility_table(args.out_dir)
        print(f"[Feasibility] 确定超 num_ctx（patch+输出）: {f['n_firm_over']}/"
              f"{len(f['rows'])} {f['firm_over']}；其余 needs_renderer")
    return 0


if __name__ == "__main__":
    sys.exit(main())
