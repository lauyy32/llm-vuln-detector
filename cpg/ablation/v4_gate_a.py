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

# V4 只消费**版本化 v2** manifest（旧 manifest 的 pair_manifest_sha256 整体陈旧，
# 且被 RQ1-R lock 逐字节绑定、不得修改）。见 canonical_manifest_v2.py 的谱系说明。
# P0-2：路径从单一来源 v4_manifest 取；CLI 强制显式传入并校验一致。
from cpg.ablation import v4_manifest  # noqa: E402
CANONICAL_MANIFEST = v4_manifest.V4_CANONICAL_MANIFEST
OLD_CANONICAL_MANIFEST = v4_manifest.LEGACY_CANONICAL_MANIFEST
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


def _lf_sha(b: bytes) -> str:
    """LF 归一化后的 SHA-256（hunk 身份锚点用，跨平台稳定）。"""
    return hashlib.sha256(b.replace(b"\r\n", b"\n")).hexdigest()


def write_text_lf(path: Path, text: str) -> None:
    """写文本用 LF（.gitattributes 规定 *.json/*.jsonl 为 eol=lf）。

    若用 Path.write_text 默认（Windows 下 os.linesep=CRLF），磁盘字节与 Git blob 会
    不一致，干净克隆后 SHA 漂移——与 patch 的 -text 问题同源。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))


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
        # V4 用 v2 的**正式**字段（无 v2_* fallback，避免重新引入字段歧义）
        if "pair_manifest_sha256" not in s:
            errors.append(f"{cve} v2 缺 pair_manifest_sha256 字段")
            continue
        expect_pm = s["pair_manifest_sha256"]
        if pm_sha != expect_pm:
            errors.append(f"{cve} pair_manifest SHA 与 v2 不符（阻断）")
            continue
        # 双重校验：v2 重算的 tree SHA 也必须与磁盘一致
        for side, key in (("vuln", "vuln_tree_sha256_lf"), ("fixed", "fixed_tree_sha256_lf")):
            if s.get(key) and _tree_sha_lf(src_dir / side) != s[key]:
                errors.append(f"{cve} {side} 树 SHA 与 v2 不符（阻断）")
                break
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
            "supersedes": str(OLD_CANONICAL_MANIFEST.relative_to(ROOT).as_posix()),
            "supersedes_sha256": (_sha256_bytes(OLD_CANONICAL_MANIFEST.read_bytes())
                                  if OLD_CANONICAL_MANIFEST.exists() else None),
            "revision_reason": "PAIR_MANIFEST_PROVENANCE_REFRESH",
            "git_commit": _git_commit(),
            "candidate_source": "cpg/ablation/partial_arm_construction.md",
        },
        "n_candidates": len(entries),
        "n_confirmation": sum(1 for e in entries if e["confirmation_eligible"]),
        "candidates": entries,
        "errors": errors,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_text_lf(out_dir / "v4_canonical_manifest.json", 
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
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
           "--cves", *V4_CANDIDATES, "--out", str(tmp),
           "--canonical-manifest", str(CANONICAL_MANIFEST),
           "--expected-manifest-sha256", v4_manifest.manifest_sha256()]
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
    write_text_lf(tmp, json.dumps(d, ensure_ascii=False, indent=1) + "\n")
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
    write_text_lf(path, "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n")


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
        "provenance": {
            "canonical_manifest": str(CANONICAL_MANIFEST.relative_to(ROOT).as_posix()),
            "canonical_manifest_sha256": _sha256_bytes(CANONICAL_MANIFEST.read_bytes()),
            "supersedes": str(OLD_CANONICAL_MANIFEST.relative_to(ROOT).as_posix()),
            "supersedes_sha256": (_sha256_bytes(OLD_CANONICAL_MANIFEST.read_bytes())
                                  if OLD_CANONICAL_MANIFEST.exists() else None),
            "revision_reason": "PAIR_MANIFEST_PROVENANCE_REFRESH",
        },
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
    # P1 闭环：Gate 消费 registry——V4 ACTIVE 项的 path/SHA 必须与磁盘一致
    registry_errs = []
    reg_path = out_dir / "manifest_registry.json"
    if not reg_path.exists():
        registry_errs.append("缺 manifest_registry.json")
    else:
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
        act = [e for e in reg.get("entries", []) if e.get("status") == "ACTIVE"
               and e.get("consumer") == "V4"]
        if len(act) != 1:
            registry_errs.append(f"V4 ACTIVE 项数 != 1（{len(act)}）")
        else:
            p = ROOT / act[0]["manifest"]
            if not p.exists() or _sha256_bytes(p.read_bytes()) != act[0]["sha256"]:
                registry_errs.append("registry V4 manifest SHA 漂移")
    report["registry_check"] = {"errors": registry_errs}
    # P0-1/P0-2：coverage 门禁 = 生产纯函数 evaluate_coverage_gate（frozen labels × 当前 coverage）
    coverage_errs = []
    cov_path = out_dir / "v4_hunk_coverage.json"
    reg_path = out_dir / "critical_hunks.frozen.json"
    cov = None
    if not cov_path.exists():
        coverage_errs.append("缺 v4_hunk_coverage.json（coverage 门禁不可跳过）")
    else:
        cov = json.loads(cov_path.read_text(encoding="utf-8"))
    frozen = None
    if reg_path.exists():
        frozen = json.loads(reg_path.read_text(encoding="utf-8"))
    coverage_errs.extend(evaluate_coverage_gate(cov, frozen))
    report["coverage_check"] = {"errors": coverage_errs, "detector_is_gate": True,
                                "join": "frozen criticality × current coverage（按 hunk identity）"}
    # Gate A 总判定
    blockers = []
    if cm["errors"]:
        blockers.append("canonical errors")
    if coverage_errs:
        blockers.append(f"coverage: {coverage_errs[:2]}")
    if registry_errs:
        blockers.append(f"registry: {registry_errs}")
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
    write_text_lf(out_dir / "gate_a_report.json", 
        json.dumps(report, ensure_ascii=False, indent=2) + "\n")
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
    write_text_lf(out_dir / "v4_feasibility_table.json", 
        json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    return doc


def sample_dir_path(cve: str):
    """候选样本的 corpus-v3 目录（复用 v4_patch_gen.sample_dir 的 fail-closed 校验）。"""
    return v4g.sample_dir(cve)


def build_manifest_registry(out_dir: Path) -> dict:
    """manifest registry：分别登记 RQ1-R（旧，冻结）与 V4（v2，活动）的权威锚点。"""
    def _ent(path: Path, consumer: str, status: str, note: str) -> dict:
        return {"consumer": consumer,
                "manifest": path.relative_to(ROOT).as_posix(),
                "sha256": _sha256_bytes(path.read_bytes()) if path.exists() else None,
                "status": status, "note": note}
    reg = {
        "schema": "manifest-registry/1",
        "generated_git_commit": _git_commit(),
        "entries": [
            _ent(OLD_CANONICAL_MANIFEST, "RQ1-R", "FROZEN_LEGACY_INPUT",
                 "被 cpg/ablation/.work/rq1-r-canonical-v4/lock_request.json 逐字节绑定；"
                 "pair_manifest_sha256 字段整体陈旧但不得就地修改"),
            _ent(CANONICAL_MANIFEST, "V4", "ACTIVE",
                 "由 canonical_manifest_v2.py 从 corpus-v3 机械重算；"
                 "revision_reason=PAIR_MANIFEST_PROVENANCE_REFRESH"),
        ],
    }
    write_text_lf(out_dir / "manifest_registry.json", 
        json.dumps(reg, ensure_ascii=False, indent=2) + "\n")
    return reg


# 旧 V4 派生工件（基于陈旧 manifest 生成）最后所在的 commit；之后全部从 v2 重生成。
SUPERSEDED_AT_COMMIT = "9f29b8b"
V4_ARTIFACTS = [
    "v4_canonical_manifest.json", "v4_upstream_real_report.json",
    "real_manifest.jsonl", "placebo_manifest.jsonl", "shuffled_manifest.jsonl",
    "gate_a_report.json", "v4_feasibility_table.json", "manifest_registry.json",
]


def build_stale_artifacts(out_dir: Path) -> dict:
    """P1 闭环：旧工件（git 历史 SHA）→ 新工件的**机器可审计**状态映射。

    分类（codex 要求，替代笼统的"完全替换"）：
      REGENERATED_CHANGED   已重生成且字节改变
      REGENERATED_IDENTICAL 已重生成但字节相同（内容本就不含漂移字段）
      MISSING               历史无此文件
      UNVERIFIED            当前缺失，无法核对
    并对 patches/** 生成逐文件清单 + 确定性 tree SHA。
    """
    def _status(rel: str, cur: Path) -> tuple:
        """P1-2：区分 NOT_PRESENT_AT_BASE / GIT_SHOW_ERROR / CURRENT_MISSING /
        REGENERATED_IDENTICAL / REGENERATED_CHANGED / NEW_ARTIFACT。"""
        gitrel = f"cpg/ablation/artifacts/v4/{rel}"
        r = subprocess.run(["git", "show", f"{SUPERSEDED_AT_COMMIT}:{gitrel}"],
                           cwd=str(ROOT), capture_output=True)
        cur_sha = _sha256_bytes(cur.read_bytes()) if cur.exists() else None
        if r.returncode != 0:
            # 旧 commit 无此文件：当前存在 → NEW_ARTIFACT；当前也缺 → NOT_PRESENT_AT_BASE
            if cur_sha is not None:
                return "NEW_ARTIFACT", cur_sha, None
            return "NOT_PRESENT_AT_BASE", None, None
        old_sha = _sha256_bytes(r.stdout)
        if cur_sha is None:
            return "CURRENT_MISSING", None, old_sha
        if old_sha == cur_sha:
            return "REGENERATED_IDENTICAL", cur_sha, old_sha
        return "REGENERATED_CHANGED", cur_sha, old_sha

    entries = []
    for rel in V4_ARTIFACTS:
        status, cur_sha, old_sha = _status(rel, out_dir / rel)
        entries.append({
            "artifact": f"cpg/ablation/artifacts/v4/{rel}",
            "superseded_sha256": old_sha,
            "current_sha256": cur_sha,
            "compared_at_commit": SUPERSEDED_AT_COMMIT,
            "status": status,
        })
    patch_files, parts = [], []
    pdir = out_dir / PATCHES_REL
    if pdir.is_dir():
        for p in sorted(pdir.rglob("*.diff")):
            b = p.read_bytes()
            rel = p.relative_to(out_dir).as_posix()
            patch_files.append({"path": rel, "sha256": _sha256_bytes(b), "bytes": len(b)})
            parts.append(f"{rel}:{_sha256_bytes(b)}")
    counts = {}
    for e in entries:
        counts[e["status"]] = counts.get(e["status"], 0) + 1
    doc = {"schema": "stale-artifacts/2",
           "compared_at_commit": SUPERSEDED_AT_COMMIT,
           "revision_reason": "PAIR_MANIFEST_PROVENANCE_REFRESH",
           "note": ("逐项给出旧/新 SHA 与**机器判定的状态**（不再笼统声明'完全替换'）；"
                    "patches/** 另附逐文件清单与确定性 tree SHA"),
           "status_counts": counts,
           "entries": entries,
           "patches": {"n_files": len(patch_files),
                       "tree_sha256": _sha256_bytes("\n".join(parts).encode("utf-8")),
                       "files": patch_files}}
    write_text_lf(out_dir / "stale_artifacts.json",
                  json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    return doc


_HUNK_RE = None


def excerpt_vuln_for_patch(sample_dir: Path, patch_text: str, window: int = 20,
                           max_chars: int = 24000) -> str:
    """按 candidate patch 的 hunk 行号，从 vuln 树做窗口摘录（±window 行）。

    这是 V4 的**表示策略草案**（正式冻结前须由 reviewer 确认）：只给补丁触及位置
    附近的代码，而非整文件。为满足预算，按 hunk 出现顺序累积，超 max_chars 即停
    （并标注被裁剪的文件数），避免 RENDER_FAILURE。
    """
    import re
    hunks: dict[str, list] = {}
    cur = None
    for ln in patch_text.split("\n"):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            hunks.setdefault(cur, [])
        elif ln.startswith("@@ ") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", ln)
            if m:
                hunks[cur].append((int(m.group(1)), int(m.group(2) or 1)))
    chunks, total, dropped = [], 0, 0
    for rel in sorted(hunks):
        p = sample_dir / "vuln" / rel
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        keep: set = set()
        for start, count in hunks[rel]:
            lo = max(0, start - 1 - window)
            hi = min(len(lines), start - 1 + count + window)
            keep.update(range(lo, hi))
        if not keep:
            continue
        body = "\n".join(lines[i] for i in sorted(keep))
        chunk = f"// ---- {rel} ----\n{body}"
        if total + len(chunk) > max_chars:
            dropped += 1
            continue
        chunks.append(chunk)
        total += len(chunk)
    out = "\n\n".join(chunks)
    if dropped:
        out += f"\n\n// [excerpt note] 另有 {dropped} 个触及文件因预算未纳入本摘录"
    return out


def build_g0_prompts(out_dir: Path) -> dict:
    """P0-1/P0-3 返工：每 CVE 只生成**一次**与 arm 无关的 code_text，四臂复用同一字节串；
    分类只由真实 tokenizer 对完整 prompt 计数决定（无字符阈值），并做硬断言。

    - code_text 选择基于**冻结的 real patch** 的 hunk 位置（预注册规则），
      shuffled 的 donor 路径**不参与**目标源码选择。
    - 硬断言：同 CVE 四臂 code_text_sha256 必须唯一；任一臂 code_text 为空 → 该组失败。
    """
    from cpg.ablation.model_client import NUM_CTX, NUM_PREDICT
    from cpg.ablation import prompt_renderer as pr
    cm = json.loads(CANONICAL_MANIFEST.read_text(encoding="utf-8"))
    cwe_by = {s["sample_id"]: (s.get("cwes") or [None])[0] for s in cm["samples"]}
    rows, group_errors = [], []
    prompt_dir = out_dir / "g0_prompts"
    for cve in V4_CANDIDATES:
        sd = sample_dir_path(cve)
        # —— 单次、与 arm 无关的源码上下文（基于 real patch 的 hunk 位置）——
        real_patch = read_patch(out_dir, f"{PATCHES_REL}/real/{cve}.diff")
        code = excerpt_vuln_for_patch(sd, real_patch)
        code_sha = _sha256_bytes(code.encode("utf-8"))
        if not code.strip():
            group_errors.append(f"{cve}: code_text 为空（预注册选择未命中任何文件）")
        for arm in ("real", "placebo", "shuffled"):
            rel = f"{PATCHES_REL}/{arm}/{cve}.diff"
            try:
                patch = read_patch(out_dir, rel)
            except FileNotFoundError as e:
                rows.append({"sample_id": cve, "arm": arm, "patch_path": rel,
                             "code_text_sha256": code_sha,
                             "verdict": "RENDER_FAILURE", "error": str(e)[:200]})
                continue
            rec = {"sample_id": cve, "arm": arm, "patch_path": rel,
                   "code_text_sha256": code_sha}
            prompt = pr.render_v4_prompt(cve=cve, cwe=cwe_by.get(cve),
                                         code_text=code, candidate_patch=patch)
            tok = count_tokens(prompt)
            rec.update({"prompt_tokens": tok,
                        "code_tokens": count_tokens(code),
                        "patch_tokens": count_tokens(patch),
                        "num_predict": NUM_PREDICT, "num_ctx": NUM_CTX,
                        "margin": NUM_CTX - (tok + NUM_PREDICT),
                        "verdict": "FIT" if tok + NUM_PREDICT <= NUM_CTX else "OVER_BUDGET",
                        "prompt_sha256": _sha256_bytes(prompt.encode("utf-8")),
                        "patch_sha256": _sha256_bytes(patch.encode("utf-8"))})
            pp = prompt_dir / arm / f"{cve}.txt"
            write_text_lf(pp, prompt)
            rec["prompt_path"] = pp.relative_to(out_dir).as_posix()
            rows.append(rec)
    # —— 硬断言 ——
    by_cve = {}
    for r in rows:
        by_cve.setdefault(r["sample_id"], []).append(r)
    for cve, rs in by_cve.items():
        shas = {r["code_text_sha256"] for r in rs}
        if len(shas) != 1:
            group_errors.append(f"{cve}: 四臂 code_text_sha256 不唯一（{len(shas)} 个）")
    doc = {"schema": "v4-g0-prompts/2",
           "status": "DRAFT_TRIPLE_ARM（partial/minimal-real 第四臂未构造，分母须分开）",
           "renderer": "cpg/ablation/prompt_renderer.py::render_v4_prompt",
           "arms": ["real", "placebo", "shuffled"],
           "n_arms": 3,
           "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
           "n_fit": sum(1 for r in rows if r["verdict"] == "FIT"),
           "n_over": sum(1 for r in rows if r["verdict"] == "OVER_BUDGET"),
           "n_render_failure": sum(1 for r in rows if r["verdict"] == "RENDER_FAILURE"),
           "code_text_unique_per_cve": all(
               len({r["code_text_sha256"] for r in rs}) == 1 for rs in by_cve.values()),
           "empty_code_groups": [c for c, rs in by_cve.items()
                                 if not rs or rs[0].get("code_tokens") == 0],
           "group_errors": group_errors,
           "provenance": {
               "generator_git_commit": _git_commit(),
               "renderer_impl_sha256": _sha256_bytes(
                   (ROOT / "cpg/ablation/prompt_renderer.py").read_bytes()),
               "tokenizer_sha256": _sha256_bytes(TOKENIZER_PATH.read_bytes()),
               "canonical_manifest": str(CANONICAL_MANIFEST.relative_to(ROOT).as_posix()),
               "canonical_manifest_sha256": _sha256_bytes(CANONICAL_MANIFEST.read_bytes()),
               "arm_registry": ["real", "placebo", "shuffled"],
               "system_message": "prompt_renderer.SYSTEM_V4",
               "user_message_boundary": "# 审计任务",
           },
           "rows": rows}
    write_text_lf(out_dir / "v4_g0_prompt_report.json",
                  json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    if group_errors:
        raise RuntimeError("G0 硬断言失败: " + "; ".join(group_errors[:5]))
    return doc


def _parse_patch_hunks(patch_text: str) -> dict:
    """解析 patch → {file: [{old_start, old_count, new_start, new_count, header, ctx_sha}]}。

    带上下文 SHA（hunk 头 + 其后 3 行），使 hunk 身份不依赖易漂移的纯行号。
    malformed hunk header → 抛 ValueError（fail-closed）。
    """
    import re
    out: dict = {}
    cur = None
    buf = patch_text.split("\n")
    starts = []
    for i, ln in enumerate(buf):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            out.setdefault(cur, [])
        elif ln.startswith("@@ ") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", ln)
            if not m:
                raise ValueError(f"malformed hunk header: {ln[:80]}")
            out[cur].append({
                "old_start": int(m.group(1)), "old_count": int(m.group(2) or 1),
                "new_start": int(m.group(3)), "new_count": int(m.group(4) or 1),
                "header": ln, "_start_idx": i,
                "patch_context_sha256": _sha256_bytes(
                    "\n".join(buf[i:i + 4]).encode("utf-8")),
            })
    # 补完整 hunk body（P1-2：身份锚点用完整 body 的 LF-normalized SHA）
    for rel, hs in out.items():
        for j, h in enumerate(hs):
            end = hs[j + 1]["_start_idx"] if j + 1 < len(hs) else len(buf)
            body = "\n".join(buf[h["_start_idx"] + 1:end])
            h["_body"] = body
    return out


def excerpt_vuln_for_patch(sample_dir: Path, patch_text: str, window: int = 20,
                           max_chars: int = 24000) -> tuple:
    """按 candidate patch 的 hunk 行号，从 vuln 树做窗口摘录（±window 行）。

    P1-1 修复：返回 **(code_text, selection_manifest)**——manifest 记录每个文件
    实际纳入的原始行号集合，供 coverage 计算真实的 FULL/PARTIAL/ABSENT
    （不再用"文件块保留/丢弃"这种近似，使 PARTIAL 成为可达状态）。
    """
    import re
    hunks: dict[str, list] = {}
    cur = None
    for ln in patch_text.split("\n"):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            hunks.setdefault(cur, [])
        elif ln.startswith("@@ ") and cur is not None:
            m = re.match(r"@@ -(\d+)(?:,(\d+))?", ln)
            if m:
                hunks[cur].append((int(m.group(1)), int(m.group(2) or 1)))
    chunks, selection, total, dropped = [], {}, 0, 0
    for rel in sorted(hunks):
        p = sample_dir / "vuln" / rel
        if not p.exists():
            continue
        lines = p.read_text(encoding="utf-8", errors="replace").split("\n")
        keep: set = set()
        for start, count in hunks[rel]:
            lo = max(0, start - 1 - window)
            hi = min(len(lines), start - 1 + count + window)
            keep.update(range(lo, hi))
        if not keep:
            continue
        body = "\n".join(lines[i] for i in sorted(keep))
        chunk = f"// ---- {rel} ----\n{body}"
        if total + len(chunk) > max_chars:
            dropped += 1
            continue
        chunks.append(chunk)
        total += len(chunk)
        selection[rel] = sorted(keep)          # 1-based 行号
    out = "\n\n".join(chunks)
    if dropped:
        out += f"\n\n// [excerpt note] 另有 {dropped} 个触及文件因预算未纳入本摘录"
    manifest = {"files": selection, "dropped_file_count": dropped}
    return out, manifest


def _file_status(patch_text: str) -> dict:
    """P0-3：由**文件状态**判定 added（而非 old_count==0）。

    判定依据（任一即 added）：`new file mode` / `--- /dev/null`。
    已有文件中的纯插入（old_count==0 但非 added）**不得**判为 N/A。
    """
    status, cur = {}, None
    for ln in patch_text.split("\n"):
        if ln.startswith("diff --git ") and " b/" in ln:
            cur = ln.split(" b/", 1)[1].strip()
            status.setdefault(cur, "M")
        elif cur is not None:
            if ln.startswith("new file mode"):
                status[cur] = "A"
            elif ln.startswith("deleted file mode"):
                status[cur] = "D"
            elif ln.startswith("--- /dev/null"):
                status[cur] = "A"
    return status


def _hunk_identity(rel: str, file_status: str, h: dict, body_lf_sha: str) -> dict:
    """P1-2：完整 hunk 身份——路径 + 文件状态 + 双侧 count + **完整 body 的 LF SHA**。"""
    return {"file": rel, "file_status": file_status,
            "old_start": h["old_start"], "old_count": h["old_count"],
            "new_start": h["new_start"], "new_count": h["new_count"],
            "body_lf_sha256": body_lf_sha}


def build_hunk_coverage(out_dir: Path) -> dict:
    """机械覆盖审计（detector）：逐 hunk 报告表示覆盖。

    - identity 用完整 hunk body 的 LF-normalized SHA。
    - 覆盖按 renderer 的 **selection manifest** 计算（真实纳入了哪些行）→ PARTIAL 可达。
    - added 由**文件状态**判定（非 old_count==0）。
    """
    report = {"schema": "v4-hunk-coverage/3", "kind": "MECHANICAL_COVERAGE_AUDIT",
              "gate_consumer": "evaluate_coverage_gate",
              "note": ("detector；criticality 由 frozen registry 提供（与本文件分离）。"
                       "Gate 运行时按 hunk identity 严格 join 二者"),
              "samples": {}}
    for cve in V4_CANDIDATES:
        sd = sample_dir_path(cve)
        patch = read_patch(out_dir, f"{PATCHES_REL}/real/{cve}.diff")
        code, manifest = excerpt_vuln_for_patch(sd, patch)
        kept_lines = {k: set(v) for k, v in manifest["files"].items()}
        fstat = _file_status(patch)
        parsed = _parse_patch_hunks(patch)
        rows = []
        n = {"FULL": 0, "PARTIAL": 0, "ABSENT": 0, "NOT_APPLICABLE_ADDED": 0}
        for rel in sorted(parsed):
            p = sd / "vuln" / rel
            nlines = (len(p.read_text(encoding="utf-8", errors="replace").split("\n"))
                      if p.exists() else 0)
            for h in parsed[rel]:
                ident = _hunk_identity(rel, fstat.get(rel, "M"), h,
                                       _lf_sha(h["_body"].encode("utf-8")))
                if fstat.get(rel) == "A":
                    status = "NOT_APPLICABLE_ADDED"      # 真正的新增文件
                else:
                    # 覆盖按 selection manifest 的真实行集合计算 → PARTIAL 可达
                    if h["old_count"] == 0:
                        lo, hi = h["old_start"] - 1, h["old_start"]  # 插入边界
                    else:
                        lo, hi = h["old_start"] - 1, h["old_start"] - 1 + h["old_count"]
                    want = set(range(max(0, lo), min(nlines, hi)))
                    have = kept_lines.get(rel, set())
                    inter = len(want & have)
                    if not want:
                        status = "ABSENT"
                    elif inter == len(want):
                        status = "FULL"
                    elif inter > 0:
                        status = "PARTIAL"
                    else:
                        status = "ABSENT"
                n[status] += 1
                rows.append({"sample_id": cve, "hunk_identity": ident,
                             "coverage": status, "criticality": None})  # 由 frozen registry 提供
        report["samples"][cve] = {"n_hunks": len(rows), **n, "hunks": rows}
    report["totals"] = {k: sum(s[k] for s in report["samples"].values())
                        for k in ("FULL", "PARTIAL", "ABSENT", "NOT_APPLICABLE_ADDED")}
    report["mechanical_absent_samples"] = sorted(
        [c for c, s in report["samples"].items() if s["ABSENT"] > 0])
    report["confirmatory_blocking_samples"] = None
    write_text_lf(out_dir / "v4_hunk_coverage.json",
                  json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    return report


def build_critical_hunks_template(out_dir: Path) -> dict:
    """P0-1 拆分：**只含机械身份与待标注上下文**，不含任何人工标签、不含 coverage。

    产物：critical_hunks.template.json（供生成双盲标注包）。
    """
    cov = json.loads((out_dir / "v4_hunk_coverage.json").read_text(encoding="utf-8"))
    entries = []
    for cve, s in cov["samples"].items():
        for h in s["hunks"]:
            entries.append({"sample_id": cve, "hunk_identity": h["hunk_identity"]})
    doc = {"schema": "v4-critical-hunks-template/1",
           "status": "TEMPLATE_UNLABELED",
           "note": ("仅机械身份；不含 coverage、不含任何建议标签。"
                    "标注者各自填写 reviewer{N}.jsonl，仲裁后生成 frozen.json"),
           "n_entries": len(entries), "entries": entries}
    write_text_lf(out_dir / "critical_hunks.template.json",
                  json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
    return doc


def _ident_key(ident: dict) -> str:
    """hunk identity 的稳定键（用于严格 join）。"""
    return (f"{ident['file']}|{ident['file_status']}|{ident['old_start']}|"
            f"{ident['old_count']}|{ident['new_start']}|{ident['new_count']}|"
            f"{ident['body_lf_sha256']}")


def evaluate_coverage_gate(coverage: dict, frozen_registry: dict | None) -> list:
    """**生产 Gate 逻辑（纯函数，供测试直接调用）**。

    运行时按 hunk identity 严格 join `frozen criticality × current coverage`：
      - registry 缺失 / 未冻结 → 阻断；
      - identity 集合不等（缺/多/重复）→ 阻断；
      - SECURITY_CRITICAL × ABSENT → 阻断；
      - NON_CRITICAL × ABSENT → 不阻断。
    **只读 coverage 的当前值**，绝不读 registry 内可能过期的 coverage。
    """
    errs = []
    if not isinstance(coverage, dict) or coverage.get("kind") != "MECHANICAL_COVERAGE_AUDIT":
        errs.append("coverage 工件缺失或 kind 异常")
        return errs
    if not frozen_registry or frozen_registry.get("status") != "FROZEN_LABELED":
        errs.append("frozen registry 缺失或未冻结（status != FROZEN_LABELED）→ 保守阻断")
        return errs
    # 当前 coverage 的 identity → 状态
    cur = {}
    dup = []
    for s in coverage["samples"].values():
        for h in s["hunks"]:
            k = _ident_key(h["hunk_identity"])
            if k in cur:
                dup.append(k)
            cur[k] = h["coverage"]
    if dup:
        errs.append(f"当前 coverage 存在重复 identity {len(dup)} 条")
    # frozen registry 的 identity → criticality
    froz, fdup = {}, []
    for e in frozen_registry.get("entries", []):
        if e.get("criticality") not in ("SECURITY_CRITICAL", "NON_CRITICAL"):
            errs.append(f"registry 含未裁决 criticality: {e.get('sample_id')}")
            continue
        k = _ident_key(e["hunk_identity"])
        if k in froz:
            fdup.append(k)
        froz[k] = e["criticality"]
    if fdup:
        errs.append(f"frozen registry 存在重复 identity {len(fdup)} 条")
    # 集合严格相等
    missing = sorted(set(cur) - set(froz))
    extra = sorted(set(froz) - set(cur))
    if missing:
        errs.append(f"registry 缺少 {len(missing)} 条当前 hunk identity（新 hunk 未标注）")
    if extra:
        errs.append(f"registry 含 {len(extra)} 条当前 coverage 不存在的 identity（陈旧）")
    # 关键 hunk × 当前覆盖
    crit_absent = sorted({k.split("|")[0] for k, v in froz.items()
                          if v == "SECURITY_CRITICAL" and cur.get(k) == "ABSENT"})
    if crit_absent:
        errs.append(f"SECURITY_CRITICAL × ABSENT（当前覆盖）: {crit_absent}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["canonical", "upstream", "arms", "gate",
                                     "feasibility", "g0", "coverage", "all"])
    ap.add_argument("--out-dir", type=Path, default=OUT_DIR)
    ap.add_argument("--canonical-manifest", type=Path, default=None,
                    help="V4 权威 manifest（必须显式传入且等于 v4_manifest 单一来源）")
    ap.add_argument("--expected-manifest-sha256", default=None,
                    help="P0-2 闭环：期望 manifest SHA-256（运行时重算校验，防 TOCTOU）")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    # P0-2：缺参数即拒绝；且必须与单一来源一致（防 split-brain）
    if args.canonical_manifest is None:
        print("[FAIL] 必须显式传入 --canonical-manifest（V4 禁止隐式默认）")
        return 1
    if args.canonical_manifest.resolve() != v4_manifest.manifest_path().resolve():
        print(f"[FAIL] --canonical-manifest 与单一来源不符: "
              f"{args.canonical_manifest} != {v4_manifest.manifest_path()}")
        return 1
    _cur_sha = v4_manifest.manifest_sha256()
    if args.expected_manifest_sha256 and _cur_sha != args.expected_manifest_sha256:
        print(f"[FAIL] manifest SHA 漂移: 期望 {args.expected_manifest_sha256[:16]} "
              f"实际 {_cur_sha[:16]}")
        return 1
    print(f"[manifest] {v4_manifest.manifest_path().name} sha256={_cur_sha[:16]}")
    if args.step in ("canonical", "all"):
        doc = build_canonical_manifest(args.out_dir)
        reg = build_manifest_registry(args.out_dir)
        print(f"[GateA-1] v4_canonical_manifest.json: {doc['n_candidates']} 候选，"
              f"{doc['n_confirmation']} 确认性；errors={len(doc['errors'])}")
        print(f"[Registry] {len(reg['entries'])} 条："
              f"{[(e['consumer'], e['status']) for e in reg['entries']]}")
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
        stale = build_stale_artifacts(args.out_dir)
        rep = build_gate_a_report(args.out_dir)
        print(f"[Stale] stale_artifacts.json: {stale['status_counts']} | "
              f"patches {stale['patches']['n_files']} 文件 "
              f"tree={stale['patches']['tree_sha256'][:12]}")
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
    if args.step in ("g0", "all"):
        g = build_g0_prompts(args.out_dir)
        print(f"[G0] FIT={g['n_fit']} OVER_BUDGET={g['n_over']} "
              f"RENDER_FAILURE={g['n_render_failure']} / {len(g['rows'])}")
        for r in g["rows"]:
            if r["verdict"] != "FIT":
                print(f"  {r['verdict']} {r['arm']}/{r['sample_id']}: "
                      f"{r.get('error') or str(r.get('prompt_tokens')) + ' tok'}")
    if args.step in ("coverage", "all"):
        cov = build_hunk_coverage(args.out_dir)
        tpl = build_critical_hunks_template(args.out_dir)
        print(f"[Coverage] 机械审计 {cov['totals']}；mechanical_absent_samples="
              f"{len(cov['mechanical_absent_samples'])}: {cov['mechanical_absent_samples']}")
        print(f"[Template] critical_hunks.template.json {tpl['n_entries']} 条"
              f"（纯身份，不含标签/coverage）—> 待生成双盲标注包")
    return 0


if __name__ == "__main__":
    sys.exit(main())
