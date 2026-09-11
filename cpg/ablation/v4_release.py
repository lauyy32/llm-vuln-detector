# -*- coding: utf-8 -*-
"""V4 标注发布与回收（A-1 分发登记 / A-2 事务式回收 / A-3 预注册固化）。

设计纪律（来自外部验收）：
  - **payload 与 provenance 分离**：只把标注者**真正需要的**材料列为 `reviewer_payload`；
    `v4_hunk_coverage.json` 等内部分析工件**绝不进入**发放清单。
  - **事务式回收**：所有校验与产物先在内存/唯一临时目录完成，全部成功后才**原子提升**
    为以两份 submission SHA 命名的运行目录；**失败不改变任何现有正式工件**。
  - **两提交冻结**：冻结工件记录 `source_commit`（**其代码/文档所在的那个提交**），
    不用"生成时的当前 commit"自引用。
  - **不预填**：仲裁模板 `final_*` 全为 null，不含任何建议标签。

用法：
    python cpg/ablation/v4_release.py prereg --source-commit <sha>
    python cpg/ablation/v4_release.py registry --source-commit <sha>
    python cpg/ablation/v4_release.py recover --sub1 <f1> --sub2 <f2>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_annotation as va  # noqa: E402

OUT = ROOT / "cpg" / "ablation" / "artifacts" / "v4"
ANN = OUT / "annotation"
RECOVERY_ROOT = OUT / "recovery"

# ---------------------------------------------------------------------------
# A-1：分发登记（payload 与 provenance **严格分离**）
# ---------------------------------------------------------------------------
REVIEWER_PAYLOAD = [
    ANN / "标注交接说明.md",
    ANN / "标注手册.md",              # ← 标注者真正的证据材料（完整补丁 + 上下文 + hunk_id）
    ANN / "critical_hunks.reviewer1.jsonl",
    ANN / "critical_hunks.reviewer2.jsonl",
]
INTERNAL_PROVENANCE = [
    OUT / "critical_hunks.template.json",
    OUT / "v4_hunk_coverage.json",     # ← 内部机械审计，**不发放**
    ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.v2.json",
]
GENERATOR_SOURCES = [
    "cpg/ablation/v4_release.py",
    "cpg/ablation/v4_annotation.py",
    "cpg/ablation/v4_gate_a.py",
    "cpg/ablation/v4_selector.py",
]


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _rel(p) -> str:
    """安全相对路径：不在 ROOT 下时回退绝对路径（**防外部/临时目录导致 ValueError**）。"""
    p = Path(p)
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _f(p: Path) -> dict:
    b = p.read_bytes()
    rel = _rel(p)
    return {"path": rel, "bytes": len(b), "lines": b.count(b"\n"), "sha256": _sha(b)}


def distribution_registry(source_commit: str | None = None) -> dict:
    """登记表：**reviewer_payload**（真正发放的）+ **internal_provenance**（内部锚点）。

    `source_commit` 必须由调用方显式给出（两提交协议），**不用当前 HEAD 自引用**。
    """
    missing = [str(p) for p in REVIEWER_PAYLOAD + INTERNAL_PROVENANCE if not p.exists()]
    if missing:
        raise FileNotFoundError(f"缺登记文件: {missing}")
    real_patches = [{"name": c.name, "sha256": _sha(c.read_bytes())}
                    for c in sorted((OUT / "patches" / "real").glob("*.diff"))]
    doc = {
        "schema": "v4-distribution-registry/2",
        "source_commit": source_commit or "UNSPECIFIED",
        "note": ("payload 为**实际发放**给标注者的材料（含标注手册）；coverage 等内部工件"
                 "只进 provenance，不发放"),
        "reviewer_payload": [_f(p) for p in REVIEWER_PAYLOAD],
        "internal_provenance": {
            "files": [_f(p) for p in INTERNAL_PROVENANCE],
            "generator_sources": [
                {"path": s, "sha256": _sha((ROOT / s).read_bytes())}
                for s in GENERATOR_SOURCES if (ROOT / s).exists()],
            "real_patches_tree_sha256": _sha("\n".join(
                f"{x['name']}:{x['sha256']}" for x in real_patches).encode("utf-8")),
            "real_patches": real_patches,
        },
        "protocol": {
            "blind": True,
            "contains_ai_suggestions": False,
            "submission_rule": "两位标注者私下分别提交；先交者结果不得出现在后交者可见位置",
        },
    }
    (ANN / "distribution_registry.json").write_bytes(
        (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


# ---------------------------------------------------------------------------
# A-3：预注册固化（两提交协议）
# ---------------------------------------------------------------------------
PREREG_PARAMS = {
    "window": 20,
    "max_chars": 24000,
    "stable_sort_key": ["file_path", "old_start", "old_count",
                        "new_start", "new_count", "body_lf_sha256"],
    "critical_priority": "SECURITY_CRITICAL 优先纳入，其余按 stable_sort_key",
    "dependency_closure": "对 SECURITY_CRITICAL 的 dependency_group 取传递闭包并一并纳入",
    "budget_relief": "关键 hunk 不得因预算被丢弃；非关键可丢弃并计数落盘",
    "unrepresentable_rule": "critical hunk 仍无法纳入 → 该样本 ABSENT 并进 confirmatory_blocking",
    "tie_break": "同优先级按 stable_sort_key 字典序最小者优先",
    "role_mapping": {"DIRECT_SECURITY": "SECURITY_CRITICAL",
                     "SUPPORTING_REQUIRED": "SECURITY_CRITICAL",
                     "NON_CRITICAL": "NON_CRITICAL",
                     "UNCERTAIN": "EXCLUDE_FROM_CONFIRMATORY"},
    "num_ctx": 32768,
    "num_predict": 1024,
    "min_n_confirmatory": 8,
    "primary_estimand": "pairwise sufficiency discrimination rate",
}
PREREG_STATUS = "DRAFT_PREREG"   # 见 V4-四臂算法预注册.md：placebo/shuffled/oracle 与命名待补


def prereg(source_commit: str | None = None) -> dict:
    """固化预注册（记录 `source_commit` = 其代码与文档所在的提交，**非当前 HEAD**）。"""
    doc_path = ROOT / "cpg/ablation/V4-四臂算法预注册.md"
    doc = {
        "schema": "v4-prereg/2",
        "status": PREREG_STATUS,
        "source_commit": source_commit or "UNSPECIFIED",
        "documents": [_f(doc_path)] if doc_path.exists() else [],
        "params": PREREG_PARAMS,
        "policy": {
            "post_recovery": "只允许把标签代入本算法；不得修改任何参数",
            "deviation": "必须走 deviation log（原因/影响/作废的已跑结果）",
            "recompute_gate": "双干净目录的四臂 prompt/selection/coverage SHA 必须一致",
            "status_note": ("DRAFT_PREREG：placebo 生成算法、shuffled 约束与无候选处置、"
                            "oracle 逐臂接受标准、minimal-real/partial 命名口径尚未冻结；"
                            "**不得作为 A-4 的权威冻结输入**"),
        },
    }
    (OUT / "v4_prereg.json").write_bytes(
        (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


# ---------------------------------------------------------------------------
# A-2：事务式回收
# ---------------------------------------------------------------------------
def _transaction_dir_name(sub1: Path, sub2: Path) -> str:
    h = _sha((_sha(sub1.read_bytes()) + _sha(sub2.read_bytes())).encode("utf-8"))
    return f"run-{h[:16]}"


def recover(sub1: Path, sub2: Path, template: Path | None = None,
            root: Path | None = None) -> dict:
    """事务式回收：内存校验 → 唯一临时目录 → **全部成功后原子提升** → 消费 registry。

    - 失败时**不改变任何现有正式工件**（临时目录被清理）；
    - 运行目录以两份 submission SHA 命名，天然区分不同轮次；
    - 与 `distribution_registry.json` 核对 template SHA 与分发版本。
    """
    template = template or (OUT / "critical_hunks.template.json")

    # ---- 1) 全部校验在内存完成 ----
    v1 = va.validate_submission(sub1, template)
    v2 = va.validate_submission(sub2, template)
    if not (v1["ok"] and v2["ok"]):
        raise ValueError(f"提交校验失败：r1={v1['errors'][:3]} r2={v2['errors'][:3]}")
    agree = va.agreement_report(sub1, sub2, template)

    # ---- 2) 与分发登记核对 ----
    reg_path = ANN / "distribution_registry.json"
    reg_check = {"registry_present": reg_path.exists(), "template_match": None}
    if reg_path.exists():
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
        want = None
        for f in reg.get("internal_provenance", {}).get("files", []):
            if f["path"].endswith("critical_hunks.template.json"):
                want = f["sha256"]
        got = _sha(template.read_bytes())
        reg_check["template_match"] = (want == got)
        reg_check["source_commit"] = reg.get("source_commit")
        if want is not None and want != got:
            raise ValueError("当前 template SHA 与分发登记不符（分发版本已变）")

    # ---- 3) 写唯一临时目录（不触碰正式目录） ----
    root = root or RECOVERY_ROOT     # 测试可传临时目录，**避免合成数据污染正式目录**
    root.mkdir(parents=True, exist_ok=True)
    final_dir = root / _transaction_dir_name(sub1, sub2)
    tmp_dir = root / f".tmp-{_transaction_dir_name(sub1, sub2)}"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)

    dis = va.disagreement_list(sub1, sub2, template, tmp_dir / "disagreements.json")
    report = {
        "schema": "v4-recovery/2",
        "status": "REAL_RECOVERY",          # 与 SYNTHETIC 夹具显式区分
        "source_commit": reg_check.get("source_commit"),
        "template": _f(template),
        "submissions": {"reviewer1": _f(sub1), "reviewer2": _f(sub2)},
        "validation": {"reviewer1": v1, "reviewer2": v2},
        "agreement": agree,
        "registry_check": reg_check,
        "disagreement": {
            "n_items": dis["n_items"],
            "kinds": {k: sum(1 for i in dis["items"] if i["kind"] == k)
                      for k in ("DISAGREEMENT", "UNANIMOUS_UNCERTAIN",
                                "PARTIAL_UNCERTAIN")},
            "artifact": _f(tmp_dir / "disagreements.json"),
        },
        "prefilled_final_fields": sum(
            1 for i in dis["items"]
            if any(i.get(f) is not None for f in va.FINAL_FIELDS)),
        "next_step": ("第三人填写 disagreements.json 的 final_*；必要时填 exclusions"
                      "（结构化，仅限 UNCERTAIN 且须覆盖该样本全部 pending hunk）"),
    }
    (tmp_dir / "recovery_report.json").write_bytes(
        (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    # ---- 4) 原子提升 ----
    if final_dir.exists():
        shutil.rmtree(final_dir)
    tmp_dir.replace(final_dir)
    report["run_dir"] = _rel(final_dir)
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["prereg", "registry", "recover"])
    ap.add_argument("--source-commit", default=None,
                    help="两提交协议：其代码/文档所在的提交 SHA（不要用当前 HEAD 自引用）")
    ap.add_argument("--sub1", type=Path)
    ap.add_argument("--sub2", type=Path)
    ap.add_argument("--template", type=Path, default=None)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if args.step == "prereg":
        d = prereg(args.source_commit)
        print(f"[A-3] v4_prereg.json status={d['status']} source_commit="
              f"{d['source_commit'][:12]} params={len(d['params'])}")
        return 0
    if args.step == "registry":
        d = distribution_registry(args.source_commit)
        print(f"[A-1] payload {len(d['reviewer_payload'])} 项 / provenance "
              f"{len(d['internal_provenance']['files'])} 项 @ {d['source_commit'][:12]}")
        for x in d["reviewer_payload"]:
            print(f"  [PAYLOAD] {x['path']} ({x['bytes']}B, sha={x['sha256'][:12]})")
        for x in d["internal_provenance"]["files"]:
            print(f"  [INTERNAL] {x['path']} (sha={x['sha256'][:12]})")
        return 0
    if not (args.sub1 and args.sub2):
        print("[FAIL] recover 需要 --sub1 与 --sub2")
        return 1
    r = recover(args.sub1, args.sub2, args.template)
    print(f"[A-2] 事务完成 → {r['run_dir']}")
    print(f"  κ(role)={r['agreement']['cohen_kappa_role']} "
          f"raw_role={r['agreement']['raw_agreement_role']} | "
          f"分歧 {r['disagreement']['n_items']} {r['disagreement']['kinds']}")
    print(f"  自检：prefilled_final_fields = {r['prefilled_final_fields']}（须 0）| "
          f"registry.template_match={r['registry_check']['template_match']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
