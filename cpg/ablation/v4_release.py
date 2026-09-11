# -*- coding: utf-8 -*-
"""V4 标注发布与回收（A-1 分发登记 / A-2 回收只读流水线）。

设计纪律：
  - **只读优先**：A-2 在任一步校验失败时**不落盘**任何下游产物；
  - **不预填**：生成的仲裁空模板只含结构，`final_*` 全为 null，**不含任何建议标签**；
  - **可审计**：所有产物记录 bytes/行数/SHA，并绑定 template 与两份提交的 SHA。

用法：
    python cpg/ablation/v4_release.py registry          # A-1 分发登记表
    python cpg/ablation/v4_release.py recover \\
        --sub1 <reviewer1.jsonl> --sub2 <reviewer2.jsonl>   # A-2 回收只读流水线
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_annotation as va  # noqa: E402

OUT = ROOT / "cpg" / "ablation" / "artifacts" / "v4"
ANN = OUT / "annotation"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _f(p: Path) -> dict:
    b = p.read_bytes()
    try:
        rel = p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        rel = p.as_posix()          # 临时目录/外部文件：不强求相对 ROOT
    return {"path": rel, "bytes": len(b), "lines": b.count(b"\n"), "sha256": _sha(b)}


def _git_commit() -> str | None:
    import subprocess
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                       capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


# ---------------------------------------------------------------------------
# A-1：分发登记表
# ---------------------------------------------------------------------------
DISTRIBUTION_FILES = [
    ANN / "标注交接说明.md",
    ANN / "critical_hunks.reviewer1.jsonl",
    ANN / "critical_hunks.reviewer2.jsonl",
    OUT / "critical_hunks.template.json",
    OUT / "v4_hunk_coverage.json",
]


def distribution_registry() -> dict:
    """固化标注包全量指纹：日后可证明两位标注者拿到的是**同一协议同一版本**。"""
    missing = [str(p) for p in DISTRIBUTION_FILES if not p.exists()]
    if missing:
        raise FileNotFoundError(f"缺分发文件: {missing}")
    real_patches = []
    pdir = OUT / "patches" / "real"
    for c in sorted(pdir.glob("*.diff")):
        real_patches.append({"name": c.name, "sha256": _sha(c.read_bytes())})
    doc = {
        "schema": "v4-distribution-registry/1",
        "generated_git_commit": _git_commit(),
        "generator_impl_sha256": {
            "v4_annotation.py": _sha((ROOT / "cpg/ablation/v4_annotation.py").read_bytes()),
            "v4_gate_a.py": _sha((ROOT / "cpg/ablation/v4_gate_a.py").read_bytes()),
            "v4_selector.py": _sha((ROOT / "cpg/ablation/v4_selector.py").read_bytes()),
        },
        "canonical_manifest": _f(ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.v2.json"),
        "real_patches_tree_sha256": _sha("\n".join(
            f"{x['name']}:{x['sha256']}" for x in real_patches).encode("utf-8")),
        "real_patches": real_patches,
        "distribution_files": [_f(p) for p in DISTRIBUTION_FILES],
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
# A-2：回收只读流水线
# ---------------------------------------------------------------------------
def recover(sub1: Path, sub2: Path, template: Path | None = None) -> dict:
    """回收流水线：validate×2 → agreement → disagreement。

    **只读**：任一步失败即抛异常且**不落盘**下游产物；
    产出的仲裁空模板 `final_*` 全为 null（**不预填任何建议**）。
    """
    template = template or (OUT / "critical_hunks.template.json")
    out_dir = OUT / "recovery"
    report: dict = {"schema": "v4-recovery/1", "template": _f(template),
                    "submissions": {"reviewer1": _f(sub1), "reviewer2": _f(sub2)}}

    # 1) 双份校验（fail-closed）
    v1 = va.validate_submission(sub1, template)
    v2 = va.validate_submission(sub2, template)
    report["validation"] = {"reviewer1": v1, "reviewer2": v2}
    if not (v1["ok"] and v2["ok"]):
        raise ValueError(f"提交校验失败：r1={v1['errors'][:3]} r2={v2['errors'][:3]}")

    # 2) 一致性统计
    report["agreement"] = va.agreement_report(sub1, sub2, template)

    # 3) 分歧清单 + **空**仲裁模板（不预填）
    dis = va.disagreement_list(sub1, sub2, template, out_dir / "disagreements.json")
    report["disagreement"] = {"n_items": dis["n_items"],
                              "kinds": {k: sum(1 for i in dis["items"] if i["kind"] == k)
                                        for k in ("DISAGREEMENT", "UNANIMOUS_UNCERTAIN",
                                                  "PARTIAL_UNCERTAIN")},
                              "artifact": _f(out_dir / "disagreements.json")}
    report["next_step"] = ("第三人填写 disagreements.json 的 final_*（含 final_role/"
                           "final_dependency_group/final_counterfactual/final_evidence/"
                           "final_reason/adjudicator）；必要时填 exclusions（结构化，"
                           "仅限 UNCERTAIN 且须覆盖该样本全部 pending hunk）")
    (out_dir / "recovery_report.json").write_bytes(
        (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["registry", "recover"])
    ap.add_argument("--sub1", type=Path)
    ap.add_argument("--sub2", type=Path)
    ap.add_argument("--template", type=Path, default=None)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    if args.step == "registry":
        d = distribution_registry()
        print(f"[A-1] distribution_registry.json: {len(d['distribution_files'])} 个分发文件已登记")
        for x in d["distribution_files"]:
            print(f"  - {x['path']} ({x['bytes']}B, sha={x['sha256'][:12]})")
        print(f"  real patches tree: {d['real_patches_tree_sha256'][:16]}")
        return 0
    if not (args.sub1 and args.sub2):
        print("[FAIL] recover 需要 --sub1 与 --sub2")
        return 1
    r = recover(args.sub1, args.sub2, args.template)
    print(f"[A-2] 校验通过 | κ(role)={r['agreement']['cohen_kappa_role']} "
          f"raw_role={r['agreement']['raw_agreement_role']}")
    print(f"  dependency/counterfactual/evidence 一致率: "
          f"{r['agreement']['raw_agreement_dependency']}/"
          f"{r['agreement']['raw_agreement_counterfactual']}/"
          f"{r['agreement']['raw_agreement_evidence']}")
    print(f"  分歧 {r['disagreement']['n_items']} 条 {r['disagreement']['kinds']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
