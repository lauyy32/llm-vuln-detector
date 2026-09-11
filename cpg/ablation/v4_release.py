# -*- coding: utf-8 -*-
"""V4 标注发布与回收（A-1 分发登记 / A-2 事务式回收 / A-3 预注册固化）。

设计纪律（来自外部验收）：
  - **per-reviewer payload**：登记表分别表达 reviewer1 / reviewer2 **各自**收到的集合
    （交接说明 + 手册 + **自己的** JSONL），并各算一棵 payload tree SHA。
  - **fail-closed 双提交**：`--source-commit` 必填；校验 SHA 存在、工作树干净、
    HEAD 与该 commit 一致、源文件 blob SHA 与该 commit 内一致。
  - **真事务**：唯一临时目录（含 pid+随机后缀）→ try/finally 清理 → 原子提升；
    **绝不删除**既有成功结果（幂等返回或 fail-closed）。
  - **registry fail-closed**：registry 缺失/不含 template 条目时，**在建目录前**即失败。
  - **不预填**：仲裁模板 `final_*` 全 null。

用法：
    python cpg/ablation/v4_release.py prereg --source-commit <sha>
    python cpg/ablation/v4_release.py registry --source-commit <sha>
    python cpg/ablation/v4_release.py recover --sub1 <f1> --sub2 <f2>
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_annotation as va  # noqa: E402

OUT = ROOT / "cpg" / "ablation" / "artifacts" / "v4"
ANN = OUT / "annotation"
RECOVERY_ROOT = OUT / "recovery"

HANDOVER = ANN / "标注交接说明.md"
HANDBOOK = ANN / "标注手册.md"

INTERNAL_PROVENANCE = [
    OUT / "critical_hunks.template.json",
    OUT / "v4_hunk_coverage.json",     # 内部机械审计，**不发放**
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
    p = Path(p)
    try:
        return p.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return p.resolve().as_posix()


def _f(p: Path) -> dict:
    b = p.read_bytes()
    return {"path": _rel(p), "bytes": len(b), "lines": b.count(b"\n"), "sha256": _sha(b)}


def _tree_sha(files: list) -> str:
    """对 [(name, sha256)] 的确定性序列取 tree SHA。"""
    return _sha("\n".join(f"{n}:{s}" for n, s in sorted(files)).encode("utf-8"))


# ---------------------------------------------------------------------------
# fail-closed 双提交校验
# ---------------------------------------------------------------------------
def _git(*args: str) -> tuple[int, str]:
    r = subprocess.run(["git", *args], cwd=str(ROOT), capture_output=True, text=True)
    return r.returncode, (r.stdout or "").strip()


def require_source_commit(source_commit: str | None, files: list) -> dict:
    """fail-closed：校验 source_commit 存在 / 工作树干净 / HEAD 一致 / blob 一致。

    任一条不成立即抛异常（**不再允许 UNSPECIFIED 或随意传入**）。
    """
    if not source_commit:
        raise ValueError("缺少 --source-commit（fail-closed，不接受省略）")
    rc, _ = _git("cat-file", "-e", f"{source_commit}^{{commit}}")
    if rc != 0:
        raise ValueError(f"source_commit 不存在: {source_commit}")
    rc, dirty = _git("status", "--porcelain")
    if rc != 0 or dirty:
        raise ValueError(f"工作树不干净，禁止冻结（dirty={dirty[:120]!r}）")
    rc, head = _git("rev-parse", "HEAD")
    if rc != 0 or head != source_commit:
        raise ValueError(f"HEAD({head[:12]}) != source_commit({source_commit[:12]})")
    # 记录文件的 blob SHA 必须与该 commit 内一致
    checked = []
    for p in files:
        rc, blob = _git("show", f"{source_commit}:{_rel(p)}")
        if rc != 0:
            raise ValueError(f"{_rel(p)} 不在 commit {source_commit[:12]} 中")
        # 行尾归一化（Windows 检出会把 LF 变 CRLF，不能因此误判"工作树偏离"）
        _crlf = chr(13) + chr(10)
        want = _sha(blob.replace(_crlf, chr(10)).encode("utf-8"))
        got = _sha(p.read_bytes().replace(_crlf.encode("utf-8"), chr(10).encode("utf-8")))
        if want != got:
            raise ValueError(f"{_rel(p)} 与 commit 内不一致（工作树已偏离）")
        checked.append({"path": _rel(p), "blob_sha256_in_commit": want,
                        "normalized_lf": True})
    return {"source_commit": source_commit, "head": head, "clean": True, "checked": checked}


# ---------------------------------------------------------------------------
# A-1：分发登记（per-reviewer payload）
# ---------------------------------------------------------------------------
def distribution_registry(source_commit: str) -> dict:
    """登记表：**per-reviewer payload**（各自精确集合）+ internal provenance。"""
    payload_common = [HANDOVER, HANDBOOK]
    per_reviewer = {
        "reviewer1": payload_common + [ANN / "critical_hunks.reviewer1.jsonl"],
        "reviewer2": payload_common + [ANN / "critical_hunks.reviewer2.jsonl"],
    }
    files = sorted({p for v in per_reviewer.values() for p in v} | set(INTERNAL_PROVENANCE))
    prov = require_source_commit(source_commit, files)

    payload_docs, trees = {}, {}
    for who, ps in per_reviewer.items():
        payload_docs[who] = [_f(p) for p in ps]
        trees[who] = _tree_sha([(x["path"].split("/")[-1], x["sha256"]) for x in payload_docs[who]])
    real_patches = [{"name": c.name, "sha256": _sha(c.read_bytes())}
                    for c in sorted((OUT / "patches" / "real").glob("*.diff"))]
    doc = {
        "schema": "v4-distribution-registry/3",
        "source_commit": prov["source_commit"],
        "provenance_check": prov,
        "note": ("每人只收到【交接说明 + 手册 + 自己的 JSONL】；coverage 等内部工件只进 "
                 "internal_provenance，不发放"),
        "reviewer_payloads": payload_docs,
        "reviewer_payload_tree_sha256": trees,
        "internal_provenance": {
            "files": [_f(p) for p in INTERNAL_PROVENANCE],
            "generator_sources": [{"path": s, "sha256": _sha((ROOT / s).read_bytes())}
                                  for s in GENERATOR_SOURCES if (ROOT / s).exists()],
            "real_patches_tree_sha256": _tree_sha([(x["name"], x["sha256"]) for x in real_patches]),
            "real_patches": real_patches,
        },
        "protocol": {
            "blind": True,
            "contains_ai_suggestions": False,
            "per_reviewer": "两人收到的集合不同（各自的 reviewerN.jsonl）",
            "submission_rule": "私下分别提交；先交者结果不得出现在后交者可见位置",
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
PREREG_STATUS = "DRAFT_PREREG"


def prereg(source_commit: str) -> dict:
    doc_path = ROOT / "cpg/ablation/V4-四臂算法预注册.md"
    prov = require_source_commit(source_commit, [doc_path])
    doc = {
        "schema": "v4-prereg/3",
        "status": PREREG_STATUS,
        "source_commit": prov["source_commit"],
        "provenance_check": prov,
        "documents": [_f(doc_path)],
        "params": PREREG_PARAMS,
        "status_detail": {
            "done": "设计草案与部分固定参数",
            "pending": ["placebo 确定性生成算法", "shuffled 硬/软约束·放宽顺序·无候选处置",
                        "oracle 逐臂机器化判据", "最终统计功效脚本与口径"],
            "policy": "**不得消费为权威输入**（不得据此生成正式四臂或 RUN_LOCK）",
        },
        "policy": {
            "post_recovery": "只允许把标签代入已冻结算法；不得修改任何参数",
            "deviation": "必须走 deviation log（原因/影响/作废的已跑结果）",
            "recompute_gate": "双干净目录的四臂 prompt/selection/coverage SHA 必须一致",
        },
    }
    (OUT / "v4_prereg.json").write_bytes(
        (json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


# ---------------------------------------------------------------------------
# A-2：真事务回收
# ---------------------------------------------------------------------------
def _run_name(sub1: Path, sub2: Path) -> str:
    h = _sha((_sha(sub1.read_bytes()) + _sha(sub2.read_bytes())).encode("utf-8"))
    return f"run-{h[:16]}"


def _require_registry_template(template: Path) -> dict:
    """fail-closed：registry 必须存在、可解析、且含 template 条目并 SHA 一致。"""
    reg_path = ANN / "distribution_registry.json"
    if not reg_path.exists():
        raise ValueError("缺 distribution_registry.json（分发版本未登记，拒绝回收）")
    try:
        reg = json.loads(reg_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"distribution_registry.json 不可解析: {e}")
    want = None
    for f in reg.get("internal_provenance", {}).get("files", []):
        if f["path"].endswith("critical_hunks.template.json"):
            want = f["sha256"]
    if want is None:
        raise ValueError("registry 未列出 template（无法核对分发版本）")
    got = _sha(template.read_bytes())
    if want != got:
        raise ValueError(f"template SHA 与分发登记不符（登记 {want[:12]} vs 当前 {got[:12]}）")
    return {"registry": _rel(reg_path), "template_match": True,
            "source_commit": reg.get("source_commit")}


def recover(sub1: Path, sub2: Path, template: Path | None = None,
            root: Path | None = None) -> dict:
    """真事务回收：内存校验 → registry fail-closed → 唯一临时目录 → 原子提升。

    - registry 缺失/异常/不含 template → **建目录前**即失败（零落盘）；
    - 临时目录 **唯一**（pid + uuid），并发同输入不互删；
    - 写盘包在 try 内，失败时 finally 清理临时目录；
    - 目标目录已存在：内容一致 → **幂等返回**；不一致 → fail-closed；**绝不删除既有结果**。
    """
    template = template or (OUT / "critical_hunks.template.json")

    def _fp(p: Path) -> dict:
        """**仅指纹**（不含路径）：提交可能来自仓库外，记录绝对路径既无意义也有泄露风险。"""
        d = _f(p)
        d.pop("path", None)
        d["filename"] = p.name
        return d

    # 1) 内存校验
    v1 = va.validate_submission(sub1, template)
    v2 = va.validate_submission(sub2, template)
    if not (v1["ok"] and v2["ok"]):
        raise ValueError(f"提交校验失败：r1={v1['errors'][:3]} r2={v2['errors'][:3]}")
    for v in (v1, v2):
        v.pop("path", None)      # 去绝对路径（含本机用户名）
    # 2) registry fail-closed（在建目录之前）
    reg_check = _require_registry_template(template)
    agree = va.agreement_report(sub1, sub2, template)

    root = root or RECOVERY_ROOT
    final_dir = root / _run_name(sub1, sub2)
    # 3) 幂等 / 冲突（不删除既有成功结果）
    if final_dir.exists():
        prev = final_dir / "recovery_report.json"
        if prev.exists():
            old = json.loads(prev.read_text(encoding="utf-8"))
            same = (old.get("submissions", {}).get("reviewer1", {}).get("sha256")
                    == _fp(sub1)["sha256"]
                    and old.get("submissions", {}).get("reviewer2", {}).get("sha256")
                    == _fp(sub2)["sha256"])
            if same:
                old["run_dir"] = _rel(final_dir)
                old["idempotent_replay"] = True
                return old
        raise ValueError(f"目标运行目录已存在且内容不匹配，拒绝覆盖: {_rel(final_dir)}")

    tmp_dir = root / f".tmp-{_run_name(sub1, sub2)}-{os.getpid()}-{uuid.uuid4().hex[:8]}"
    try:
        root.mkdir(parents=True, exist_ok=True)
        tmp_dir.mkdir(parents=True)
        dis = va.disagreement_list(sub1, sub2, template, tmp_dir / "disagreements.json")
        report = {
            "schema": "v4-recovery/3",
            "status": "REAL_RECOVERY",
            "source_commit": reg_check.get("source_commit"),
            "template": _f(template),
            "submissions": {"reviewer1": _fp(sub1), "reviewer2": _fp(sub2)},
            "validation": {"reviewer1": v1, "reviewer2": v2},
            "agreement": agree,
            "registry_check": reg_check,
            "disagreement": {
                "n_items": dis["n_items"],
                "kinds": {k: sum(1 for i in dis["items"] if i["kind"] == k)
                          for k in ("DISAGREEMENT", "UNANIMOUS_UNCERTAIN",
                                    "PARTIAL_UNCERTAIN")},
                # 只记**提升后**仍然成立的信息（**不得记临时路径**）
                "artifact_relpath": "disagreements.json",
                "artifact": {k: v for k, v in _f(tmp_dir / "disagreements.json").items()
                             if k != "path"},
            },
            "prefilled_final_fields": sum(
                1 for i in dis["items"]
                if any(i.get(f) is not None for f in va.FINAL_FIELDS)),
            "next_step": ("第三人填写 disagreements.json 的 final_*；必要时填 exclusions"
                          "（结构化，仅限 UNCERTAIN 且须覆盖该样本全部 pending hunk）"),
            # run_dir 在提升前即可确定（目录名确定性），故在写盘时一并记录
            "run_dir": _rel(final_dir),
        }
        (tmp_dir / "recovery_report.json").write_bytes(
            (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        tmp_dir.replace(final_dir)               # 原子提升
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)   # 失败即清理，零残留
        # 若 root 是本轮刚创建且已空，一并移除（保持"零落盘"语义）
        try:
            if root.exists() and not any(root.iterdir()):
                root.rmdir()
        except OSError:
            pass
        raise
    return report


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["prereg", "registry", "recover"])
    ap.add_argument("--source-commit", default=None)
    ap.add_argument("--sub1", type=Path)
    ap.add_argument("--sub2", type=Path)
    ap.add_argument("--template", type=Path, default=None)
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        if args.step == "prereg":
            d = prereg(args.source_commit)
            print(f"[A-3] status={d['status']} source_commit={d['source_commit'][:12]}")
            return 0
        if args.step == "registry":
            d = distribution_registry(args.source_commit)
            print(f"[A-1] per-reviewer payload @ {d['source_commit'][:12]}")
            for who, items in d["reviewer_payloads"].items():
                print(f"  [{who}] tree={d['reviewer_payload_tree_sha256'][who][:12]}")
                for x in items:
                    print(f"      {x['path'].split('/')[-1]} ({x['bytes']}B)")
            return 0
        if not (args.sub1 and args.sub2):
            print("[FAIL] recover 需要 --sub1 与 --sub2")
            return 1
        r = recover(args.sub1, args.sub2, args.template)
        print(f"[A-2] → {r['run_dir']} idempotent={r.get('idempotent_replay', False)}")
        print(f"  prefilled={r['prefilled_final_fields']} registry={r['registry_check']}")
        return 0
    except Exception as e:
        print(f"[FAIL] {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
