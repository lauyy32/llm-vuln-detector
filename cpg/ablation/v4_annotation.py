# -*- coding: utf-8 -*-
"""V4 标注基础设施：提交校验 / 一致性统计 / 分歧清单 / frozen registry 编译。

**不含任何研究判断**（不预设 criticality 定义、不预设依赖组），只做机械校验与汇总：
  validate_submission  → 单份标注文件的 schema/SHA 校验（fail-closed）
  agreement_report     → Cohen's κ + 原始一致率 + UNCERTAIN 比例
  disagreement_list    → 分歧清单（供第三人仲裁）
  compile_frozen       → 仲裁记录 → critical_hunks.frozen.json（仅身份+最终标签）

证据不足（UNCERTAIN）**不得**被机械转成确定标签；仲裁者须显式给出 adjudication。
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

VALID_CRIT = {"DIRECT_SECURITY", "SUPPORTING_REQUIRED", "NON_CRITICAL", "UNCERTAIN"}
VALID_EVIDENCE = {"PoC", "regression-test", "code-reasoning", "insufficient"}


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _key(ident: dict) -> str:
    return (f"{ident.get('sample_id')}|{ident['file']}|{ident['file_status']}|"
            f"{ident['old_start']}|{ident['old_count']}|{ident['new_start']}|"
            f"{ident['new_count']}|{ident['body_lf_sha256']}")


def _read_jsonl(p: Path) -> list:
    return [json.loads(l) for l in (p.read_text(encoding="utf-8").splitlines() if False else p.read_text(encoding="utf-8").splitlines()) if l.strip()]


def validate_submission(path: Path, template_path: Path) -> dict:
    """校验一份标注提交：identity 集合与 template 完全一致 + 字段合法 + SHA 记录。

    fail-closed：缺条/多条/重复/字段非法/空值未填 均记入 errors。
    """
    errs = []
    tpl = json.loads(template_path.read_text(encoding="utf-8"))
    want = {_key(e["hunk_identity"]) for e in tpl["entries"]}
    rows = [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    got, dup = set(), []
    for r in rows:
        k = _key(r["hunk_identity"])
        if k in got:
            dup.append(k)
        got.add(k)
        if r.get("criticality") not in VALID_CRIT:
            errs.append(f"{r.get('sample_id')}: 非法 criticality={r.get('criticality')}")
        if r.get("evidence") is not None and r["evidence"] not in VALID_EVIDENCE:
            errs.append(f"{r.get('sample_id')}: 非法 evidence={r.get('evidence')}")
        if not r.get("reason"):
            errs.append(f"{r.get('sample_id')}: reason 为空")
    if dup:
        errs.append(f"重复 identity {len(dup)} 条")
    if got != want:
        errs.append(f"identity 集合不符: 缺 {len(want - got)}，多 {len(got - want)}")
    return {"path": str(path), "n_rows": len(rows), "bytes": path.stat().st_size,
            "sha256": _sha(path.read_bytes()), "errors": errs,
            "ok": not errs}


def _cohen_kappa(a: list, b: list, labels: list) -> float:
    n = len(a)
    if n == 0:
        return 0.0
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca.get(l, 0) / n) * (cb.get(l, 0) / n) for l in labels)
    return 0.0 if pe == 1 else (po - pe) / (1 - pe)


def agreement_report(sub1: Path, sub2: Path) -> dict:
    """Cohen's κ + 原始一致率 + UNCERTAIN 比例（机械统计，不含判断）。"""
    r1 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub1.read_text(encoding="utf-8").splitlines() if l.strip()}
    r2 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub2.read_text(encoding="utf-8").splitlines() if l.strip()}
    keys = sorted(set(r1) & set(r2))
    a = [r1[k]["criticality"] for k in keys]
    b = [r2[k]["criticality"] for k in keys]
    labels = sorted(VALID_CRIT)
    raw = sum(1 for x, y in zip(a, b) if x == y) / len(keys) if keys else 0.0
    return {"n_common": len(keys),
            "raw_agreement": round(raw, 4),
            "cohen_kappa": round(_cohen_kappa(a, b, labels), 4),
            "only_in_reviewer1": len(set(r1) - set(r2)),
            "only_in_reviewer2": len(set(r2) - set(r1)),
            "uncertain_ratio_r1": round(sum(1 for x in a if x == "UNCERTAIN") / len(a), 4) if a else None,
            "uncertain_ratio_r2": round(sum(1 for x in b if x == "UNCERTAIN") / len(b), 4) if b else None}


def disagreement_list(sub1: Path, sub2: Path, out: Path) -> dict:
    """分歧清单（供第三人仲裁）；含双方标签与证据，**不含 AI 建议**。"""
    r1 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub1.read_text(encoding="utf-8").splitlines() if l.strip()}
    r2 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub2.read_text(encoding="utf-8").splitlines() if l.strip()}
    items = []
    for k in sorted(set(r1) & set(r2)):
        if r1[k]["criticality"] != r2[k]["criticality"]:
            items.append({"hunk_identity": r1[k]["hunk_identity"],
                          "sample_id": r1[k]["sample_id"],
                          "reviewer1": {"criticality": r1[k]["criticality"],
                                        "evidence": r1[k].get("evidence"),
                                        "reason": r1[k].get("reason")},
                          "reviewer2": {"criticality": r2[k]["criticality"],
                                        "evidence": r2[k].get("evidence"),
                                        "reason": r2[k].get("reason")},
                          "adjudication": None, "adjudicator": None, "final": None})
    doc = {"schema": "v4-disagreements/1", "n_disagreements": len(items),
           "note": "第三人只处理分歧；UNCERTAIN 不得被机械转成确定标签",
           "items": items}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


def compile_frozen(template_path: Path, sub1: Path, sub2: Path, adjudicated: Path,
                   out: Path) -> dict:
    """编译 frozen registry：一致项直接采用；分歧项须有 adjudication；UNCERTAIN 保留。

    fail-closed：分歧未裁决、adjudication 非法、identity 缺失 → 抛异常。
    """
    tpl = {_key(e["hunk_identity"]): e for e in
           json.loads(template_path.read_text(encoding="utf-8"))["entries"]}
    r1 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub1.read_text(encoding="utf-8").splitlines() if l.strip()}
    r2 = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
          for l in sub2.read_text(encoding="utf-8").splitlines() if l.strip()}
    adj = {_key(json.loads(l)["hunk_identity"]): json.loads(l)
           for l in adjudicated.read_text(encoding="utf-8").splitlines() if l.strip()}
    if set(r1) != set(tpl) or set(r2) != set(tpl):
        raise ValueError("提交与 template 的 identity 集合不一致")
    entries, unresolved = [], []
    for k, t in tpl.items():
        c1, c2 = r1[k]["criticality"], r2[k]["criticality"]
        if c1 == c2:
            final, reason, ev = c1, r1[k].get("reason"), r1[k].get("evidence")
        else:
            a = adj.get(k)
            if not a or a.get("final") not in VALID_CRIT or not a.get("adjudicator"):
                unresolved.append(t["sample_id"])
                continue
            final = a["final"]
            reason = a.get("reason") or f"adjudicated (r1={c1}, r2={c2})"
            ev = a.get("evidence")
        entries.append({"sample_id": t["sample_id"], "hunk_identity": t["hunk_identity"],
                        "criticality": final, "reason": reason, "evidence": ev})
    if unresolved:
        raise ValueError(f"存在未裁决分歧: {sorted(set(unresolved))}")
    # frozen 只含 SECURITY_CRITICAL / NON_CRITICAL（Gate 消费的语义）
    for e in entries:
        e["criticality"] = ("SECURITY_CRITICAL"
                            if e["criticality"] in ("DIRECT_SECURITY", "SUPPORTING_REQUIRED")
                            else "NON_CRITICAL" if e["criticality"] == "NON_CRITICAL"
                            else "UNCERTAIN")
    doc = {"schema": "v4-critical-hunks-frozen/1", "status": "FROZEN_LABELED",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes()),
                                 "adjudicated": _sha(adjudicated.read_bytes())},
           "n_entries": len(entries),
           "n_uncertain": sum(1 for e in entries if e["criticality"] == "UNCERTAIN"),
           "entries": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc
