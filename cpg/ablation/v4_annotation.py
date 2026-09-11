# -*- coding: utf-8 -*-
"""V4 标注基础设施：提交校验 / 一致性统计 / 分歧清单 / 仲裁 / frozen 编译。

**不含任何研究判断**，只做机械校验、汇总与状态机推进。

流水线（**每个入口都强制先 validate_submission**，杜绝重复 identity 被字典静默覆盖）：
    validate_submission  → 单份提交的 schema/依赖/SHA 校验（fail-closed）
    agreement_report     → Cohen's κ + 原始一致率 + UNCERTAIN 比例
    disagreement_list    → **JSON 对象**（doc.items），含双方标签+证据+dependency
    adjudicate           → 第三人只处理分歧（JSON 对象，同一格式）
    compile_frozen       → 状态机：一致确定→冻结；分歧→须仲裁；UNCERTAIN→复审/排除

UNCERTAIN 生命周期（P0-3，预注册）：
    双方一致确定标签        → admissable
    双方分歧                → 第三人仲裁（须填 final）
    任一方 UNCERTAIN        → 进入 uncertainty_review
    复审仍无法确定          → 样本**排除**出确认性分析并记录原因
    只要仍存在未处置 UNCERTAIN → registry 状态 = **INCOMPLETE_UNCERTAINTY**（不得称 FROZEN_LABELED）
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

ROLE_DIRECT = "DIRECT_SECURITY"
ROLE_SUPPORTING = "SUPPORTING_REQUIRED"
ROLE_NONCRIT = "NON_CRITICAL"
ROLE_UNCERTAIN = "UNCERTAIN"
VALID_ROLES = {ROLE_DIRECT, ROLE_SUPPORTING, ROLE_NONCRIT, ROLE_UNCERTAIN}
VALID_EVIDENCE = {"PoC", "regression-test", "code-reasoning", "insufficient"}
SAFE_ROLES = {ROLE_DIRECT, ROLE_SUPPORTING}   # 映射为 SECURITY_CRITICAL


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _key(ident: dict) -> str:
    return (f"{ident.get('sample_id')}|{ident['file']}|{ident['file_status']}|"
            f"{ident['old_start']}|{ident['old_count']}|{ident['new_start']}|"
            f"{ident['new_count']}|{ident['body_lf_sha256']}")


def _load_rows(p: Path) -> list:
    """加载提交：优先按整体 JSON 对象解析（doc.entries/items），失败再按 JSONL 逐行。"""
    txt = p.read_text(encoding="utf-8")
    try:
        doc = json.loads(txt)
        if isinstance(doc, list):
            return doc
        if isinstance(doc, dict):
            for k in ("entries", "items"):
                if isinstance(doc.get(k), list):
                    return doc[k]
            return [doc]
    except json.JSONDecodeError:
        pass
    return [json.loads(l) for l in txt.splitlines() if l.strip()]


def _template_index(template_path: Path) -> dict:
    tpl = json.loads(template_path.read_text(encoding="utf-8"))
    return {_key(e["hunk_identity"]): e for e in tpl["entries"]}


def validate_submission(path: Path, template_path: Path) -> dict:
    """校验一份提交（fail-closed）：identity 集合精确一致、字段合法、**依赖引用合法**。

    依赖校验（P0-2）：dependency_group 内每个 identity 必须存在、属于同一 CVE、不得自引用。
    """
    errs = []
    tpl = _template_index(template_path)
    want = set(tpl)
    rows = _load_rows(path)
    got, dup = set(), []
    by_key = {}
    for r in rows:
        k = _key(r["hunk_identity"])
        if k in got:
            dup.append(k)
        got.add(k)
        by_key[k] = r
        if r.get("criticality") not in VALID_ROLES:
            errs.append(f"{r.get('sample_id')}: 非法 criticality={r.get('criticality')}")
        ev = r.get("evidence")
        if ev is not None and ev not in VALID_EVIDENCE:
            errs.append(f"{r.get('sample_id')}: 非法 evidence={ev}")
        if not r.get("reason"):
            errs.append(f"{r.get('sample_id')}: reason 为空")
        if r.get("criticality") == ROLE_UNCERTAIN and ev not in ("insufficient", None):
            errs.append(f"{r.get('sample_id')}: UNCERTAIN 但 evidence={ev}（应为 insufficient）")
    if dup:
        errs.append(f"重复 identity {len(dup)} 条")
    if got != want:
        errs.append(f"identity 集合不符: 缺 {len(want - got)}，多 {len(got - want)}")
    # 依赖引用校验
    for k, r in by_key.items():
        deps = r.get("dependency_group") or []
        if not isinstance(deps, list):
            errs.append(f"{r.get('sample_id')}: dependency_group 非列表")
            continue
        self_id = r["hunk_identity"].get("body_lf_sha256")
        for d in deps:
            dk = [kk for kk in want if kk.split("|")[-1] == str(d)
                  or kk.split("|")[-1].startswith(str(d))]
            if not dk:
                errs.append(f"{r.get('sample_id')}: 依赖不存在 {str(d)[:12]}")
                continue
            if str(d) == self_id or _key(r["hunk_identity"]) in dk:
                errs.append(f"{r.get('sample_id')}: 依赖自引用")
            else:
                dep_cve = dk[0].split("|", 1)[0]
                if dep_cve != r["sample_id"]:
                    errs.append(f"{r.get('sample_id')}: 依赖跨 CVE（{dep_cve}）")
    return {"path": str(path), "n_rows": len(rows), "bytes": path.stat().st_size,
            "sha256": _sha(path.read_bytes()), "errors": errs, "ok": not errs}


def _require_valid(path: Path, template_path: Path) -> dict:
    v = validate_submission(path, template_path)
    if not v["ok"]:
        raise ValueError(f"提交校验失败 {path.name}: {v['errors'][:5]}")
    return v


def _index_checked(path: Path, template_path: Path, who: str) -> dict:
    """强制校验后返回 {key: row}；并核对 reviewer 字段身份。"""
    v = _require_valid(path, template_path)
    idx = {}
    for r in _load_rows(path):
        if r.get("reviewer") != who:
            raise ValueError(f"{path.name}: reviewer={r.get('reviewer')} != {who}")
        idx[_key(r["hunk_identity"])] = r
    return idx


def _cohen_kappa(a: list, b: list, labels: list) -> float:
    n = len(a)
    if n == 0:
        return 0.0
    po = sum(1 for x, y in zip(a, b) if x == y) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum((ca.get(l, 0) / n) * (cb.get(l, 0) / n) for l in labels)
    return 0.0 if pe == 1 else (po - pe) / (1 - pe)


def agreement_report(sub1: Path, sub2: Path, template_path: Path) -> dict:
    """Cohen's κ + 原始一致率 + UNCERTAIN 比例。**先强制校验两份提交**。"""
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    keys = sorted(set(r1) & set(r2))
    a = [r1[k]["criticality"] for k in keys]
    b = [r2[k]["criticality"] for k in keys]
    labels = sorted(VALID_ROLES)
    raw = sum(1 for x, y in zip(a, b) if x == y) / len(keys) if keys else 0.0
    return {"n_common": len(keys), "n_template": len(_template_index(template_path)),
            "raw_agreement": round(raw, 4),
            "cohen_kappa": round(_cohen_kappa(a, b, labels), 4),
            "uncertain_ratio_r1": round(sum(1 for x in a if x == ROLE_UNCERTAIN) / len(a), 4) if a else None,
            "uncertain_ratio_r2": round(sum(1 for x in b if x == ROLE_UNCERTAIN) / len(b), 4) if b else None,
            "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                  "reviewer2": _sha(sub2.read_bytes())}}


def disagreement_list(sub1: Path, sub2: Path, template_path: Path, out: Path) -> dict:
    """分歧清单（**JSON 对象**，与 adjudicate/compile_frozen 同格式）。

    保留 dependency_group / counterfactual / evidence（P0-2），供后续 minimal-real
    按依赖闭包构造。
    """
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    items = []
    for k in sorted(set(r1) & set(r2)):
        c1, c2 = r1[k]["criticality"], r2[k]["criticality"]
        if c1 == c2 and c1 != ROLE_UNCERTAIN:
            continue    # 一致且确定 → 无需处理
        if c1 == c2 == ROLE_UNCERTAIN:
            kind = "UNANIMOUS_UNCERTAIN"
        elif ROLE_UNCERTAIN in (c1, c2):
            kind = "PARTIAL_UNCERTAIN"
        else:
            kind = "DISAGREEMENT"
        items.append({
            "kind": kind,
            "sample_id": r1[k]["sample_id"],
            "hunk_identity": r1[k]["hunk_identity"],
            "reviewer1": {"criticality": c1, "evidence": r1[k].get("evidence"),
                          "dependency_group": r1[k].get("dependency_group") or [],
                          "counterfactual": r1[k].get("counterfactual"),
                          "reason": r1[k].get("reason")},
            "reviewer2": {"criticality": c2, "evidence": r2[k].get("evidence"),
                          "dependency_group": r2[k].get("dependency_group") or [],
                          "counterfactual": r2[k].get("counterfactual"),
                          "reason": r2[k].get("reason")},
            "adjudication": None, "adjudicator": None, "final": None,
        })
    doc = {"schema": "v4-adjudication/1",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes())},
           "n_items": len(items),
           "note": ("第三人只处理本清单；UNCERTAIN 须显式复审为确定标签或排除样本，"
                    "不得机械转成确定标签"),
           "items": items}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


def adjudicate(disagreements: Path, out: Path, template_path: Path,
               sub1: Path, sub2: Path) -> dict:
    """在分歧清单上写入仲裁（同格式 JSON 对象；校验 template/submission SHA 一致）。"""
    doc = json.loads(disagreements.read_text(encoding="utf-8"))
    if doc.get("template_sha256") != _sha(template_path.read_bytes()):
        raise ValueError("分歧清单的 template_sha256 与当前 template 不符")
    if doc.get("submission_sha256") != {"reviewer1": _sha(sub1.read_bytes()),
                                        "reviewer2": _sha(sub2.read_bytes())}:
        raise ValueError("分歧清单的 submission SHA 与当前提交不符")
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc


def compile_frozen(template_path: Path, sub1: Path, sub2: Path, adjudicated: Path,
                   out: Path) -> dict:
    """编译 frozen registry（**状态机**，含 UNCERTAIN 复审/排除）。

    - 一致且确定 → 直接采用；
    - 分歧 → 必须已仲裁（final 合法且有 adjudicator）；
    - 任一方 UNCERTAIN 或仲裁后仍 UNCERTAIN → 进入 uncertainty_review；
      若在 `exclusions` 中给出排除理由 → 记入 excluded_samples，不阻塞冻结；
    - 仍存在未处置 UNCERTAIN → **抛异常**（状态不得称为 FROZEN_LABELED）。

    保留 dependency graph / counterfactual / evidence / 角色原值（P0-2）。
    """
    tpl = _template_index(template_path)
    r1 = _index_checked(sub1, template_path, "reviewer1")
    r2 = _index_checked(sub2, template_path, "reviewer2")
    adj_doc = json.loads(adjudicated.read_text(encoding="utf-8"))
    if adj_doc.get("template_sha256") != _sha(template_path.read_bytes()):
        raise ValueError("仲裁件的 template_sha256 不符")
    adj = {_key(it["hunk_identity"]): it for it in adj_doc.get("items", [])}
    exclusions = adj_doc.get("exclusions") or {}   # {sample_id: reason}

    entries, pending_uncertain, excluded = [], [], []
    for k, t in tpl.items():
        c1, c2 = r1[k]["criticality"], r2[k]["criticality"]
        role, src = None, None
        if c1 == c2 and c1 != ROLE_UNCERTAIN:
            role, src = c1, "unanimous"
        elif ROLE_UNCERTAIN not in (c1, c2) and c1 != c2:
            a = adj.get(k)
            if not a or a.get("final") not in VALID_ROLES or not a.get("adjudicator"):
                raise ValueError(f"分歧未裁决: {t['sample_id']}")
            role, src = a["final"], "adjudicated"
        else:
            a = adj.get(k) or {}
            if a.get("final") in VALID_ROLES and a.get("adjudicator") \
                    and a["final"] != ROLE_UNCERTAIN:
                role, src = a["final"], "adjudicated_uncertain"
            else:
                sid = t["sample_id"]
                if sid in exclusions:
                    excluded.append({"sample_id": sid, "reason": exclusions[sid],
                                     "hunk_identity": t["hunk_identity"]})
                    continue
                pending_uncertain.append(sid)
                continue
        r = r1[k] if r1[k]["criticality"] == role else r2[k]
        entries.append({
            "sample_id": t["sample_id"], "hunk_identity": t["hunk_identity"],
            "role": role,                                   # 角色原值（P0-2）
            "criticality": ("SECURITY_CRITICAL" if role in SAFE_ROLES
                            else "NON_CRITICAL" if role == ROLE_NONCRIT else role),
            "source": src,
            "dependency_group": (r.get("dependency_group") or r2[k].get("dependency_group") or []),
            "counterfactual": r.get("counterfactual") or r2[k].get("counterfactual"),
            "evidence": r.get("evidence") or r2[k].get("evidence"),
            "reason": r.get("reason"),
        })
    if pending_uncertain:
        raise ValueError(f"存在未处置 UNCERTAIN（须复审为确定标签或列入 exclusions）: "
                         f"{sorted(set(pending_uncertain))[:5]}")
    doc = {"schema": "v4-critical-hunks-frozen/2",
           "status": "FROZEN_LABELED" if not excluded else "FROZEN_WITH_EXCLUSIONS",
           "template_sha256": _sha(template_path.read_bytes()),
           "submission_sha256": {"reviewer1": _sha(sub1.read_bytes()),
                                 "reviewer2": _sha(sub2.read_bytes())},
           "adjudication_sha256": _sha(adjudicated.read_bytes()),
           "n_entries": len(entries),
           "n_excluded": len(excluded),
           "excluded_samples": excluded,
           "role_counts": {r: sum(1 for e in entries if e["role"] == r)
                           for r in sorted(VALID_ROLES)},
           "entries": entries}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes((json.dumps(doc, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    return doc
