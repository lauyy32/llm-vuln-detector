"""CodeQL 官方基线适配器（SPEC §6 / ARCHITECTURE §3）。

``run_codeql_baseline(db_path, sample_file, cwe) -> Verdict``：

1. 对给定 DB 跑官方 ``python-code-scanning`` 套件（``database analyze``，SARIF 输出）。
2. 解析 SARIF：用 ``run.tool.driver.rules[].properties.tags`` 建 ``ruleId -> CWE`` 映射
   （标签形如 ``cwe/CWE-918``）。
3. 每条 result，若其 rule 的 CWE 标签包含目标 CWE，且其物理位置 uri 命中 ``sample_file``
   的 basename → 判 vulnerable。

与自定义 taint 查询（供 StructuralHeuristic）分流、互不覆盖。复用 pipeline 的 run / make_env /
_is_defender_block / resolve_suite，不重写 CodeQL 调用。
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import config
from .scorers import Verdict

# analyze 墙钟上限（官方套件比单条 taint 查询重）
BASELINE_TIMEOUT = 600


def _sarif_path(db_path: Path, sample_file: Path) -> Path:
    out_dir = config.WORK_DIR / "baseline"
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{db_path.stem}__{sample_file.stem}.sarif"


def _build_rule_tags(run: dict) -> dict[str, set[str]]:
    """ruleId -> set(tags) ，兼容 driver.rules 与 extensions[*].rules。"""
    tags: dict[str, set[str]] = {}

    def _collect(rules: list[dict]) -> None:
        for r in rules:
            rid = r.get("id")
            if rid is None:
                continue
            props = r.get("properties", {}) or {}
            t = set(props.get("tags", []) or [])
            tags.setdefault(rid, set()).update(t)

    driver = run.get("tool", {}).get("driver", {})
    _collect(driver.get("rules", []) or [])
    for ext in run.get("tool", {}).get("extensions", []) or []:
        _collect(ext.get("rules", []) or [])
    return tags


_CWE_RE = re.compile(r"cwe[-_ ]?(\d+)", re.IGNORECASE)


def _cwe_number(value: str | None) -> str | None:
    """从任意 CWE 形态（'CWE-022' / 'cwe-918' / 'external/cwe/cwe-022'）提取纯数字。

    大小写、'external/' 前缀、分隔符（'-' '_' ' '）一律无关，只比对数字。
    """
    if not value:
        return None
    m = _CWE_RE.search(value)
    return m.group(1) if m else None


def _result_cwe_match(res: dict, rule_tags: dict[str, set[str]], target_cwe: str) -> bool:
    """目标 CWE 与 result 所属 rule 的任一 CWE 标签编号相等即算命中。"""
    tnum = _cwe_number(target_cwe)
    if tnum is None:
        return False
    rid = res.get("ruleId")
    for tag in rule_tags.get(rid, set()):
        if _cwe_number(tag) == tnum:
            return True
    return False


def _result_hits_file(res: dict, sample_basename: str) -> bool:
    for loc in res.get("locations", []) or []:
        uri = (
            loc.get("physicalLocation", {})
            .get("artifactLocation", {})
            .get("uri")
        )
        if uri and Path(uri).name == sample_basename:
            return True
    return False


def run_codeql_baseline(
    db_path: str | Path,
    sample_file: str | Path,
    cwe: str | None,
) -> Verdict:
    """对 db_path 跑官方 python-code-scanning 套件，按目标 CWE 命中 sample_file 判 vulnerable。"""
    db_path = Path(db_path)
    sample_file = Path(sample_file)
    target = config.normalize_cwe(cwe)

    if not db_path.exists():
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": "database not found", "db": str(db_path)}],
        )

    sarif = _sarif_path(db_path, sample_file)
    exe = config.codeql_binary()
    env = config.make_env(config.DEFAULT_JAVA_HOME)
    suite = config.resolve_suite()
    rc = config.run(
        [
            str(exe),
            "database",
            "analyze",
            config.win_path(db_path),
            suite,
            "--format=sarif-latest",
            f"--output={config.win_path(sarif)}",
            "--ram=3000",
            "--threads=8",
        ],
        env,
        BASELINE_TIMEOUT,
    )
    if rc != 0:
        reason = "baseline analyze failed"
        if rc == 124:
            reason = "baseline analyze watchdog timeout (possible Defender lock on DB cache)"
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": reason, "rc": rc, "sarif": str(sarif)}],
        )

    try:
        data = json.loads(sarif.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": f"SARIF unreadable: {exc}", "sarif": str(sarif)}],
        )

    rule_tags: dict[str, set[str]] = {}
    for run in data.get("runs", []) or []:
        rule_tags.update(_build_rule_tags(run))

    if target is None:
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": "no target CWE supplied to baseline"}],
        )

    evidence: list[dict] = []
    matched_rules: set[str] = set()
    for run in data.get("runs", []) or []:
        for res in run.get("results", []) or []:
            if not _result_cwe_match(res, rule_tags, target):
                continue
            if not _result_hits_file(res, sample_file.name):
                continue
            rid = res.get("ruleId")
            matched_rules.add(rid)
            sev = (res.get("properties", {}) or {}).get("security-severity")
            evidence.append(
                {
                    "type": "codeql-baseline",
                    "cwe": target,
                    "ruleId": rid,
                    "uri": (
                        (res.get("locations", []) or [{}])[0]
                        .get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri")
                    ),
                }
            )
            # 仅取 security-severity 作 confidence 参考（若有）
            if sev is not None:
                try:
                    evidence[-1]["security-severity"] = float(sev)
                except (TypeError, ValueError):
                    pass

    if evidence:
        # 取命中点 security-severity 均值作 confidence（无则 1.0）
        sevs = [e["security-severity"] for e in evidence if isinstance(e.get("security-severity"), float)]
        confidence = round(sum(sevs) / len(sevs), 4) if sevs else 1.0
        return Verdict(label="vulnerable", confidence=confidence, cwe=target, evidence=evidence)

    return Verdict(
        label="benign", confidence=1.0, cwe=target,
        evidence=[{"reason": f"official python-code-scanning did not flag {target} in {sample_file.name}"}],
    )


def run_codeql_baseline_corpus(
    sarif_path: str | Path,
    sample_prefix: str,
    cwe: str | None,
) -> Verdict:
    """语料库级单数据库场景：从已跑好的 corpus SARIF 中，按 ``sample_prefix``
    （如 ``CVE-2026-50558_vuln``）过滤匹配目标 CWE 的结果，判 vulnerable。

    单数据库下多个样本的 SARIF 结果共存，必须按样本路径前缀隔离，否则同名文件
    （``__init__.py`` / ``conf.py`` / ``test_*.py``）会跨样本串味。artifactLocation
    的 uri 相对 source-root，形如 ``<cve>_<version>/<relpath>``，故以前缀 + '/' 匹配。
    """
    sarif_path = Path(sarif_path)
    target = config.normalize_cwe(cwe)
    if not sarif_path.exists():
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": "corpus SARIF not found", "sarif": str(sarif_path)}],
        )
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": f"SARIF unreadable: {exc}", "sarif": str(sarif_path)}],
        )

    rule_tags: dict[str, set[str]] = {}
    for run in data.get("runs", []) or []:
        rule_tags.update(_build_rule_tags(run))

    if target is None:
        return Verdict(
            label="abstain", confidence=0.0, cwe=target,
            evidence=[{"reason": "no target CWE supplied to corpus baseline"}],
        )

    prefix_norm = sample_prefix.replace("\\", "/")
    evidence: list[dict] = []
    for run in data.get("runs", []) or []:
        for res in run.get("results", []) or []:
            if not _result_cwe_match(res, rule_tags, target):
                continue
            hit = False
            for loc in res.get("locations", []) or []:
                uri = (
                    loc.get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri")
                )
                if uri and uri.replace("\\", "/").startswith(prefix_norm + "/"):
                    hit = True
                    break
            if not hit:
                continue
            rid = res.get("ruleId")
            evidence.append(
                {
                    "type": "codeql-baseline",
                    "cwe": target,
                    "ruleId": rid,
                    "uri": (
                        (res.get("locations", []) or [{}])[0]
                        .get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri")
                    ),
                }
            )

    if evidence:
        return Verdict(label="vulnerable", confidence=1.0, cwe=target, evidence=evidence)

    return Verdict(
        label="benign", confidence=1.0, cwe=target,
        evidence=[{"reason": f"official suite did not flag {target} under {sample_prefix}"}],
    )
