# -*- coding: utf-8 -*-
"""V4 manifest 单一来源（P0-2 修复：消除 split-brain）。

V4 的三个模块（v4_gate_a / v4_patch_gen / upstream_manifest）**不得各自维护**
manifest 默认常量——否则会出现"Gate 读 v2、patch 构造读旧 manifest"的 provenance
分裂。统一从本模块取路径与 SHA。

旧 `canonical_corpus_manifest.json` 被 RQ1-R 的 lock_request 逐字节绑定，
只能作为历史输入（LEGACY），V4 一律消费 v2。
"""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# V4 权威输入（版本化；见 canonical_manifest_v2.py）
V4_CANONICAL_MANIFEST = ROOT / "cpg" / "ablation" / "artifacts" / "canonical_corpus_manifest.v2.json"
# RQ1-R 历史输入（冻结；被 lock_request 绑定，严禁修改）
LEGACY_CANONICAL_MANIFEST = ROOT / "cpg" / "ablation" / "artifacts" / "canonical_corpus_manifest.json"


def manifest_path() -> Path:
    """V4 使用的 canonical manifest 路径（唯一权威）。"""
    return V4_CANONICAL_MANIFEST


def manifest_sha256() -> str:
    """V4 canonical manifest 当前 SHA-256（供派生工件记录）。"""
    return hashlib.sha256(V4_CANONICAL_MANIFEST.read_bytes()).hexdigest()


def require_manifest(path: Path | None) -> Path:
    """P0-2：显式传入校验——缺参数或文件不存在即拒绝。"""
    if path is None:
        raise ValueError("必须显式传入 --canonical-manifest（V4 禁止隐式默认）")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"canonical manifest 不存在: {p}")
    return p
