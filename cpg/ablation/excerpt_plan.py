# -*- coding: utf-8 -*-
"""配对摘录计划（Code plan 第4阶段）——先建结构化计划，再渲染文本。

⚠️ **表示版本与适用范围（2026-09-09 裁决：选 C）**

```text
representation   = changed-hunk-r0
role             = coverage-audit / future V4
not_allowed_for  = RQ1-R
```

依据 Experiment design §二.2：RQ1-R 必须使用 `legacy-rq1-r0`（历史兼容摘录器），
"改进后的摘录器必须另立版本，不能混进本轮"。因此本模块**不得进入 RQ1-R 调用图**，
仅用于覆盖审计（输出 sample→path→hunk_idx→side→FULL/PARTIAL/ABSENT）与未来 V4 实验。

已知未解决（不得写成"已解决"）：hunk 级最小窗口仍装不下 687 个（显式报告于
`skipped_hunks`），56/82 样本存在跳过；73498 ssrf_adapter.py、45019 mcp.py 等
核心安全文件在预算阶段被跳过。这些在本轮只报告、不现场修正。

核心不变量：
- 文件顺序依据**完整相对路径**（不依据各侧文件大小），vuln/fixed 两侧一致；
- 同一逻辑文件在两侧使用配对窗口；
- added/deleted 显式记录 side absence；
- 只在完整行边界截取，绝不截半行；
- 文件标记使用完整相对路径；
- 达预算时缩小窗口或舍弃完整低优先块，绝不截半行；
- 对所有上游 changed hunk 输出 FULL/PARTIAL/ABSENT；
- 相同输入跨进程 SHA 一致（不依赖 dict 迭代序、PYTHONHASHSEED）。
"""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

REPRESENTATION = "changed-hunk-r0"
ROLE = "coverage-audit / future V4"
NOT_ALLOWED_FOR = "RQ1-R"

# changed-hunk 覆盖三态
FULL = "FULL"
PARTIAL = "PARTIAL"
ABSENT = "ABSENT"


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


@dataclass
class BlockPlan:
    path: str            # 完整相对路径（含目录）
    side: str            # vuln / fixed
    lo: int              # 1-based 起始行
    hi: int              # 1-based 结束行（含）
    reason: str          # 选择原因
    content: str         # 块内容（完整行）
    content_sha: str
    token_estimate: int
    hunk_idx: int = -1   # 所属 hunk 序号（-1 = 非 hunk 块，如 head_window）


@dataclass
class PairSelectionPlan:
    sample_id: str
    blocks: list[BlockPlan] = field(default_factory=list)
    hunk_coverage: dict = field(default_factory=dict)  # path -> FULL/PARTIAL/ABSENT
    changed_hunks: dict = field(default_factory=dict)  # path -> [hunk dict, ...]
    max_chars: int = 8000
    # hunk 级：最小窗口（2 行）仍装不下的 (path, hunk_idx)，显式上报不静默丢弃
    skipped_hunks: list = field(default_factory=list)
    # 样本级：任一侧渲染为空 → UNREPRESENTABLE_BUDGET，须 exclude 且不产生空 prompt
    unrepresentable: list = field(default_factory=list)

    def plan_sha(self) -> str:
        keys = sorted(
            f"{b.path}|{b.side}|{b.lo}|{b.hi}|{b.content_sha}" for b in self.blocks
        )
        return _sha256_bytes("\n".join(keys).encode("utf-8"))


def get_changed_hunks(repo_dir: Path, parent: str, fix: str, path: str) -> dict:
    """git diff -U0 获取逐 hunk 配对坐标（fallback 用，fail-closed）。

    返回 {"hunks": [{"old_start","old_count","new_start","new_count"}, ...]}，保留 count=0。
    """
    r = subprocess.run(
        ["git", "diff", "-U0", parent, fix, "--", path],
        cwd=str(repo_dir), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if r.returncode != 0:
        raise RuntimeError(f"git diff 失败 rc={r.returncode}: {r.stderr[:200]}")
    hunks = []
    for line in r.stdout.splitlines():
        if not line.startswith("@@"):
            continue
        try:
            hdr = line.split("@@")[1].strip()
            old_part, new_part = hdr.split()[:2]
            old_lo, old_cnt = _parse_range(old_part)
            new_lo, new_cnt = _parse_range(new_part)
        except (ValueError, IndexError) as e:
            raise RuntimeError(f"hunk header 解析失败：{line!r}") from e
        hunks.append({"old_start": old_lo, "old_count": old_cnt,
                      "new_start": new_lo, "new_count": new_cnt})
    return {"hunks": hunks}


def _parse_range(s: str):
    s = s[1:] if s and s[0] in "-+" else s
    if "," in s:
        lo, cnt = s.split(",")
        return int(lo), int(cnt)
    return int(s), 1


def _read_source_lines(source_dir: Path, version: str, path: str,
                       expect_exists: bool = False) -> list[str]:
    """从 corpus-v3 源目录读文件内容（干净克隆无 corpus_raw 也可复现）。

    expect_exists=True 时文件缺失即抛错，禁止把"语料文件异常"伪装成"空窗口"
    （本项目曾发生 fixed 文件静默缺失，必须 fail-closed）。
    """
    p = source_dir / version / path
    if not p.exists():
        if expect_exists:
            raise RuntimeError(
                f"语料文件缺失（fail-closed）: {p} (side={version})")
        return []
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def _read_lines(source_dir, repo_dir, version, commit, path,
                expect_exists: bool = False) -> list[str]:
    """优先从 source_dir（corpus-v3）读，fallback 到 git show（repo_dir）。"""
    if source_dir is not None:
        return _read_source_lines(source_dir, version, path, expect_exists)
    r = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=str(repo_dir),
                       capture_output=True)
    if r.returncode != 0:
        if expect_exists:
            raise RuntimeError(
                f"git show 失败（fail-closed）: {commit}:{path} "
                f"stderr={r.stderr[:200]!r}")
        return []
    return r.stdout.decode("utf-8", errors="replace").splitlines()


def _is_complete_line(content: str) -> bool:
    return content == "" or content.endswith("\n")


def build_pair_selection_plan(
    sample_spec,
    pair_manifest: dict,
    repo_dir: Path,
    source_dir: Path | None = None,
    max_chars: int = 8000,
    head_lines: int = 100,
    hunk_window: int = 20,
) -> PairSelectionPlan:
    """生成 vuln/fixed 共享的摘录计划。

    - 文件顺序按完整相对路径排序；
    - 优先 changed-hunk 中心窗口（FULL 覆盖），剩余预算给文件头部（head_lines）；
    - 只在完整行边界截取；达预算时缩小窗口/舍弃低优先块，绝不截半行；
    - source_dir 提供时从 corpus-v3 读文件内容（干净克隆无 corpus_raw 也可复现），
      否则 fallback 到 git show（repo_dir）。
    """
    plan = PairSelectionPlan(sample_id=sample_spec.sample_id, max_chars=max_chars)
    parent = pair_manifest["parent_commit"]
    fix = pair_manifest["fix_commit"]

    # 收集所有 .py 改动文件（按完整相对路径排序）
    files = sorted(pair_manifest.get("files", []), key=lambda f: f["path"])

    # 1) 计算每个文件的 changed hunks（逐 hunk 配对坐标，保留 count=0）：
    #    优先读 pair_manifest 缓存；source_dir 模式下缺失即报错，禁止 fallback corpus_raw
    changed_hunks = {}
    for f in files:
        if "changed_hunks" in f:
            changed_hunks[f["path"]] = list(f["changed_hunks"].get("hunks", []))
        elif source_dir is not None:
            raise ValueError(
                f"{f['path']} 缺 changed_hunks（source_dir 模式禁止 fallback corpus_raw）")
        else:
            changed_hunks[f["path"]] = get_changed_hunks(
                repo_dir, parent, fix, f["path"])["hunks"]

    # 2) 按 hunk 生成候选块：每条 hunk 一个 paired unit（同 hunk 的 vuln 块 + fixed 块），
    #    零长度一侧（count=0）用 start±window 边界上下文，不复制另一侧绝对行号。
    blocks: list[BlockPlan] = []
    for f in files:
        path = f["path"]
        status = f.get("status")
        hunk_list = changed_hunks[path]

        # hunk_window=None 表示禁用 hunk 窗口（退化为头 100 行旧策略）。
        if hunk_window is not None and status in ("M", "T") and hunk_list:
            for idx, h in enumerate(hunk_list):
                for side, commit in (("vuln", parent), ("fixed", fix)):
                    start, cnt = ((h["old_start"], h["old_count"]) if side == "vuln"
                                  else (h["new_start"], h["new_count"]))
                    w_lo = max(1, start - hunk_window)
                    # 零长度一侧：边界上下文 start±window；非空：覆盖 [start, start+cnt-1]
                    w_hi = (start + hunk_window) if cnt == 0 else (start + cnt - 1 + hunk_window)
                    lines = _read_lines(source_dir, repo_dir, side, commit, path,
                                       expect_exists=True)
                    lo_c = max(1, w_lo)
                    hi_c = min(len(lines), w_hi)
                    content = "\n".join(lines[lo_c - 1:hi_c]) + ("\n" if lines else "")
                    blocks.append(BlockPlan(
                        path=path, side=side, lo=lo_c, hi=hi_c,
                        reason=f"changed_hunk_window:h{idx}:{w_lo}-{w_hi}",
                        content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                        token_estimate=len(content) // 4, hunk_idx=idx,
                    ))
            continue

        # 头部窗口（无 changed hunk 的 modified，或 added/deleted 的现有侧）
        if status in ("M", "T"):
            for side, commit in (("vuln", parent), ("fixed", fix)):
                lines = _read_lines(source_dir, repo_dir, side, commit, path,
                                    expect_exists=True)
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=path, side=side, lo=1, hi=hi_c, reason="head_window",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))
        elif status == "A":
            lines = _read_lines(source_dir, repo_dir, "fixed", fix, path,
                                expect_exists=True)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason="added_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        elif status == "D":
            lines = _read_lines(source_dir, repo_dir, "vuln", parent, path,
                                expect_exists=True)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="vuln", lo=1, hi=hi_c, reason="deleted_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        # R/C：renamed/copied 也按现有侧取头部（简化，pair_manifest 已有 prev）
        elif status in ("R", "C"):
            lines = _read_lines(source_dir, repo_dir, "fixed", fix, path,
                                expect_exists=True)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason=f"{status}_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
            if f.get("prev"):
                lines = _read_lines(source_dir, repo_dir, "vuln", parent, f["prev"],
                                    expect_exists=True)
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=f["prev"], side="vuln", lo=1, hi=hi_c, reason=f"{status}_prev_head",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))

    # 3) 预算分配：按 hunk unit（path, hunk_idx）成对分配（每侧独立 max_chars 预算）；
    #    超预算时按同一 hunk 单元逐级对称缩小窗口（hunk_window → 10 → 5 → 2），
    #    **绝不静默丢弃整个文件**（那会造成双侧空输入、路径对称但无信息）；
    #    最小窗口仍装不下 → 记入 unrepresentable（UNREPRESENTABLE_BUDGET，须显式上报）。
    def marker_len(b: BlockPlan) -> int:
        return len(f"# ===== FILE: {b.path} (L{b.lo}-L{b.hi}) =====\n")

    def block_priority(b: BlockPlan) -> tuple:
        return (0 if b.hunk_idx >= 0 else 1, b.path, b.hunk_idx, b.side)

    def make_block(path_, side, h, w, commit, hidx):
        start, cnt = ((h["old_start"], h["old_count"]) if side == "vuln"
                      else (h["new_start"], h["new_count"]))
        w_lo = max(1, start - w)
        w_hi = (start + w) if cnt == 0 else (start + cnt - 1 + w)
        lines = _read_lines(source_dir, repo_dir, side, commit, path_,
                            expect_exists=True)
        lo_c = max(1, w_lo)
        hi_c = min(len(lines), w_hi)
        content = "\n".join(lines[lo_c - 1:hi_c]) + ("\n" if lines else "")
        return BlockPlan(path=path_, side=side, lo=lo_c, hi=hi_c,
                         reason=f"changed_hunk_window:h{hidx}:{w_lo}-{w_hi}",
                         content=content,
                         content_sha=_sha256_bytes(content.encode("utf-8")),
                         token_estimate=len(content) // 4, hunk_idx=hidx)

    # hunk 信息映射（缩小窗口时重建块用）
    hunk_map: dict = {}
    for f in files:
        for idx, h in enumerate(changed_hunks[f["path"]]):
            hunk_map[(f["path"], idx)] = h

    # 按 hunk unit 分组
    units: dict = {}
    for b in sorted(blocks, key=block_priority):
        units.setdefault((b.path, b.hunk_idx), {})[b.side] = b

    selected: list[BlockPlan] = []
    side_used = {"vuln": 0, "fixed": 0}
    unrepr: list = []
    shrink_steps = ([hunk_window] if hunk_window is not None else []) + [10, 5, 2]
    unit_items = sorted(units.items(),
                        key=lambda kv: block_priority(next(iter(kv[1].values()))))
    for (path, hidx), pd in unit_items:
        placed = False
        for w in shrink_steps:
            cand: dict = {}
            ok = True
            for side in ("vuln", "fixed"):
                b0 = pd.get(side)
                if b0 is None:
                    continue
                if hidx >= 0 and w == hunk_window:
                    cand[side] = b0  # 复用已生成的原窗口块
                elif hidx >= 0 and (path, hidx) in hunk_map:
                    commit = parent if side == "vuln" else fix
                    cand[side] = make_block(path, side, hunk_map[(path, hidx)], w,
                                            commit, hidx)
                else:
                    cand[side] = b0  # 非 hunk 块（head_window），不可缩小
                cost = len(cand[side].content) + marker_len(cand[side])
                if side_used[side] + cost > max_chars:
                    ok = False
                    break
            if ok:
                for side, b in cand.items():
                    selected.append(b)
                    side_used[side] += len(b.content) + marker_len(b)
                placed = True
                break
        if not placed:
            unrepr.append((path, hidx))

    plan.blocks = selected
    plan.skipped_hunks = unrepr
    # 样本级：任一侧渲染无内容才算 UNREPRESENTABLE_BUDGET（不得产生空 prompt）
    rv = render_side(plan, "vuln").strip()
    rf = render_side(plan, "fixed").strip()
    plan.unrepresentable = (sorted({p for p, _ in unrepr})
                            if (not rv or not rf) else [])
    plan.changed_hunks = changed_hunks
    plan.hunk_coverage = _compute_coverage(files, changed_hunks, selected)
    return plan


def _compute_coverage(files, changed_hunks, blocks) -> dict:
    """按 hunk × side 计算覆盖 → {path: {side: FULL/PARTIAL/ABSENT}}。

    逐 hunk 用该侧自身区间（old 给 vuln、new 给 fixed）；count=0 的一侧无区间，跳过。
    """
    coverage = {}
    for f in files:
        path = f["path"]
        hunk_list = changed_hunks.get(path, [])
        if not hunk_list:
            continue
        coverage[path] = {}
        for side in ("vuln", "fixed"):
            ranges = []
            for h in hunk_list:
                start, cnt = ((h["old_start"], h["old_count"]) if side == "vuln"
                              else (h["new_start"], h["new_count"]))
                if cnt == 0:
                    continue
                ranges.append((start, start + cnt - 1))
            if not ranges:
                continue  # 该侧无区间（纯插入/纯删除）
            side_blocks = [b for b in blocks if b.path == path and b.side == side]
            covered = 0
            for lo, hi in ranges:
                if any(b.lo <= lo and hi <= b.hi for b in side_blocks):
                    covered += 1
            if covered == len(ranges):
                coverage[path][side] = FULL
            elif covered > 0:
                coverage[path][side] = PARTIAL
            else:
                coverage[path][side] = ABSENT
    return coverage


def render_side(plan: PairSelectionPlan, side: str) -> str:
    """渲染单侧代码文本，块间用完整相对路径 FILE marker 分隔。"""
    side_blocks = [b for b in plan.blocks if b.side == side]
    # 按完整相对路径排序
    side_blocks = sorted(side_blocks, key=lambda b: b.path)
    parts = []
    for b in side_blocks:
        parts.append(f"# ===== FILE: {b.path} (L{b.lo}-L{b.hi}) =====\n")
        parts.append(b.content)
    return "".join(parts)
