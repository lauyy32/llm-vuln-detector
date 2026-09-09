# -*- coding: utf-8 -*-
"""配对摘录计划（Code plan 第4阶段）——先建结构化计划，再渲染文本。

替代 run_ablation._load_sample_code 的"按文件大小排序 + 头 100 行 + text[:remain] 截半行"。

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


@dataclass
class PairSelectionPlan:
    sample_id: str
    blocks: list[BlockPlan] = field(default_factory=list)
    hunk_coverage: dict = field(default_factory=dict)  # path -> FULL/PARTIAL/ABSENT
    changed_hunks: dict = field(default_factory=dict)  # path -> [(lo,hi), ...]
    max_chars: int = 8000

    def plan_sha(self) -> str:
        keys = sorted(
            f"{b.path}|{b.side}|{b.lo}|{b.hi}|{b.content_sha}" for b in self.blocks
        )
        return _sha256_bytes("\n".join(keys).encode("utf-8"))


def get_changed_hunks(repo_dir: Path, parent: str, fix: str, path: str) -> dict:
    """git diff -U0 获取 old/new 两侧行区间（fallback 用，返回 {"old_ranges","new_ranges"}）。"""
    r = subprocess.run(
        ["git", "diff", "-U0", parent, fix, "--", path],
        cwd=str(repo_dir), capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if r.returncode != 0:
        return {"old_ranges": [], "new_ranges": []}
    old_ranges = []
    new_ranges = []
    for line in r.stdout.splitlines():
        if not line.startswith("@@"):
            continue
        try:
            hdr = line.split("@@")[1].strip()
            old_part, new_part = hdr.split()[:2]
            old_lo, old_cnt = _parse_range(old_part)
            new_lo, new_cnt = _parse_range(new_part)
            if old_cnt > 0:
                old_ranges.append([old_lo, old_lo + old_cnt - 1])
            if new_cnt > 0:
                new_ranges.append([new_lo, new_lo + new_cnt - 1])
        except (ValueError, IndexError):
            continue
    return {"old_ranges": old_ranges, "new_ranges": new_ranges}


def _parse_range(s: str):
    s = s[1:] if s and s[0] in "-+" else s
    if "," in s:
        lo, cnt = s.split(",")
        return int(lo), int(cnt)
    return int(s), 1


def _read_source_lines(source_dir: Path, version: str, path: str) -> list[str]:
    """从 corpus-v3 源目录读文件内容（干净克隆无 corpus_raw 也可复现）。"""
    p = source_dir / version / path
    if not p.exists():
        return []
    return p.read_text(encoding="utf-8", errors="replace").splitlines()


def _read_lines(source_dir, repo_dir, version, commit, path) -> list[str]:
    """优先从 source_dir（corpus-v3）读，fallback 到 git show（repo_dir）。"""
    if source_dir is not None:
        return _read_source_lines(source_dir, version, path)
    r = subprocess.run(["git", "show", f"{commit}:{path}"], cwd=str(repo_dir),
                       capture_output=True)
    if r.returncode != 0:
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

    # 1) 计算每个文件的 changed hunks（old/new 双坐标）：优先读 pair_manifest 缓存；
    #    source_dir 模式（干净克隆）下，缺 changed_hunks 即报错，禁止 fallback corpus_raw
    changed_hunks = {}
    for f in files:
        if "changed_hunks" in f:
            changed_hunks[f["path"]] = {
                "old_ranges": [tuple(h) for h in f["changed_hunks"].get("old_ranges", [])],
                "new_ranges": [tuple(h) for h in f["changed_hunks"].get("new_ranges", [])],
            }
        elif source_dir is not None:
            raise ValueError(
                f"{f['path']} 缺 changed_hunks（source_dir 模式禁止 fallback corpus_raw）")
        else:
            changed_hunks[f["path"]] = get_changed_hunks(repo_dir, parent, fix, f["path"])

    # 2) 为每个文件生成候选块：vuln 侧用 old_ranges、fixed 侧用 new_ranges（配对窗口，
    #    但坐标按侧对应）。
    blocks: list[BlockPlan] = []
    for f in files:
        path = f["path"]
        status = f.get("status")
        hunks = changed_hunks[path]

        # changed-hunk 中心窗口：每侧用各自坐标，每个 hunk 单独 ±window 只合并重叠。
        # hunk_window=None 表示禁用 hunk 窗口（退化为头 100 行旧策略）。
        has_any_hunk = bool(hunks.get("old_ranges") or hunks.get("new_ranges"))
        if hunk_window is not None and status in ("M", "T") and has_any_hunk:
            for side, commit in (("vuln", parent), ("fixed", fix)):
                key = "old_ranges" if side == "vuln" else "new_ranges"
                ranges = hunks.get(key, [])
                if not ranges:
                    # 纯插入/纯删除：该侧无对应坐标，用另一侧坐标作配对锚点
                    other = "new_ranges" if side == "vuln" else "old_ranges"
                    ranges = hunks.get(other, [])
                if not ranges:
                    continue
                windows = []
                for h_lo, h_hi in sorted(ranges):
                    w_lo = max(1, h_lo - hunk_window)
                    w_hi = h_hi + hunk_window
                    if windows and w_lo <= windows[-1][1] + 1:
                        windows[-1] = (windows[-1][0], max(windows[-1][1], w_hi))
                    else:
                        windows.append((w_lo, w_hi))
                lines = _read_lines(source_dir, repo_dir, side, commit, path)
                for w_lo, w_hi in windows:
                    lo_c = max(1, w_lo)
                    hi_c = min(len(lines), w_hi)
                    content = "\n".join(lines[lo_c - 1:hi_c]) + ("\n" if lines else "")
                    blocks.append(BlockPlan(
                        path=path, side=side, lo=lo_c, hi=hi_c,
                        reason=f"changed_hunk_window:{w_lo}-{w_hi}",
                        content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                        token_estimate=len(content) // 4,
                    ))
            continue

        # 头部窗口（无 changed hunk 的 modified，或 added/deleted 的现有侧）
        if status in ("M", "T"):
            for side, commit in (("vuln", parent), ("fixed", fix)):
                lines = _read_lines(source_dir, repo_dir, side, commit, path)
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=path, side=side, lo=1, hi=hi_c, reason="head_window",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))
        elif status == "A":
            lines = _read_lines(source_dir, repo_dir, "fixed", fix, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason="added_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        elif status == "D":
            lines = _read_lines(source_dir, repo_dir, "vuln", parent, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="vuln", lo=1, hi=hi_c, reason="deleted_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
        # R/C：renamed/copied 也按现有侧取头部（简化，pair_manifest 已有 prev）
        elif status in ("R", "C"):
            lines = _read_lines(source_dir, repo_dir, "fixed", fix, path)
            hi_c = min(len(lines), head_lines)
            content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
            blocks.append(BlockPlan(
                path=path, side="fixed", lo=1, hi=hi_c, reason=f"{status}_head",
                content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                token_estimate=len(content) // 4,
            ))
            if f.get("prev"):
                lines = _read_lines(source_dir, repo_dir, "vuln", parent, f["prev"])
                hi_c = min(len(lines), head_lines)
                content = "\n".join(lines[:hi_c]) + ("\n" if lines else "")
                blocks.append(BlockPlan(
                    path=f["prev"], side="vuln", lo=1, hi=hi_c, reason=f"{status}_prev_head",
                    content=content, content_sha=_sha256_bytes(content.encode("utf-8")),
                    token_estimate=len(content) // 4,
                ))

    # 3) 预算分配：每侧独立 max_chars 预算（vuln/fixed 各自 <= 8000，历史每份 prompt 独立），
    #    但文件/窗口保持配对（同一文件集、同一窗口策略、同一优先级遍历）。
    def marker_len(b: BlockPlan) -> int:
        return len(f"# ===== FILE: {b.path} (L{b.lo}-L{b.hi}) =====\n")

    def block_priority(b: BlockPlan) -> tuple:
        is_hunk = b.reason.startswith("changed_hunk_window")
        return (0 if is_hunk else 1, b.path, b.side)

    sorted_blocks = sorted(blocks, key=block_priority)

    # 按 path 分组（文件单元）：一个 path 的 vuln 块列表 + fixed 块列表。
    # 不能用 (path, reason) 分组，因为 reason 含窗口坐标，vuln/fixed 的 old/new 坐标不同
    # 会导致同一文件两侧被拆进不同 pair（文件集合不对称的根因）。
    by_path: dict = {}
    for b in sorted_blocks:
        by_path.setdefault(b.path, {"vuln": [], "fixed": []})[b.side].append(b)

    selected: list[BlockPlan] = []
    side_used = {"vuln": 0, "fixed": 0}
    path_items = sorted(
        by_path.items(),
        key=lambda kv: block_priority(next(iter(kv[1]["vuln"] + kv[1]["fixed"]))))
    for path, sd in path_items:
        # 文件单元共同入选：两侧都必须能完整容纳（各自独立预算），否则该文件两侧都不进。
        # 达预算时"舍弃完整低优先块"，绝不截半行（codex 语义）。
        costs = {side: sum(len(b.content) + marker_len(b) for b in sd[side])
                 for side in ("vuln", "fixed")}
        can_fit = all(
            (not sd[side]) or (side_used[side] + costs[side] <= max_chars)
            for side in ("vuln", "fixed")
        )
        if not can_fit:
            continue  # 该文件两侧都不进，保持集合一致
        for side, bs in sd.items():
            for b in bs:
                selected.append(b)
                side_used[side] += len(b.content) + marker_len(b)

    plan.blocks = selected
    plan.changed_hunks = changed_hunks
    plan.hunk_coverage = _compute_coverage(files, changed_hunks, selected)
    return plan


def _compute_coverage(files, changed_hunks, blocks) -> dict:
    """按侧计算每个文件的 hunk 覆盖 → {path: {side: FULL/PARTIAL/ABSENT}}。

    每侧独立判断（不再 any() 把任一侧覆盖算 FULL）。
    """
    coverage = {}
    for f in files:
        path = f["path"]
        hunks = changed_hunks.get(path, {})
        if not hunks:
            continue
        coverage[path] = {}
        for side in ("vuln", "fixed"):
            key = "old_ranges" if side == "vuln" else "new_ranges"
            ranges = hunks.get(key, [])
            if not ranges:
                continue  # 该侧无对应 hunk（纯插入/删除），不记 coverage
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
