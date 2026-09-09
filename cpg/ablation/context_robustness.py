# -*- coding: utf-8 -*-
"""上下文鲁棒性子实验（Code plan 第8阶段）。

操作结构化 PairSelectionPlan（禁止解析并拼接 Markdown prompt），四条件：
    C0 baseline（无新增块）
    C1 256-token license 注释块
    C2 256-token 非 license 中性注释块
    C3 256-token AST 可解析惰性 Python 块

约束：
- 变体从同一 base plan 生成，在完整块边界操作，重新经过预算分配器；
- 扰动块 token 数相等（±1）、行数/文件头/插入位置相同；
- 不含 CVE/CWE/vulnerable/fixed/security/fix 等词，不引用项目或样本标识；
- 样本与变体在看结果前冻结（本模块只负责生成，不调模型）；
- 单样本 61539 只能叫 pilot，不进入估计样本。
"""
from __future__ import annotations

import copy
from dataclasses import dataclass

from .excerpt_plan import BlockPlan, PairSelectionPlan, _sha256_bytes

# 扰动块 token 目标（256 token ≈ 1024 字符，三个模板等长 ±1）
PERTURB_TARGET_CHARS = 1024

# 三套预先冻结的扰动块（拉丁方/固定 seed 分配，避免单一模板特异性）
# 文件名统一用中性名，不含敏感词
LICENSE_TEMPLATE = (
    "# ===== FILE: third_party/notice.txt =====\n"
    + "# Licensed under the Apache License, Version 2.0.\n"
    + "# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0\n"
    + "#\n"
    + "# Unless required by applicable law or agreed to in writing, software\n"
    + "# distributed under the License is distributed on an AS IS BASIS,\n"
    + "# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n"
    + "# See the License for the specific language governing permissions and\n"
    + "# limitations under the License.\n"
    + ("# This notice is provided for attribution purposes only.\n" * 3)
)

NEUTRAL_TEMPLATE = (
    "# ===== FILE: third_party/notice.txt =====\n"
    + "# General implementation notes for reference.\n"
    + "#\n"
    + "# This module provides helper routines used across the codebase.\n"
    + "# The functions below are documented inline and should be read in order.\n"
    + "# No external service or network access is required for these helpers.\n"
    + ("# See the adjacent documentation for usage examples and return types.\n" * 4)
)

LAZY_CODE_TEMPLATE = (
    "# ===== FILE: third_party/helpers.py =====\n"
    + "def normalize(value):\n"
    + "    if value is None:\n"
    + "        return ''\n"
    + "    return str(value).strip()\n"
    + "\n"
    + "def to_list(value):\n"
    + "    if value is None:\n"
    + "        return []\n"
    + "    if isinstance(value, list):\n"
    + "        return value\n"
    + "    return [value]\n"
    + "\n"
    + "def clamp(value, lo, hi):\n"
    + "    return max(lo, min(hi, value))\n"
    + "\n"
    + "def merge(a, b):\n"
    + "    out = dict(a)\n"
    + "    out.update(b or {})\n"
    + "    return out\n"
)


CONDITIONS = ("C0", "C1", "C2", "C3")
TEMPLATES = {
    "C1": LICENSE_TEMPLATE,
    "C2": NEUTRAL_TEMPLATE,
    "C3": LAZY_CODE_TEMPLATE,
}


def _pad_to_target(template: str, target: int = PERTURB_TARGET_CHARS,
                   pad_line: str = "# additional reference line for completeness\n") -> str:
    """把模板精确补齐到 target 字符（±1），保持完整行边界。"""
    if len(template) >= target:
        return template[:target].rsplit("\n", 1)[0] + "\n"
    out = template
    while len(out) + len(pad_line) <= target:
        out += pad_line
    remaining = target - len(out)
    if remaining >= 2:
        # 用注释行 + 空格精确填满，保持完整行
        out += "#" + " " * (remaining - 2) + "\n"
    return out


def _pad_code_to_target(template: str, target: int = PERTURB_TARGET_CHARS) -> str:
    """代码模板用空行/注释补齐，保持 AST 可解析（只用空行）。"""
    if len(template) >= target:
        return template[:target].rsplit("\n", 1)[0] + "\n"
    out = template
    while len(out) + 1 <= target:
        out += "\n"
    return out


@dataclass
class PerturbedPlan:
    condition: str
    plan: PairSelectionPlan


def make_perturbed_plan(base_plan: PairSelectionPlan, condition: str,
                        template_index: int = 0) -> PairSelectionPlan:
    """在 base_plan 上追加扰动块（C1/C2/C3），重新经过预算分配。

    - 深拷贝 base_plan（不原地修改，避免连续生成不同条件互相污染）；
    - 扰动块应用到两侧（vuln + fixed 各一个，同一内容），确保扰动真实进入渲染。
    C0 返回深拷贝的 base_plan 本身。
    """
    new_plan = copy.deepcopy(base_plan)
    if condition == "C0":
        return new_plan
    template = TEMPLATES[condition]
    if condition == "C3":
        perturb = _pad_code_to_target(template)
    else:
        perturb = _pad_to_target(template)
    content = perturb
    path = "third_party/notice.txt" if condition != "C3" else "third_party/helpers.py"
    for side in ("vuln", "fixed"):
        block = BlockPlan(
            path=path,
            side=side,  # 应用到具体侧，确保 render_side 可见
            lo=1, hi=content.count("\n"),
            reason=f"perturbation_{condition}",
            content=content,
            content_sha=_sha256_bytes(content.encode("utf-8")),
            token_estimate=len(content) // 4,
        )
        new_plan.blocks.append(block)
    return new_plan


def render_condition(plan: PairSelectionPlan, side: str) -> str:
    """渲染某侧四条件文本（扰动块按 side 过滤后渲染）。"""
    from .excerpt_plan import render_side
    return render_side(plan, side)
