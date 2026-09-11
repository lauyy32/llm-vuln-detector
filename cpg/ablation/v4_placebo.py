# -*- coding: utf-8 -*-
"""A-3 第 1 项（步 1）：placebo 变换的**算子框架 + 中性判据**。

设计原则（严谨性关键）：
  "语义中性"对图灵完备语言**无法一般判定**。因此本模块**不做事后判定**，而是
  要求每个算子显式声明：
    ① **前置条件**（`precondition`）——不满足即**拒绝**该位置；
    ② **变换**（`transform`）；
    ③ **中性理由**（`neutrality_reason`）——属于可枚举的等价类（交换律 / 括号 /
       重命名 / 死代码 / 注释），且前置条件恰好覆盖该等价类的适用边界。
  这样"中性"由**构造**保证，而非由启发式猜测。

本步**只实现框架 + 首批算子 + 校验器**，不生成任何正式 placebo 工件（受 A-3 边界约束）。

算子登记表（`OPERATORS`）是**预注册**对象：新增算子必须同时给出前置/理由/测试。
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field

PLACEBO_SCHEMA = "v4-placebo-operator/1"

# 纯表达式节点（无副作用）：允许参与交换律/括号类变换
_PURE_NODES = (ast.Name, ast.Constant, ast.Attribute)


def _is_pure(expr: ast.expr) -> bool:
    """表达式是否**无副作用**（无调用、无下标副作用、无 await/yield）。"""
    for n in ast.walk(expr):
        if isinstance(n, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom,
                          ast.NamedExpr, ast.Subscript)):
            return False
    return True


def _contains_call(expr: ast.expr) -> bool:
    return any(isinstance(n, ast.Call) for n in ast.walk(expr))


@dataclass
class Operator:
    """一个可作为 placebo 的变换算子。"""
    name: str
    arity: str
    precondition_doc: str
    neutrality_reason: str
    applies: object          # (node) -> bool
    transform: object        # (node) -> ast.expr | None
    version: int = 1
    meta: dict = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = f"{self.name}|v{self.version}|{self.precondition_doc}|{self.neutrality_reason}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# 算子 1：交换律（a + b → b + a 等）
# ---------------------------------------------------------------------------
_COMMUTATIVE_OPS = (ast.Add, ast.Mult, ast.BitOr, ast.BitAnd, ast.BitXor)


def _comm_applies(node: ast.AST) -> bool:
    """前置：二元交换律运算，且**两侧均为无副作用表达式**。

    理由：若任一侧含调用/下标，交换会改变**求值顺序**，行为不再中性。
    同理 float 加法不满足交换律的精确语义（浮点误差），故**仅当两侧都不是浮点常量**时放行。
    """
    if not (isinstance(node, ast.BinOp) and isinstance(node.op, _COMMUTATIVE_OPS)):
        return False
    if not (_is_pure(node.left) and _is_pure(node.right)):
        return False
    # 浮点：加法/乘法交换会改变舍入结果 → 拒绝
    if isinstance(node.op, (ast.Add, ast.Mult)):
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and isinstance(side.value, float):
                return False
    return True


def _comm_transform(node: ast.BinOp) -> ast.expr:
    new = ast.BinOp(left=node.right, right=node.left, op=node.op)
    return ast.copy_location(new, node)


COMMUTATIVE_SWAP = Operator(
    name="commutative_swap",
    arity="expr",
    precondition_doc=("BinOp 且 op∈{Add,Mult,BitOr,BitAnd,BitXor}；两侧均无副作用"
                      "（无 Call/Await/Yield/海象/Subscript）；加法/乘法两侧不得为浮点常量"),
    neutrality_reason="整数/位运算满足交换律，且两侧无副作用 → 求值顺序与结果均不变",
    applies=_comm_applies,
    transform=_comm_transform,
)

# ---------------------------------------------------------------------------
# 算子 2：冗余括号（不改变 AST 语义，但改变源码 token）
# ---------------------------------------------------------------------------
def _paren_applies(node: ast.AST) -> bool:
    """前置：任意表达式（括号在 Python 中不改变求值，除元组歧义外）。"""
    return isinstance(node, ast.expr)


def _paren_transform(node: ast.expr) -> ast.expr:
    """用 `ast.unparse` 后的文本无法表达"多余括号"；改为在源码层处理，
    故此处仅做**标记**（真正的括号注入在 patch 构造阶段按 token 位置进行）。"""
    return node


REDUNDANT_PARENS = Operator(
    name="redundant_parens",
    arity="expr",
    precondition_doc="任意表达式；不得用于可能构成元组的位置（由构造阶段按 token 位置复查）",
    neutrality_reason="Python 中括号不改变表达式求值（元组歧义除外）→ 行为中性",
    applies=_paren_applies,
    transform=_paren_transform,
    meta={"implemented_at": "source_token_level", "note": "AST 层保持原节点"},
)

# ---------------------------------------------------------------------------
# 算子 3：死代码插入（不可达分支）
# ---------------------------------------------------------------------------
def _dead_applies(node: ast.AST) -> bool:
    """前置：函数体语句（可插入 `if False:` 死分支）。"""
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))


def _dead_transform(node) -> ast.AST:
    dead = ast.If(test=ast.Constant(value=False),
                  body=[ast.Pass()], orelse=[])
    ast.copy_location(dead, node)
    node.body = [dead, *node.body]
    return node


DEAD_BRANCH = Operator(
    name="dead_branch",
    arity="stmt",
    precondition_doc="目标为函数定义；插入 `if False: pass` 于函数体首部",
    neutrality_reason="`if False` 分支恒不执行 → 控制流与数据流均不变",
    applies=_dead_applies,
    transform=_dead_transform,
)

OPERATORS = {op.name: op for op in (COMMUTATIVE_SWAP, REDUNDANT_PARENS, DEAD_BRANCH)}


def operators_registry() -> dict:
    """预注册登记表：每个算子的前置条件、中性理由与指纹。"""
    return {
        "schema": PLACEBO_SCHEMA,
        "n_operators": len(OPERATORS),
        "operators": [
            {"name": op.name, "arity": op.arity,
             "precondition": op.precondition_doc,
             "neutrality_reason": op.neutrality_reason,
             "version": op.version, "fingerprint": op.fingerprint()}
            for op in OPERATORS.values()],
        "policy": ("新增算子必须同时提供前置条件、中性理由与针对性测试；"
                   "中性性由**构造**保证，不做事后启发式判定"),
    }


# ---------------------------------------------------------------------------
# 校验器：变换前后必须满足的可检查不变量
# ---------------------------------------------------------------------------
def _count_nodes(tree: ast.AST) -> dict:
    from collections import Counter
    return Counter(type(n).__name__ for n in ast.walk(tree))


def check_invariants(orig_src: str, new_src: str, op_name: str) -> list:
    """对一次算子应用做**可检查不变量**校验（fail-closed，返回错误列表）。

    不变量（按算子类型区分，避免"一刀切"造成过度约束或漏检）：
      - 两侧均可 `ast.parse`；
      - **无新增调用**：`Call` 数量不得增加；
      - **无新增 import**：`Import/ImportFrom` 数量不得增加；
      - **控制流骨架不变**：除 `dead_branch` 允许 +1 个 `If`（其 `test` 必须为 `False`）
        外，其余控制流节点数量不得增加；
      - 语句数不减少（不得删除代码）。
    """
    errs = []
    try:
        t0 = ast.parse(orig_src)
        t1 = ast.parse(new_src)
    except SyntaxError as e:
        return [f"语法错误: {e.msg}"]
    c0, c1 = _count_nodes(t0), _count_nodes(t1)
    if c1["Call"] > c0["Call"]:
        errs.append(f"新增调用: {c0['Call']} → {c1['Call']}")
    if (c1["Import"] + c1["ImportFrom"]) > (c0["Import"] + c0["ImportFrom"]):
        errs.append("新增 import")
    if op_name == "dead_branch":
        # 允许 +1 个 If，但必须恰好是 `if False`，且其它控制流不得增加
        extra_if = c1["If"] - c0["If"]
        if extra_if > 1:
            errs.append(f"dead_branch 新增 If 超过 1 个: {extra_if}")
        for k in ("For", "While", "Try", "With", "Match"):
            if c1[k] > c0[k]:
                errs.append(f"新增控制流节点 {k}: {c0[k]} → {c1[k]}")
        if extra_if == 1:
            has_false = any(isinstance(n, ast.If) and isinstance(n.test, ast.Constant)
                            and n.test.value is False for n in ast.walk(t1))
            if not has_false:
                errs.append("dead_branch 新增的 If 不是 `if False`")
    else:
        for k in ("If", "For", "While", "Try", "With", "Match"):
            if c1[k] > c0[k]:
                errs.append(f"新增控制流节点 {k}: {c0[k]} → {c1[k]}")
    stmts = ("Assign", "AugAssign", "Return", "Expr", "FunctionDef", "AsyncFunctionDef")
    for k in stmts:
        if c1[k] < c0[k]:
            errs.append(f"语句减少 {k}: {c0[k]} → {c1[k]}")
    return errs


class _FirstMatchTransformer(ast.NodeTransformer):
    """把**首个**满足 `applies` 的节点替换为 `transform(node)`（只改一处）。

    用 `NodeTransformer` 是为了真正把新节点**接回 AST 树**——`ast.walk` 只读，
    直接改子节点不会生效（这正是本轮修掉的 bug）。
    """

    def __init__(self, op, node_selector=None):
        self.op = op
        self.node_selector = node_selector
        self.done = False

    def generic_visit(self, node):
        if not self.done and self.op.applies(node) and \
                (self.node_selector is None or self.node_selector(node)):
            self.done = True
            return self.op.transform(node)
        return super().generic_visit(node)


def apply_operator(src: str, op_name: str, node_selector=None) -> dict:
    """在源码上应用一个算子：**前置不满足即拒绝**（返回 `applied=False`）。

    `node_selector(node) -> bool` 可选，用于指定目标节点；默认取**首个前置满足**的节点。
    """
    if op_name not in OPERATORS:
        raise KeyError(f"未注册算子: {op_name}")
    op = OPERATORS[op_name]
    tree = ast.parse(src)
    tr = _FirstMatchTransformer(op, node_selector)
    new_tree = tr.visit(tree)
    if not tr.done:
        return {"applied": False, "reason": "无满足前置条件的节点",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    ast.fix_missing_locations(new_tree)
    new_src = ast.unparse(new_tree)
    errs = check_invariants(src, new_src, op_name)
    if errs:
        return {"applied": False, "reason": "不变量校验失败: " + "; ".join(errs),
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    return {"applied": True, "new_source": new_src, "operator": op_name,
            "operator_fingerprint": op.fingerprint(),
            "neutrality_reason": op.neutrality_reason}
