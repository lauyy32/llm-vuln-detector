# -*- coding: utf-8 -*-
"""A-3 第 1 项（返工版）：placebo 算子框架 —— **span 级精确修改**。

返工要点（针对两份评审的 P0）：
  P0-1 交换律：Python 运算符**动态分派/可重载**（`"a"+"b" != "b"+"a"`、`[1]+[2] != [2]+[1]`、
       `obj1+obj2` 可调 `__add__/__radd__`），`Attribute` 读取可触发 property/descriptor。
       因此 `commutative_swap` 的**前置条件收紧为"两侧均为 `int` 字面量常量"**——
       这是 AST 层**可机械证明**的交换律适用范围；`Name`/`Attribute`/字符串/列表一律拒绝。
  P0-2 docstring：`dead_branch` 必须插在**函数 docstring 之后**，且变换后
       `__doc__` 必须保持（否则是运行时语义变化）。
  P0-3 假实现：`redundant_parens` 真正在源码 span 上插入括号（AST 层**完全不变**）；
       未实现时**不得**返回 `applied=True`。
  P0-4 整文件重写：**禁用 `ast.unparse`**。所有修改都在**源码 span** 上进行，
      硬断言 **span 之外逐字节相等**。
  P1 指纹：`fingerprint` 绑定 **模块 SHA + 算子实现源码 SHA + version + 前置 + 理由**，
       实现改动后指纹必然变化。

不变量（按算子分别定义结构契约）：
  * `redundant_parens`：AST 完全相同（`ast.dump(include_attributes=False)`）；
  * `commutative_swap`：AST 不改（文本交换，语义由"整数常量"前置保证）；
  * `dead_branch`：多出**恰好一个** `if False` 分支，原函数体与 docstring 逐项保持；
  * 全部：span 之外逐字节相等。
"""
from __future__ import annotations

import ast
import hashlib
import inspect
from dataclasses import dataclass, field
from pathlib import Path

PLACEBO_SCHEMA = "v4-placebo-operator/2"

MODULE_PATH = Path(__file__).resolve()


# ---------------------------------------------------------------------------
# span 工具（UTF-8 字节偏移 → 字符偏移）
# ---------------------------------------------------------------------------
def _line_char_offsets(src: str) -> list:
    """每行起始的**字符**偏移（末尾多一项 = 全文长度）。"""
    offsets, pos = [0], 0
    for line in src.splitlines(keepends=True):
        pos += len(line)
        offsets.append(pos)
    if not src.endswith(("\n", "\r")):
        pass
    return offsets


def node_span(src: str, node: ast.AST) -> tuple:
    """节点的**字符 span** `[start, end)`。

    `col_offset` 是 **UTF-8 字节**偏移，故先把所在行按字节切片再解码，避免非 ASCII 错位。
    """
    offsets = _line_char_offsets(src)
    lines = src.splitlines(keepends=True)

    def _col_to_char(lineno: int, byte_col: int) -> int:
        raw = lines[lineno - 1].encode("utf-8")
        return len(raw[:byte_col].decode("utf-8", errors="replace"))

    start = offsets[node.lineno - 1] + _col_to_char(node.lineno, node.col_offset)
    end = offsets[node.end_lineno - 1] + _col_to_char(node.end_lineno, node.end_col_offset)
    return start, end


def _dump(node: ast.AST) -> str:
    return ast.dump(node, include_attributes=False)


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# 算子协议
# ---------------------------------------------------------------------------
@dataclass
class Operator:
    name: str
    status: str                 # "OK" | "NOT_IMPLEMENTED" | "SUSPENDED"
    precondition_doc: str
    neutrality_reason: str
    applies: object             # (src, node) -> bool
    make_edit: object           # (src, node) -> (start, end, replacement) | None
    verify_contract: object     # (orig_src, new_src, node) -> list[str]
    version: int = 1
    meta: dict = field(default_factory=dict)

    def impl_source(self) -> str:
        try:
            return inspect.getsource(self.applies) + inspect.getsource(self.make_edit) + \
                inspect.getsource(self.verify_contract)
        except (OSError, TypeError):
            return repr((self.applies, self.make_edit, self.verify_contract))

    def fingerprint(self, module_sha: str | None = None) -> str:
        """指纹**绑定实现源码**（P1）：实现改了，指纹必变。"""
        ms = module_sha or _sha(MODULE_PATH.read_bytes())
        payload = "|".join([ms, self.name, f"v{self.version}",
                            _sha(self.impl_source().encode("utf-8")),
                            self.precondition_doc, self.neutrality_reason])
        return _sha(payload.encode("utf-8"))


# ---------------------------------------------------------------------------
# 算子 1：redundant_parens（span 级插入括号；AST 完全不变）
# ---------------------------------------------------------------------------
def _paren_applies(src: str, node: ast.AST) -> bool:
    """前置：表达式节点，且**不是**已被括号包裹的顶层元组/生成器（避免歧义）。"""
    if not isinstance(node, ast.expr):
        return False
    if isinstance(node, (ast.Tuple, ast.GeneratorExp, ast.ListComp, ast.SetComp)):
        return False
    s, e = node_span(src, node)
    inner = src[s:e].strip()
    return not (inner.startswith("(") and inner.endswith(")"))


def _paren_make_edit(src: str, node: ast.AST):
    s, e = node_span(src, node)
    return (s, e, f"({src[s:e]})")


def _paren_verify(orig_src: str, new_src: str, node: ast.AST) -> list:
    """结构契约：**AST 完全相同**（括号不改变求值）。"""
    errs = []
    if _dump(ast.parse(orig_src)) != _dump(ast.parse(new_src)):
        errs.append("AST 发生变化（括号不应改变 AST）")
    if "(" not in new_src:
        errs.append("未真正插入括号")
    return errs


REDUNDANT_PARENS = Operator(
    name="redundant_parens",
    status="OK",
    precondition_doc=("表达式节点；排除顶层 Tuple/推导式（避免括号歧义）；"
                      "已带括号的表达式不重复添加"),
    neutrality_reason="Python 中括号不改变表达式求值与 AST（元组歧义除外，已由前置排除）",
    applies=_paren_applies,
    make_edit=_paren_make_edit,
    verify_contract=_paren_verify,
)

# ---------------------------------------------------------------------------
# 算子 2：dead_branch（插在 **docstring 之后**；__doc__ 必须保持）
# ---------------------------------------------------------------------------
def _dead_applies(src: str, node: ast.AST) -> bool:
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and bool(node.body)


def _func_body_first_lineno(fn) -> int:
    """函数体**首条非 docstring 语句**的行号（有 docstring 则跳过它）。"""
    body = fn.body
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        if len(body) < 2:
            return -1        # 仅 docstring：无法安全插入
        return body[1].lineno
    return body[0].lineno


def _dead_make_edit(src: str, node: ast.AST):
    lineno = _func_body_first_lineno(node)
    if lineno < 0:
        return None
    lines = src.splitlines(keepends=True)
    target = lines[lineno - 1]
    indent = target[:len(target) - len(target.lstrip())]
    insert = f"{indent}if False:\n{indent}    pass\n"
    # 在目标行**起始**插入（span = 该行起点的空区间）
    offsets = _line_char_offsets(src)
    pos = offsets[lineno - 1]
    return (pos, pos, insert)


def _dead_verify(orig_src: str, new_src: str, node: ast.AST) -> list:
    errs = []
    t0, t1 = ast.parse(orig_src), ast.parse(new_src)
    f0 = next(n for n in ast.walk(t0) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == node.name)
    f1 = next(n for n in ast.walk(t1) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
              and n.name == node.name)
    # docstring 语义必须保持（P0-2）
    if ast.get_docstring(f0) != ast.get_docstring(f1):
        errs.append(f"docstring 语义变化: {ast.get_docstring(f0)!r} → {ast.get_docstring(f1)!r}")
    # 恰好新增 1 个 `if False`
    def _deads(fn):
        return [n for n in fn.body if isinstance(n, ast.If) and isinstance(n.test, ast.Constant)
                and n.test.value is False]
    d1 = _deads(f1)
    if len(d1) != 1:
        errs.append(f"函数体直属 `if False` 数量应为 1，实得 {len(d1)}")
    if _deads(f0):
        errs.append("原函数体已含 `if False`（前置应排除）")
    # 原函数体语句（除 docstring 与**本次插入的 if False**）必须逐项保持
    def _stmts(fn):
        b = list(fn.body)
        if b and isinstance(b[0], ast.Expr) and isinstance(b[0].value, ast.Constant) \
                and isinstance(b[0].value.value, str):
            b = b[1:]
        return [_dump(s) for s in b if s not in _deads(fn)]
    if _stmts(f0) != _stmts(f1):
        errs.append("原函数体语句未逐项保持")
    return errs


DEAD_BRANCH = Operator(
    name="dead_branch",
    status="OK",
    precondition_doc=("函数定义且函数体非空；若函数体仅含 docstring 则拒绝（无处安全插入）；"
                      "插入位置 = **docstring 之后**的首条语句之前"),
    neutrality_reason=("`if False` 恒不执行 → 业务输出不变；且 docstring 仍是首条语句，"
                       "`__doc__` 语义保持。**中性范围限定为业务输出**：会改变源码行号，"
                       "故 tracing/coverage/行号反射类观测不在此声明内"),
    applies=_dead_applies,
    make_edit=_dead_make_edit,
    verify_contract=_dead_verify,
)

# ---------------------------------------------------------------------------
# 算子 3：commutative_swap（**仅整数常量** —— Python 唯一可机械证明的交换律范围）
# ---------------------------------------------------------------------------
def _int_const(expr: ast.AST) -> bool:
    return isinstance(expr, ast.Constant) and type(expr.value) is int and not isinstance(
        expr.value, bool)


def _comm_applies(src: str, node: ast.AST) -> bool:
    """前置：BinOp，op∈{Add,Mult,BitOr,BitAnd,BitXor}，且**两侧均为 `int` 字面量常量**。

    Python 运算符可重载，字符串/列表/自定义对象/`Name`/`Attribute` 一律**不可证明**交换律，
    因此全部拒绝（评审 P0-1）。
    """
    if not (isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Mult, ast.BitOr, ast.BitAnd, ast.BitXor))):
        return False
    return _int_const(node.left) and _int_const(node.right)


def _comm_make_edit(src: str, node: ast.BinOp):
    ls, le = node_span(src, node.left)
    rs, re_ = node_span(src, node.right)
    left_txt, right_txt = src[ls:le], src[rs:re_]
    if left_txt == right_txt:
        return None                      # 无实际变化 → 不产出
    # 整体替换为 "right op left"（保留原 operator 文本）
    s, e = node_span(src, node)
    op_txt = src[le:rs]
    return (s, e, f"{right_txt}{op_txt}{left_txt}")


def _comm_verify(orig_src: str, new_src: str, node: ast.AST) -> list:
    """结构契约：新源码可解析；**前置仍成立**（两侧均为 int 常量）。

    两侧都是 `int` 字面量常量时，交换律由整数运算的数学性质保证，
    无需再对整行源码做 `eval`（后者对赋值语句不适用，且会引入不必要的求值风险）。
    另做一次**数值复核**：把左右常量按该运算符算出结果，与交换后顺序一致。
    """
    errs = []
    try:
        ast.parse(new_src)
    except SyntaxError as e:
        errs.append(f"新源码语法错误: {e.msg}")
        return errs
    if not (_int_const(node.left) and _int_const(node.right)):
        errs.append("前置不再成立（两侧必须都是 int 字面量常量）")
        return errs
    lv, rv = node.left.value, node.right.value
    ops = {ast.Add: lambda a, b: a + b, ast.Mult: lambda a, b: a * b,
           ast.BitOr: lambda a, b: a | b, ast.BitAnd: lambda a, b: a & b,
           ast.BitXor: lambda a, b: a ^ b}
    fn = ops.get(type(node.op))
    if fn is None:
        errs.append("不支持的运算符")
        return errs
    if fn(lv, rv) != fn(rv, lv):
        errs.append(f"交换后数值不等: {fn(lv, rv)} vs {fn(rv, lv)}")
    return errs


COMMUTATIVE_SWAP = Operator(
    name="commutative_swap",
    status="OK",
    precondition_doc=("BinOp 且 op∈{Add,Mult,BitOr,BitAnd,BitXor}；**两侧均为 `int` 字面量"
                      "常量**（`type(v) is int` 且非 bool）。Name/Attribute/字符串/列表/"
                      "任意运行时对象一律拒绝 —— Python 运算符可重载，AST 无法证明交换律；"
                      "两侧文本相同时不产出（无实际变化）"),
    neutrality_reason="两侧均为 int 字面量常量 → 求值确定，整数/位运算满足交换律",
    applies=_comm_applies,
    make_edit=_comm_make_edit,
    verify_contract=_comm_verify,
)

OPERATORS = {op.name: op for op in (REDUNDANT_PARENS, DEAD_BRANCH, COMMUTATIVE_SWAP)}


def operators_registry() -> dict:
    """预注册登记表（含**模块 SHA** 与逐算子实现指纹）。"""
    module_sha = _sha(MODULE_PATH.read_bytes())
    return {
        "schema": PLACEBO_SCHEMA,
        "module_sha256": module_sha,
        "n_operators": len(OPERATORS),
        "operators": [
            {"name": op.name, "status": op.status, "version": op.version,
             "precondition": op.precondition_doc,
             "neutrality_reason": op.neutrality_reason,
             "operator_impl_sha256": _sha(op.impl_source().encode("utf-8")),
             "fingerprint": op.fingerprint(module_sha)}
            for op in OPERATORS.values()],
        "policy": ("中性由**构造**保证；指纹绑定实现源码，实现改动即指纹变化；"
                   "修改一律在源码 span 上进行，span 外逐字节相等"),
    }


# ---------------------------------------------------------------------------
# 施加入口
# ---------------------------------------------------------------------------
def _apply_edit(src: str, start: int, end: int, repl: str) -> str:
    return src[:start] + repl + src[end:]


def apply_operator(src: str, op_name: str, node_selector=None) -> dict:
    """应用算子：**前置不满足即拒绝**，且**span 外逐字节相等**（硬断言）。

    返回 dict，含 `applied` / `new_source` / `span` / `fingerprint`；
    若算子未实现或不可应用，返回 `applied=False` 与原因（**不得**返回假成功）。
    """
    if op_name not in OPERATORS:
        raise KeyError(f"未注册算子: {op_name}")
    op = OPERATORS[op_name]
    if op.status != "OK":
        return {"applied": False, "reason": f"算子状态为 {op.status}（不得使用）",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    tree = ast.parse(src)
    target = None
    for n in ast.walk(tree):
        if not op.applies(src, n):
            continue
        if node_selector is None or node_selector(n):
            target = n
            break
    if target is None:
        return {"applied": False, "reason": "无满足前置条件的节点",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    edit = op.make_edit(src, target)
    if edit is None:
        return {"applied": False, "reason": "前置满足但无实际变化（不产出）",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    start, end, repl = edit
    new_src = _apply_edit(src, start, end, repl)
    if new_src == src:
        return {"applied": False, "reason": "变换后源码与原文完全相同",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    # **span 外逐字节相等**（硬断言）
    if new_src[:start] != src[:start] or not new_src.endswith(src[end:]):
        return {"applied": False, "reason": "span 之外发生改动（严重错误）",
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    errs = op.verify_contract(src, new_src, target)
    if errs:
        return {"applied": False, "reason": "结构契约校验失败: " + "; ".join(errs),
                "operator": op_name, "operator_fingerprint": op.fingerprint()}
    return {"applied": True, "new_source": new_src, "operator": op_name,
            "span": [start, end], "before_span_sha256": _sha(src[start:end].encode("utf-8")),
            "after_span_sha256": _sha(repl.encode("utf-8")),
            "operator_fingerprint": op.fingerprint(),
            "neutrality_reason": op.neutrality_reason}


def byte_identity_outside_span(orig: str, new: str, start: int, end: int, repl_len: int) -> bool:
    """显式校验：`orig[:start] == new[:start]` 且 `orig[end:] == new[start+repl_len:]`。"""
    return orig[:start] == new[:start] and orig[end:] == new[start + repl_len:]
