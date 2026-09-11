# -*- coding: utf-8 -*-
"""A-3 步 1（返工版）验收：**两份评审列出的反例全覆盖**。

本测试的存在意义：**固定住那些曾经漏检的反例**，防止"框架正确"再次掩盖语义错误。
"""
import ast
import hashlib
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_placebo as pl  # noqa: E402


# ===========================================================================
# P0-1：交换律反例（Python 运算符可重载，AST 无法证明）
# ===========================================================================
class TestCommutativeRejectsUnprovable(unittest.TestCase):
    """**评审 P0-1 的全部反例必须被拒绝**。"""

    REJECT = (
        'y = "a" + "b"\n',            # 字符串拼接不交换
        'y = [1] + [2]\n',            # 列表拼接不交换
        'y = x + y\n',                # Name 类型未知（可能是 float/自定义）
        'y = obj.attr + b\n',         # 属性读取可触发 property/descriptor
        'y = Custom() + Custom()\n',  # 运算符重载
        'y = a + b\n',                # 任意 Name
        'y = 1.0 + 2\n',              # 浮点常量
        'y = True + False\n',         # bool 是 int 子类，但语义特殊 → 拒绝
    )

    def test_all_rejected(self):
        for src in self.REJECT:
            r = pl.apply_operator(src, "commutative_swap")
            self.assertFalse(r["applied"], f"应拒绝但放行了: {src.strip()}")

    def test_int_constants_allowed(self):
        r = pl.apply_operator("y = 1 + 2\n", "commutative_swap")
        self.assertTrue(r["applied"], r)
        self.assertIn("2 + 1", r["new_source"])

    def test_bitwise_int_constants_allowed(self):
        r = pl.apply_operator("y = 0b1010 | 0b0101\n", "commutative_swap")
        self.assertTrue(r["applied"])

    def test_identical_operands_no_change(self):
        """两侧文本相同 → 无实际变化 → 不产出。"""
        r = pl.apply_operator("y = 1 + 1\n", "commutative_swap")
        self.assertFalse(r["applied"])
        self.assertIn("无实际变化", r["reason"])

    def test_precondition_doc_mentions_overload_reason(self):
        op = pl.OPERATORS["commutative_swap"]
        self.assertIn("可重载", op.precondition_doc)
        self.assertIn("int", op.precondition_doc)


# ===========================================================================
# P0-2：dead_branch 不得破坏 docstring
# ===========================================================================
class TestDeadBranchDocstring(unittest.TestCase):
    def test_docstring_preserved(self):
        src = 'def f():\n    """security parser"""\n    return 1\n'
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"], r)
        fn = ast.parse(r["new_source"]).body[0]
        self.assertEqual(ast.get_docstring(fn), "security parser")

    def test_async_function(self):
        src = 'async def f():\n    """doc"""\n    await g()\n'
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"], r)
        self.assertEqual(ast.get_docstring(ast.parse(r["new_source"]).body[0]), "doc")

    def test_no_docstring_function(self):
        src = "def f():\n    return 1\n"
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"])
        self.assertIsNone(ast.get_docstring(ast.parse(r["new_source"]).body[0]))

    def test_function_with_only_docstring_rejected(self):
        """仅含 docstring → 无处安全插入 → 拒绝（不得破坏 __doc__）。"""
        r = pl.apply_operator('def f():\n    """only"""\n', "dead_branch")
        self.assertFalse(r["applied"])

    def test_original_statements_kept(self):
        src = "def f():\n    a = 1\n    return a\n"
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"])
        self.assertIn("a = 1", r["new_source"])
        self.assertIn("return a", r["new_source"])

    def test_exactly_one_if_false(self):
        src = "def f():\n    return 1\n"
        r = pl.apply_operator(src, "dead_branch")
        n = sum(1 for x in ast.walk(ast.parse(r["new_source"]))
                if isinstance(x, ast.If) and isinstance(x.test, ast.Constant)
                and x.test.value is False)
        self.assertEqual(n, 1)

    def test_neutrality_reason_limits_scope(self):
        """中性范围必须**显式限定**（排除 tracing/coverage/行号反射）。"""
        op = pl.OPERATORS["dead_branch"]
        self.assertIn("行号", op.neutrality_reason)
        self.assertIn("tracing", op.neutrality_reason)

    def test_single_line_body_rejected(self):
        """单行函数体 `def f(): return 1` —— 行首插入会落到**函数体外**（模块层），
        作用域错误 → 前置必须直接拒绝，不得留给 verify 兜底。
        """
        r = pl.apply_operator("def f(): return 1\n", "dead_branch")
        self.assertFalse(r["applied"])

    def test_never_produces_module_level_if_false(self):
        """任何被接受的 dead_branch 变换，`if False` 必须在**函数体内**。"""
        cases = ('def f():\n    return 1\n',
                 'async def f():\n    """d"""\n    await g()\n')
        for src in cases:
            with self.subTest(src=src):
                r = pl.apply_operator(src, "dead_branch")
                self.assertTrue(r["applied"], r)
                tree = ast.parse(r["new_source"])
                module_level = [n for n in tree.body if isinstance(n, ast.If)]
                self.assertEqual(module_level, [], "出现了模块层 if False")


# ===========================================================================
# P0-3：redundant_parens 必须真正插入括号且 AST 不变
# ===========================================================================
class TestRedundantParensReal(unittest.TestCase):
    def test_really_inserts_parens(self):
        r = pl.apply_operator("y = a + b\n", "redundant_parens")
        self.assertTrue(r["applied"], r)
        self.assertIn("(", r["new_source"])
        self.assertNotEqual(r["new_source"], "y = a + b\n")

    def test_ast_unchanged(self):
        src = "y = a + b * c\n"
        r = pl.apply_operator(src, "redundant_parens")
        self.assertTrue(r["applied"])
        self.assertEqual(ast.dump(ast.parse(src), include_attributes=False),
                         ast.dump(ast.parse(r["new_source"]), include_attributes=False))

    def test_already_parenthesized_top_expression_rejected(self):
        """**显式指定顶层表达式**（已带括号）→ 拒绝；避免重复包裹。"""
        src = "y = (a + b)\n"
        top = ast.parse(src).body[0].value           # BinOp，文本为 "(a + b)"
        r = pl.apply_operator(src, "redundant_parens",
                              node_selector=lambda n: n is top)
        self.assertFalse(r["applied"])

    def test_subexpression_may_be_wrapped(self):
        """若允许选择子节点，包裹子表达式是**合法**的（AST 不变）。"""
        src = "y = a + b\n"
        # apply_operator 内部会重新 parse → selector 不能按对象身份，须按**类型/文本**
        r = pl.apply_operator(src, "redundant_parens",
                              node_selector=lambda n: isinstance(n, ast.Name) and n.id == "a")
        self.assertTrue(r["applied"], r)
        self.assertIn("(a)", r["new_source"])
        self.assertEqual(ast.dump(ast.parse(src), include_attributes=False),
                         ast.dump(ast.parse(r["new_source"]), include_attributes=False))

    def test_tuple_top_expression_rejected(self):
        src = "y = 1, 2\n"
        top = ast.parse(src).body[0].value           # Tuple
        r = pl.apply_operator(src, "redundant_parens",
                              node_selector=lambda n: n is top)
        self.assertFalse(r["applied"])

    def test_status_must_be_ok(self):
        self.assertEqual(pl.OPERATORS["redundant_parens"].status, "OK")

    def test_not_implemented_operator_cannot_apply(self):
        """把算子临时标 NOT_IMPLEMENTED → 必须拒绝（防"假实现"回归）。"""
        op = pl.OPERATORS["redundant_parens"]
        orig = op.status
        try:
            op.status = "NOT_IMPLEMENTED"
            r = pl.apply_operator("y = a + b\n", "redundant_parens")
            self.assertFalse(r["applied"])
            self.assertIn("NOT_IMPLEMENTED", r["reason"])
        finally:
            op.status = orig


# ===========================================================================
# P0-4：span 之外必须逐字节相等；不得整文件重写
# ===========================================================================
class TestSpanLocalOnly(unittest.TestCase):
    SRC = ('#!/usr/bin/env python\n'
           '# -*- coding: utf-8 -*-\n'
           '"""module doc"""\n'
           '\n'
           'def f(a, b):\n'
           '    # 关键注释：不可丢失\n'
           '    total = a + b      # 行内注释\n'
           '    return total\n')

    def test_comments_and_header_preserved(self):
        for op in ("redundant_parens", "dead_branch"):
            r = pl.apply_operator(self.SRC, op)
            if not r["applied"]:
                continue
            self.assertIn("#!/usr/bin/env python", r["new_source"], op)
            self.assertIn("# -*- coding: utf-8 -*-", r["new_source"], op)
            self.assertIn("关键注释：不可丢失", r["new_source"], op)
            self.assertIn('"""module doc"""', r["new_source"], op)

    def test_outside_span_byte_identical(self):
        src = "y = 1 + 2\n"
        r = pl.apply_operator(src, "commutative_swap")
        self.assertTrue(r["applied"])
        s, e = r["span"]
        repl_len = len(r["new_source"]) - (len(src) - (e - s))
        self.assertTrue(pl.byte_identity_outside_span(src, r["new_source"], s, e, repl_len))

    def test_multiline_source_span_identity(self):
        """多行源码：span 外必须逐字节相等（含所有注释与空行）。"""
        src = self.SRC
        r = pl.apply_operator(src, "redundant_parens")
        self.assertTrue(r["applied"], r)
        s, e = r["span"]
        repl_len = len(r["new_source"]) - (len(src) - (e - s))
        self.assertTrue(pl.byte_identity_outside_span(src, r["new_source"], s, e, repl_len))

    def test_no_unparse_used(self):
        """模块**不得**使用 ast.unparse（评审 P0-4）。"""
        src = pl.MODULE_PATH.read_text(encoding="utf-8")
        code = "\n".join(l for l in src.splitlines()
                         if not l.strip().startswith("#"))
        code = code.split('"""', 2)[-1]      # 去掉模块 docstring
        self.assertNotIn("ast.unparse", code)
        self.assertNotIn("ast.fix_missing_locations", code)

    def test_identical_transform_returns_not_applied(self):
        r = pl.apply_operator('y = 1 + 1\n', "commutative_swap")
        self.assertFalse(r["applied"])

    def test_span_recorded(self):
        r = pl.apply_operator("y = 1 + 2\n", "commutative_swap")
        self.assertEqual(len(r["span"]), 2)
        self.assertEqual(len(r["before_span_sha256"]), 64)
        self.assertEqual(len(r["after_span_sha256"]), 64)


# ===========================================================================
# P1：指纹必须绑定实现源码
# ===========================================================================
class TestFingerprintBindsImplementation(unittest.TestCase):
    def test_registry_records_module_and_impl_sha(self):
        reg = pl.operators_registry()
        self.assertEqual(len(reg["module_sha256"]), 64)
        for op in reg["operators"]:
            self.assertEqual(len(op["operator_impl_sha256"]), 64, op["name"])
            self.assertEqual(len(op["fingerprint"]), 64, op["name"])

    def test_impl_change_changes_fingerprint(self):
        """改动算子实现 → 指纹必须变化（旧版只哈希 name+version+doc，改实现不变）。"""
        op = pl.OPERATORS["redundant_parens"]
        orig = op.applies

        def tampered(src, node):
            return orig(src, node)
        op.applies = tampered
        try:
            fp2 = op.fingerprint()
        finally:
            op.applies = orig
        fp1 = op.fingerprint()
        self.assertNotEqual(fp1, fp2)

    def test_doc_change_changes_fingerprint(self):
        op = pl.OPERATORS["dead_branch"]
        orig = op.precondition_doc
        try:
            op.precondition_doc = orig + "（改）"
            fp2 = op.fingerprint()
        finally:
            op.precondition_doc = orig
        self.assertNotEqual(op.fingerprint(), fp2)


class TestMisc(unittest.TestCase):
    def test_unknown_operator_raises(self):
        with self.assertRaises(KeyError):
            pl.apply_operator("x = 1\n", "nope")

    def test_span_helper_handles_non_ascii(self):
        """非 ASCII 源码的 span 计算不得错位。"""
        src = 'y = "中文" + 1\n'
        tree = ast.parse(src)
        node = tree.body[0].value
        s, e = pl.node_span(src, node)
        self.assertEqual(src[s:e], '"中文" + 1')

    def test_registry_schema(self):
        self.assertEqual(pl.operators_registry()["schema"], pl.PLACEBO_SCHEMA)


# ===========================================================================
# 评审 3 P1：跨平台指纹（LF 归一化）/ 行尾继承 / span identity 定位
# ===========================================================================
class TestLFNormalizedFingerprint(unittest.TestCase):
    def test_registry_declares_hash_mode(self):
        reg = pl.operators_registry()
        self.assertEqual(pl.HASH_MODE, "lf-normalized-text")
        self.assertEqual(reg["hash_mode"], pl.HASH_MODE)
        for op in reg["operators"]:
            self.assertEqual(op["hash_mode"], pl.HASH_MODE, op["name"])

    def test_sha_lf_ignores_line_ending(self):
        self.assertEqual(pl._sha_lf(b"a\r\nb\r\n"), pl._sha_lf(b"a\nb\n"))

    def test_module_sha_is_lf_normalized(self):
        self.assertEqual(pl.operators_registry()["module_sha256"],
                         pl._sha_lf(pl.MODULE_PATH.read_bytes()))

    def test_fingerprint_stable_across_line_endings(self):
        """同一内容以 CRLF / LF 两种检出 → 指纹必须相同（此前会漂移）。"""
        op = pl.OPERATORS["redundant_parens"]
        self.assertEqual(op.fingerprint(pl._sha_lf(b"x\r\ny\r\n")),
                         op.fingerprint(pl._sha_lf(b"x\ny\n")))


class TestNewlineInheritance(unittest.TestCase):
    def test_crlf_source_produces_no_bare_lf(self):
        """CRLF 源文件插入语句后**不得混入裸 LF**（否则整文件行尾不再一致）。"""
        src = "def f():\r\n    return 1\r\n"
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"], r)
        body = r["new_source"]
        self.assertEqual(body.count("\n"), body.count("\r\n"), "混入裸 LF")
        self.assertIn("if False:\r\n", body)

    def test_lf_source_produces_no_cr(self):
        r = pl.apply_operator("def f():\n    return 1\n", "dead_branch")
        self.assertTrue(r["applied"], r)
        self.assertNotIn("\r", r["new_source"])


class TestSpanIdentityFunctionLookup(unittest.TestCase):
    def test_second_same_name_function_located_by_span(self):
        """同名函数重定义时，verify 必须按 **span** 定位目标函数（旧版按 name 会错配）。"""
        src = ("def f():\n"
               "    return 1\n"
               "\n"
               "def f():\n"
               "    return 2\n")
        r = pl.apply_operator(src, "dead_branch",
                              node_selector=lambda n: getattr(n, "lineno", 0) == 4)
        self.assertTrue(r["applied"], r)
        fns = [n for n in ast.parse(r["new_source"]).body
               if isinstance(n, ast.FunctionDef)]
        self.assertEqual(len(fns), 2)

        def _has_dead(fn):
            return any(isinstance(s, ast.If) and isinstance(s.test, ast.Constant)
                       and s.test.value is False for s in fn.body)
        self.assertFalse(_has_dead(fns[0]), "误插到第一个同名函数")
        self.assertTrue(_has_dead(fns[1]))

    def test_nested_method_located_by_span(self):
        src = ("class C:\n"
               "    def m(self):\n"
               "        return 1\n")
        r = pl.apply_operator(src, "dead_branch",
                              node_selector=lambda n: getattr(n, "name", "") == "m")
        self.assertTrue(r["applied"], r)
        cls = ast.parse(r["new_source"]).body[0]
        self.assertTrue(any(isinstance(s, ast.If) for s in cls.body[0].body))


if __name__ == "__main__":
    unittest.main()
