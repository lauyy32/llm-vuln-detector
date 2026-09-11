# -*- coding: utf-8 -*-
"""A-3 第 1 项（步 1）验收：placebo 算子框架与中性判据。

重点：**前置条件必须真的拦得住**（这是"中性由构造保证"的唯一依据），
而不变量校验必须能检出"偷偷加调用/加控制流/删语句"。
"""
import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import v4_placebo as pl  # noqa: E402


class TestRegistry(unittest.TestCase):
    def test_every_operator_declares_precondition_and_reason(self):
        reg = pl.operators_registry()
        self.assertEqual(reg["schema"], pl.PLACEBO_SCHEMA)
        self.assertGreaterEqual(reg["n_operators"], 3)
        for op in reg["operators"]:
            self.assertTrue(op["precondition"], op["name"])
            self.assertTrue(op["neutrality_reason"], op["name"])
            self.assertEqual(len(op["fingerprint"]), 64, op["name"])

    def test_fingerprint_stable(self):
        a = pl.OPERATORS["commutative_swap"].fingerprint()
        b = pl.OPERATORS["commutative_swap"].fingerprint()
        self.assertEqual(a, b)

    def test_unknown_operator_rejected(self):
        with self.assertRaises(KeyError):
            pl.apply_operator("x = 1\n", "no_such_operator")


class TestCommutativePrecondition(unittest.TestCase):
    """交换律算子的**前置条件**必须精确拦住有副作用的场景。"""

    def test_pure_names_allow_swap(self):
        r = pl.apply_operator("y = a + b\n", "commutative_swap")
        self.assertTrue(r["applied"])
        self.assertIn("b + a", r["new_source"])

    def test_integer_constants_allow_swap(self):
        r = pl.apply_operator("y = 1 + 2\n", "commutative_swap")
        self.assertTrue(r["applied"])

    def test_call_on_either_side_rejected(self):
        """含调用 → 交换会改变求值顺序 → 必须拒绝。"""
        for src in ("y = f() + b\n", "y = a + g()\n"):
            r = pl.apply_operator(src, "commutative_swap")
            self.assertFalse(r["applied"], src)
            self.assertIn("无满足前置条件", r["reason"])

    def test_float_addition_rejected(self):
        """浮点加法交换会改变舍入 → 必须拒绝。"""
        r = pl.apply_operator("y = 1.0 + b\n", "commutative_swap")
        self.assertFalse(r["applied"])

    def test_bitwise_float_none_but_allowed(self):
        r = pl.apply_operator("y = a | b\n", "commutative_swap")
        self.assertTrue(r["applied"])

    def test_subscript_rejected(self):
        r = pl.apply_operator("y = arr[0] + b\n", "commutative_swap")
        self.assertFalse(r["applied"])

    def test_no_eligible_node(self):
        r = pl.apply_operator("x = 1\n", "commutative_swap")
        self.assertFalse(r["applied"])
        self.assertIn("无满足前置条件", r["reason"])


class TestDeadBranch(unittest.TestCase):
    def test_inserts_if_false(self):
        src = "def f():\n    return 1\n"
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"], r)
        tree = ast.parse(r["new_source"])
        self.assertTrue(any(isinstance(n, ast.If) and isinstance(n.test, ast.Constant)
                            and n.test.value is False for n in ast.walk(tree)))
        self.assertIn("return 1", r["new_source"])

    def test_statement_not_deleted(self):
        src = "def f():\n    a = 1\n    return a\n"
        r = pl.apply_operator(src, "dead_branch")
        self.assertTrue(r["applied"])
        self.assertIn("a = 1", r["new_source"])
        self.assertIn("return a", r["new_source"])


class TestInvariantChecker(unittest.TestCase):
    """不变量校验必须能检出各种"偷偷改语义"。"""

    def test_detects_new_call(self):
        errs = pl.check_invariants("x = 1\n", "x = f()\n", "commutative_swap")
        self.assertTrue(any("新增调用" in e for e in errs), errs)

    def test_detects_new_import(self):
        errs = pl.check_invariants("x = 1\n", "import os\nx = 1\n", "commutative_swap")
        self.assertTrue(any("import" in e for e in errs), errs)

    def test_detects_new_control_flow(self):
        errs = pl.check_invariants("x = 1\n", "if x:\n    x = 2\n", "commutative_swap")
        self.assertTrue(any("控制流" in e for e in errs), errs)

    def test_detects_statement_removal(self):
        errs = pl.check_invariants("x = 1\ny = 2\n", "y = 2\n", "commutative_swap")
        self.assertTrue(any("语句减少" in e for e in errs), errs)

    def test_dead_branch_allows_one_if_but_requires_false_test(self):
        ok = "def f():\n    if False:\n        pass\n    return 1\n"
        self.assertEqual(pl.check_invariants("def f():\n    return 1\n", ok, "dead_branch"), [])
        bad = "def f():\n    if True:\n        pass\n    return 1\n"
        errs = pl.check_invariants("def f():\n    return 1\n", bad, "dead_branch")
        self.assertTrue(any("if False" in e for e in errs), errs)

    def test_valid_transform_passes(self):
        self.assertEqual(
            pl.check_invariants("y = a + b\n", "y = b + a\n", "commutative_swap"), [])

    def test_syntax_error_reported(self):
        errs = pl.check_invariants("x = 1\n", "x = ((\n", "commutative_swap")
        self.assertTrue(any("语法错误" in e for e in errs))


class TestPurityHelper(unittest.TestCase):
    def test_pure_expressions(self):
        for src in ("a", "1", "obj.attr"):
            node = ast.parse(src, mode="eval").body
            self.assertTrue(pl._is_pure(node), src)

    def test_impure_expressions(self):
        for src in ("f()", "a[0]", "a[1:2]", "obj.m()"):
            node = ast.parse(src, mode="eval").body
            self.assertFalse(pl._is_pure(node), src)


if __name__ == "__main__":
    unittest.main()
