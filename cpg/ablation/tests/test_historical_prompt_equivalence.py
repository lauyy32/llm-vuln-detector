# -*- coding: utf-8 -*-
"""指令 5 等价门禁测试：10 类验收场景（合成 fixture，不依赖真实 170 条数据）。"""
import csv
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from cpg.ablation import historical_prompt_equivalence as heq  # noqa: E402


def mk_prompt(cve, cwe, code="x=1", cpg=None):
    p = f"# 审计任务\n- CVE: {cve}\n- 目标 CWE: {cwe}\n"
    p += f"\n# 目标代码（节选）\n```\n{code}\n```"
    if cpg:
        p += f"\n# 代码级上下文（CPG 污点切片）\n{cpg}"
    p += "\n# 输出要求\n{}"
    return p


def sha(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


class Fixture:
    """构造最小可运行门禁输入：2 个 eligible CVE + 1 个 excluded CVE（各 2 side）。"""

    def __init__(self, td: Path):
        self.td = td
        self.prompts = td / "prompts"
        self.prompts.mkdir(parents=True, exist_ok=True)
        self.cves = ["CVE-A", "CVE-B"]
        # 排除集必须与 heq.EXCLUDED 一致（交叉断言要求），否则门禁按设计拒绝
        self.excluded = sorted(heq.EXCLUDED)
        self.n_rows = (len(self.cves) + len(self.excluded)) * 2
        self.tree = {}  # (cve, side) -> tree sha
        self._build()

    def _build(self):
        # canonical：A/B eligible，X excluded
        samples = []
        for c in self.cves:
            s = {"sample_id": c, "eligible": True}
            for side in ("vuln", "fixed"):
                t = sha(f"{c}{side}")
                self.tree[(c, side)] = t
                s[f"{side}_tree_sha256_lf"] = t
            samples.append(s)
        for c in self.excluded:
            samples.append({"sample_id": c, "eligible": False,
                            "exclusion_reason": heq.EXCLUDED[c]})
        self.canon = self.td / "canonical.json"
        self.canon.write_text(json.dumps({"samples": samples}), encoding="utf-8")

        # 历史 raw + results（6 条：3 CVE × 2 side）
        self.raw = self.td / "raw.jsonl"
        self.results = self.td / "results.csv"
        raw_rows = []
        res_rows = []
        i = 0
        for c in self.cves + self.excluded:
            for side in ("vuln", "fixed"):
                raw_rows.append({"cve_id": c, "mode": "code",
                                 "prompt": mk_prompt(c, "CWE-022", code=f"code_{c}_{side}")})
                res_rows.append({"sample_id": c, "version": side, "mode": "code",
                                 "scorer": "LocalLLMScorer"})
                i += 1
        self.raw.write_text("\n".join(json.dumps(r) for r in raw_rows) + "\n",
                            encoding="utf-8")
        with self.results.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(res_rows[0].keys()))
            w.writeheader()
            w.writerows(res_rows)

        # 重生成 manifest：与历史 prompt 完全相同（默认等价）
        self.regen_dir = self.td / "regen"
        self.regen_dir.mkdir(exist_ok=True)
        self._write_regen(same_as_history=True)

    def _write_regen(self, same_as_history=True, corrupt_sha=False):
        recs = []
        for c in self.cves:
            for side in ("vuln", "fixed"):
                txt = (mk_prompt(c, "CWE-022", code=f"code_{c}_{side}")
                       if same_as_history
                       else mk_prompt(c, "CWE-022", code="DIFFERENT"))
                p = self.prompts / f"{c}_{side}.prompt.txt"
                p.write_text(txt, encoding="utf-8")
                recs.append({
                    "sample_id": c, "side": side, "arm": "real",
                    "prompt_path": f"../prompts/{c}_{side}.prompt.txt",
                    "prompt_sha256": ("0" * 64) if corrupt_sha else sha(txt),
                    "representation": "legacy-rq1-r0",
                    "source_tree_sha256": self.tree[(c, side)],
                    "cpg_bundle_sha256": "e" * 64,
                })
        self.regen = self.regen_dir / "prompt_manifest.jsonl"
        self.regen.write_text("\n".join(json.dumps(r) for r in recs) + "\n",
                              encoding="utf-8")

    def argv(self, hist_src=True):
        a = ["--expect-historical", str(self.n_rows),
             "--raw", str(self.raw), "--results", str(self.results),
             "--regenerated-manifest", str(self.regen),
             "--canonical-manifest", str(self.canon),
             "--out", str(self.td / "out.jsonl"),
             "--summary", str(self.td / "summary.json")]
        if hist_src:
            # 历史树证据：A/B 两侧 == canonical（UNCHANGED）
            p = self.td / "hist_src.jsonl"
            rows = [{"sample_id": c, "side": s, "tree_sha256_lf": self.tree[(c, s)]}
                    for c in self.cves for s in ("vuln", "fixed")]
            p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
            a += ["--historical-source", str(p)]
        else:
            a += ["--historical-source", str(self.td / "nonexistent.jsonl")]
        return a


class TestEquivalenceGate(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.fx = Fixture(Path(self._td.name))

    def tearDown(self):
        self._td.cleanup()

    def test_01_raw_results_count_mismatch_fails(self):
        rows = [json.loads(l) for l in
                self.fx.raw.read_text(encoding="utf-8").splitlines() if l.strip()]
        self.fx.raw.write_text("\n".join(json.dumps(r) for r in rows[:-1]) + "\n",
                               encoding="utf-8")
        with self.assertRaises(RuntimeError):
            heq.load_historical_index(self.fx.raw, self.fx.results, self.fx.n_rows)

    def test_02_cve_mismatch_fails(self):
        rows = [json.loads(l) for l in
                self.fx.raw.read_text(encoding="utf-8").splitlines() if l.strip()]
        rows[1]["cve_id"] = "CVE-WRONG"
        self.fx.raw.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                               encoding="utf-8")
        with self.assertRaises(RuntimeError):
            heq.load_historical_index(self.fx.raw, self.fx.results, self.fx.n_rows)

    def test_03_duplicate_key_fails(self):
        rows = [json.loads(l) for l in
                self.fx.raw.read_text(encoding="utf-8").splitlines() if l.strip()]
        rows[1] = dict(rows[0])
        self.fx.raw.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                               encoding="utf-8")
        # 同时把 results 第 1 行 side 改为 vuln，使 (CVE-A, vuln, code) 真正重复
        res = list(csv.DictReader(self.fx.results.read_text(encoding="utf-8").splitlines()))
        res[1]["version"] = "vuln"
        with self.fx.results.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(res[0].keys()))
            w.writeheader()
            w.writerows(res)
        with self.assertRaises(RuntimeError):
            heq.load_historical_index(self.fx.raw, self.fx.results, self.fx.n_rows)

    def test_04_invalid_side_fails(self):
        with self.fx.results.open("w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["sample_id", "version", "mode", "scorer"])
            w.writeheader()
            for i in range(6):
                w.writerow({"sample_id": "CVE-A", "version": "bogus",
                            "mode": "code", "scorer": "LocalLLMScorer"})
        with self.assertRaises(RuntimeError):
            heq.load_historical_index(self.fx.raw, self.fx.results, self.fx.n_rows)

    def test_05_regen_prompt_sha_drift_fails(self):
        self.fx._write_regen(same_as_history=True, corrupt_sha=True)
        self.assertEqual(heq.main(self.fx.argv()), 2)

    def test_06_unchanged_prompt_mismatch_fails(self):
        self.fx._write_regen(same_as_history=False)
        rc = heq.main(self.fx.argv())
        self.assertNotEqual(rc, 0, "UNCHANGED 源码下 prompt 不等价必须 FAIL")
        s = json.loads((Path(self._td.name) / "summary.json").read_text(encoding="utf-8"))
        self.assertFalse(s["gate_pass"])

    def test_07_changed_allows_mismatch_but_records(self):
        # 历史树证据给一个不同的值 → CHANGED
        p = Path(self._td.name) / "hist_changed.jsonl"
        rows = [{"sample_id": c, "side": s, "tree_sha256_lf": "f" * 64}
                for c in self.fx.cves for s in ("vuln", "fixed")]
        p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        self.fx._write_regen(same_as_history=False)
        argv = self.fx.argv()
        argv[argv.index("--historical-source") + 1] = str(p)
        rc = heq.main(argv)
        self.assertEqual(rc, 0, "CHANGED 侧不要求相等，Gate 应 PASS")
        s = json.loads((Path(self._td.name) / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(s["changed_total"], 4)
        self.assertEqual(s["unchanged_total"], 0)

    def test_08_unknown_not_in_denominator(self):
        argv = self.fx.argv(hist_src=False)  # 无历史证据 → UNKNOWN
        rc = heq.main(argv)
        self.assertEqual(rc, 0)
        s = json.loads((Path(self._td.name) / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(s["unknown_total"], 4)
        self.assertEqual(s["unchanged_total"], 0)
        self.assertEqual(s["unchanged_exact_match"], 0)

    def test_09_excluded_records_listed(self):
        rc = heq.main(self.fx.argv())
        rows = [json.loads(l) for l in
                (Path(self._td.name) / "out.jsonl").read_text(encoding="utf-8").splitlines()
                if l.strip()]
        exc = [r for r in rows if "exclusion_reason" in r]
        self.assertEqual(len(exc), 6, "被排除 3 个 CVE 的 6 份历史 prompt 必须单列")
        self.assertTrue(all(r["exclusion_reason"] for r in exc))

    def test_10_identical_prompts_gate_passes(self):
        rc = heq.main(self.fx.argv())
        s = json.loads((Path(self._td.name) / "summary.json").read_text(encoding="utf-8"))
        self.assertEqual(rc, 0)
        self.assertEqual(s["unchanged_exact_match"], s["unchanged_total"])
        self.assertTrue(s["gate_pass"])


if __name__ == "__main__":
    unittest.main()
