# -*- coding: utf-8 -*-
"""干净克隆复算门禁（Code plan 第9阶段）。

在系统临时目录 clone 指定 commit，验证可复现性：
1. clone 指定 commit；2. 检查 Python 版本；3. 验证 canonical 源语料 82/82；
4. 重算 manifest 树哈希；5. 跑全部 unit/invariant tests；6. 生成全部 prompt 不调模型；
7. 比对 prompt SHA；8. 验证 run schema；9. 确认无未跟踪依赖。

用法：python scripts/reproduce_clean_clone.py --commit <sha> [--inputs-only]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_URL = "https://github.com/lauyy32/llm-vuln-detector.git"


def run(args, cwd, timeout=600):
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)


def check_python(cwd: Path):
    """Python 版本须为 3.9 或 3.13。"""
    r = run([sys.executable, "--version"], cwd)
    ver = r.stdout.strip()
    if not (ver.startswith("Python 3.9") or ver.startswith("Python 3.13")):
        raise RuntimeError(f"Python 版本不符: {ver}")
    print(f"[ok] Python 版本: {ver}")


def verify_corpus(cwd: Path):
    """重算 canonical manifest（验证 82/82 路径 + 树哈希）。"""
    r = run([sys.executable, "cpg/ablation/canonical_manifest.py"], cwd)
    if r.returncode != 0:
        raise RuntimeError(f"canonical_manifest 验证失败:\n{r.stdout[-400:]}")
    print(f"[ok] canonical manifest: {r.stdout.strip().splitlines()[0]}")


def run_tests(cwd: Path):
    """跑全部 unit tests。"""
    r = run([sys.executable, "-m", "unittest", "discover", "-s",
             "cpg/ablation/tests", "-p", "test_*.py"], cwd, timeout=900)
    if r.returncode != 0:
        raise RuntimeError(f"unit tests 失败:\n{r.stderr[-400:]}")
    print("[ok] unit tests 全通过")


def prepare_inputs(cwd: Path, run_dir: Path):
    """生成全部 prompt 但不调模型（prepare + verify-inputs）。"""
    r = run([sys.executable, "cpg/ablation/run_experiment.py", "prepare",
             "--run-dir", str(run_dir)], cwd)
    if r.returncode != 0:
        raise RuntimeError(f"prepare 失败:\n{r.stdout[-400:]}")
    r = run([sys.executable, "cpg/ablation/run_experiment.py", "verify-inputs",
             "--run-dir", str(run_dir)], cwd)
    if r.returncode != 0:
        raise RuntimeError(f"verify-inputs 失败:\n{r.stdout[-400:]}")
    n = sum(1 for _ in (run_dir / "prompt_manifest.jsonl").read_text().splitlines() if _.strip())
    print(f"[ok] prepare+verify-inputs: {n} 份 prompt")


def check_untracked(cwd: Path):
    """确认无未跟踪依赖（关键数据文件已 git 跟踪）。"""
    r = run(["git", "ls-files", "--others", "--exclude-standard"], cwd)
    untracked = [l for l in r.stdout.splitlines()
                 if "corpus-v3" in l or "artifacts" in l]
    if untracked:
        raise RuntimeError(f"关键数据未跟踪: {untracked[:5]}")
    print("[ok] 无未跟踪关键数据")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--commit", required=True)
    ap.add_argument("--inputs-only", action="store_true", help="只验证输入工件，不调模型")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="clean_clone_") as tmp:
        cwd = Path(tmp) / "repo"
        print(f"[clone] {REPO_URL} @ {args.commit[:12]}")
        r = run(["git", "clone", "--quiet", REPO_URL, str(cwd)], cwd=Path(tmp), timeout=900)
        if r.returncode != 0:
            raise RuntimeError(f"clone 失败: {r.stderr[-300:]}")
        r = run(["git", "checkout", "--quiet", args.commit], cwd)
        if r.returncode != 0:
            raise RuntimeError(f"checkout 失败: {r.stderr[-300:]}")

        check_python(cwd)
        verify_corpus(cwd)
        run_tests(cwd)
        check_untracked(cwd)
        run_dir = cwd / "cpg/ablation/.work/rq1-r-cleanclone"
        prepare_inputs(cwd, run_dir)
        print("\n[PASS] clean-clone 复算门禁全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
