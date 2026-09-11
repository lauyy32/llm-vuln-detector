# -*- coding: utf-8 -*-
"""受控 apply runner：**真实执行** `git apply`，产出不可由调用者手填的执行记录。

评审 5 的 P0-2：旧 `make_pair_candidate` 只是把调用者提供的 `command` / stdout 与
冻结的 runner SHA 拼进一个 dataclass，既不执行也不捕获，硬编码 `exit_code=0` ——
只能证明「记录内部自洽」，不能证明 patch 真的应用过、post 目录真的由该次执行产生。

本模块把 apply 变成一次**真实执行**：
  1. 在 `base_dir/<workroot>/<run_id>/` 建唯一工作目录（run_id = 随机 token）；
  2. 把目标树**复制**进去，重算复制后的 tree SHA 作为 `before`；
  3. 真实调用 `git apply`（`subprocess.run`，参数列表、不经 shell），
     捕获 `command` / `exit_code` / stdout / stderr，并各自**落盘为工件**；
  4. 重算 `after` tree SHA；
  5. 写 `record.json`，返回含 stdout/stderr **工件路径**的完整执行记录。

调用者无法指定 exit_code、stdout 或 post-apply 内容；这些只能由真实执行得到。
记录中的 `runner_sha256` 是本模块（LF 归一化）实现 SHA，冻结点写入
`FrozenRuntime.apply_runner_sha256`，从而把「哪份 runner」也钉死。
"""
from __future__ import annotations

import json
import secrets
import shutil
import subprocess
from pathlib import Path

import hashlib

RUNNER_SCHEMA = "v4-apply-runner/1"
GIT_APPLY_EXTRA_ARGS = ("-p1", "--verbose")
WORKROOT_DEFAULT = ".apply"


def _sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def write_text_lf(path, text: str) -> None:
    """以 UTF-8 + **LF** 写文本。

    `Path.write_text(newline=...)` 自 Python 3.10 起才提供，本仓下限为 3.9，
    故统一改用 `open(..., newline="\\n")`，避免双解释器门禁失效。
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def apply_runner_sha256() -> str:
    """本 runner 的**实现 SHA**（LF 归一化）：冻结时写入 `FrozenRuntime`。"""
    src = Path(__file__).read_bytes().decode("utf-8")
    return _sha_bytes(src.replace("\r\n", "\n").encode("utf-8"))


def run_apply(*, base_dir, target_tree_dir: str, donor_patch_path: str,
              workroot_rel: str = WORKROOT_DEFAULT) -> dict:
    """真实执行一次 `git apply`，返回执行记录（路径均相对 `base_dir`）。

    失败（`git apply` 非零退出、目标树/补丁缺失）**不吞掉**：调用者据
    `exit_code` 判定；本函数自身只在输入缺失时抛异常。
    """
    base = Path(base_dir)
    src_tree = base / target_tree_dir
    patch = base / donor_patch_path
    if not src_tree.is_dir():
        raise FileNotFoundError(f"目标树不存在: {target_tree_dir}")
    if not patch.is_file():
        raise FileNotFoundError(f"donor patch 不存在: {donor_patch_path}")

    workroot = base / workroot_rel
    workroot.mkdir(parents=True, exist_ok=True)
    run_id = secrets.token_hex(8)
    workdir = workroot / run_id
    workdir.mkdir(parents=True, exist_ok=False)

    tree = workdir / "tree"
    shutil.copytree(src_tree, tree)                 # 每轮独立拷贝，杜绝串库

    def _tree_sha() -> str:
        from cpg.ablation.v4_arms import normalized_tree_sha256
        return normalized_tree_sha256(tree)

    before = _tree_sha()

    local_patch = workdir / "donor.patch"           # 字节复制，锁定被应用的补丁
    shutil.copyfile(patch, local_patch)
    patch_sha = _sha_bytes(local_patch.read_bytes())

    argv = ["git", "apply", *GIT_APPLY_EXTRA_ARGS, str(local_patch)]
    proc = subprocess.run(argv, cwd=str(tree), capture_output=True,
                          text=True, errors="replace", shell=False)

    write_text_lf(workdir / "apply.stdout", proc.stdout or "")
    write_text_lf(workdir / "apply.stderr", proc.stderr or "")
    after = _tree_sha()

    def rel(p: Path) -> str:
        return p.relative_to(base).as_posix()

    record = {
        "schema": RUNNER_SCHEMA,
        "runner_sha256": apply_runner_sha256(),
        "workdir_id": run_id,
        "command": " ".join(argv),
        "argv": argv,
        "exit_code": proc.returncode,
        "stdout_path": rel(workdir / "apply.stdout"),
        "stdout_sha256": _sha_bytes((proc.stdout or "").encode("utf-8")),
        "stderr_path": rel(workdir / "apply.stderr"),
        "stderr_sha256": _sha_bytes((proc.stderr or "").encode("utf-8")),
        "target_tree_sha256": before,
        "post_apply_tree_sha256": after,
        "patch_sha256": patch_sha,
        "post_apply_tree_dir": rel(tree),
        "workdir_rel": rel(workdir),
    }
    write_text_lf(workdir / "record.json",
                  json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True))
    return record
