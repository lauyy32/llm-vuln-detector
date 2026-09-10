# -*- coding: utf-8 -*-
"""通用批量实验 runner（Code plan 第7阶段）。

状态机：CREATED → INPUTS_FROZEN → RUNNING → COMPLETE → VERIFIED；任何失败 → FAILED。
子命令：prepare / verify-inputs / invoke / verify-results / summarize。

- 只接受 --protocol / --canonical-manifest / --run-dir（不接受人工 --exclude-cves）；
- prepare 生成全部 prompt 并冻结 SHA + 固定 seed 打乱调用顺序写入 run_schedule；
- 全部 prompt 冻结后才可 invoke；运行期间不打印单项 verdict；
- resume 支持，但唯一键 (sample_id, side, arm, repeat) 重复即失败；
- 结果完成后再 summarize，不边看结果边改。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from cpg.ablation import excerpt_plan  # noqa: E402
from cpg.ablation import prompt_renderer  # noqa: E402
from cpg.ablation import config  # noqa: E402
from cpg.ablation import corpus_db  # noqa: E402
from cpg.ablation import cpg_eval  # noqa: E402
from cpg.ablation.cpg_eval import (  # noqa: E402
    build_cpg_slices_text, sort_taint_rows_canonical, canonical_cpg_rows_sha,
)
from cpg.ablation import legacy_rq1_r0  # noqa: E402
from cpg.ablation import legacy_rq1_r1_cpg_canonical  # noqa: E402
from cpg.ablation import model_client  # noqa: E402
from cpg.ablation.legacy_rq1_r0 import (  # noqa: E402
    REPRESENTATION as LEGACY_REPR, MAX_CODE_CHARS, SUMMARY,
    load_legacy_code_text, preflight_legacy,
)
from cpg.ablation.excerpt_plan import REPRESENTATION as CHANGED_HUNK_REPR  # noqa: E402
from cpg.ablation.model_client import ModelClient, MODEL, MODEL_DIGEST, NUM_CTX, NUM_PREDICT, TEMPERATURE, TOP_P, SEED, OLLAMA_VERSION  # noqa: E402

# 允许用于 RQ1-R prompt 生成的表示（选 C 裁决 + 确定性行序补正案）：
# - legacy-rq1-r0：历史基线重跑（冻结表示）；
# - legacy-rq1-r1-cpg-canonical：消除 CPG 流顺序非确定后的新实验表示（新表示另立版本）。
# changed-hunk-r0 是改进摘录器，按 Experiment design §二.2 不得混入 RQ1-R，
# 因此不列入允许集（它仅用于独立覆盖审计 / future V4）。
CANONICAL_REPR = legacy_rq1_r1_cpg_canonical.REPRESENTATION
ALLOWED_REPRESENTATIONS = {LEGACY_REPR, CANONICAL_REPR}
assert CHANGED_HUNK_REPR not in ALLOWED_REPRESENTATIONS

STATES = ("CREATED", "INPUTS_FROZEN", "INPUTS_VERIFIED", "INPUTS_LOCKED",
          "REVIEW_LOCKED", "RUNNING", "RETRY_REQUIRED", "COMPLETE", "VERIFIED",
          "FAILED")

# 合法 verdict 枚举（P0-2：verify-results fail-closed 用）
VALID_VERDICTS = {"vulnerable", "benign", "abstain"}

# RUN_LOCK 必须精确绑定的五类文件键（P0-1：多/缺任一即失败）
LOCKED_FILE_KEYS = ("canonical_manifest", "protocol", "prompt_manifest",
                    "run_schedule", "cpg_bundle")


def _sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


# 渲染器插入的结构性 code 围栏开头（与 prompt_renderer.render_prompt 内联一致）。
# 用于 verify-inputs 的结构检查：不能数 ``` 总数（源代码 docstring 可能含 markdown
# 代码块 ```python ... ```，会误报 fence 数 != 2）。
CODE_START = "\n# 目标代码（节选）\n```\n"


# 参与逐条比对的指纹键（git_commit 仅记录，不参与比对）
FINGERPRINT_KEYS = ("representation_sha256", "prompt_renderer_sha256", "system_sha256")
# canonical 表示额外冻结 cpg_eval（canonical 行序实现所在）
CANONICAL_FINGERPRINT_KEYS = FINGERPRINT_KEYS + ("cpg_eval_sha256",)


def _fingerprint_keys(representation: str | None) -> tuple[str, ...]:
    """按表示返回参与比对的指纹键。canonical 表示多冻结 cpg_eval 实现。"""
    if representation == CANONICAL_REPR:
        return CANONICAL_FINGERPRINT_KEYS
    return FINGERPRINT_KEYS


def _file_sha256(path: Path) -> str:
    """LF 规范化后 SHA-256：避免 Windows CRLF / Linux LF 导致同内容不同哈希。"""
    b = Path(path).read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    return hashlib.sha256(b).hexdigest()


def _git_commit() -> str | None:
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception:
        return None


def representation_fingerprints(representation: str | None = None) -> dict:
    """表示实现的指纹：同一 representation 名称下改代码会被检出。

    冻结表示模块、prompt_renderer 与 SYSTEM 文本（LF 规范化），并附记 git commit。
    canonical 表示额外冻结 cpg_eval.py（canonical 行序实现所在）。
    """
    fp = {
        "prompt_renderer_sha256": _file_sha256(Path(prompt_renderer.__file__)),
        "system_sha256": _sha256_text(prompt_renderer.SYSTEM),
        "git_commit": _git_commit(),
    }
    if representation == CANONICAL_REPR:
        fp["representation_sha256"] = _file_sha256(
            Path(legacy_rq1_r1_cpg_canonical.__file__))
        fp["cpg_eval_sha256"] = _file_sha256(Path(cpg_eval.__file__))
    else:
        fp["representation_sha256"] = _file_sha256(Path(legacy_rq1_r0.__file__))
    return fp


def _read_state(run_dir: Path) -> str:
    p = run_dir / "state.json"
    if not p.exists():
        return "CREATED"
    return json.loads(p.read_text(encoding="utf-8")).get("state", "CREATED")


def _write_state(run_dir: Path, state: str, extra: dict | None = None):
    """写状态。合并既有字段（保留 lock_request_sha256/reviewer 等持久字段），只改 state。"""
    run_dir.mkdir(parents=True, exist_ok=True)
    p = run_dir / "state.json"
    d = {}
    if p.exists():
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            d = {}
    d["state"] = state
    if extra:
        d.update(extra)
    p.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")


def _fail(run_dir: Path, msg: str):
    _write_state(run_dir, "FAILED", {"error": msg})
    print(f"[FAIL] {msg}")
    return 1


def _reject(msg: str):
    """非变异拒绝：状态机预条件不满足时只报错不改状态（P0-1）。

    用于"当前状态不允许执行该命令"类拒绝，不得污染合法等待态
    （如 INPUTS_LOCKED 等待 reviewer 签字、REVIEW_LOCKED 等待 invoke）。
    """
    print(f"[REJECT] {msg}")
    return 1


def _pid_alive(pid: int) -> bool:
    """Windows 下检测进程是否存活（tasklist）。无法判断时保守返回 True（防并发优先）。"""
    try:
        r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                           capture_output=True, text=True, timeout=10)
        return str(pid) in r.stdout
    except Exception:
        return True


def _acquire_lease(run_dir: Path) -> tuple[str | None, str | None]:
    """原子获取 invoke 独占租约（防并发）。返回 (lease_id, error)。

    用 ``O_CREAT|O_EXCL`` 原子创建，消除 check-then-write 竞争窗口（P0-2）。
    中断残留租约若 pid 已死则清理后重试；lease_id 用于释放时校验所有权。
    """
    lease_path = run_dir / "invoke.lease"
    for _ in range(2):  # 一次正常尝试 + 一次清理过期后重试
        lease_id = uuid.uuid4().hex
        try:
            fd = os.open(str(lease_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                lease = json.loads(lease_path.read_text(encoding="utf-8"))
                pid = lease.get("pid")
                if pid and _pid_alive(int(pid)):
                    return None, f"invoke 已有活跃租约（pid={pid}），拒绝并发"
            except (json.JSONDecodeError, ValueError, OSError):
                pass
            try:
                lease_path.unlink()  # 已死或损坏 → 清理后重试
            except OSError:
                return None, "invoke 租约清理失败（可能并发占用）"
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "lease_id": lease_id,
                       "started_at": time.time()}, f)
        return lease_id, None
    return None, "invoke 租约竞争失败（重试后仍被占用）"


def _release_lease(run_dir: Path, lease_id: str | None) -> None:
    """释放租约：仅当租约属于自己（lease_id 匹配）才删除，避免误删他人租约。"""
    if not lease_id:
        return
    lease_path = run_dir / "invoke.lease"
    try:
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        if lease.get("lease_id") == lease_id:
            lease_path.unlink()
    except (json.JSONDecodeError, OSError):
        pass


def load_canonical(manifest_path: Path) -> dict:
    return json.loads(manifest_path.read_text(encoding="utf-8"))


def prepare(args) -> int:
    """生成 82×2 prompt + 冻结 SHA + run_schedule。CREATED → INPUTS_FROZEN。"""
    run_dir = args.run_dir
    if _read_state(run_dir) not in ("CREATED", "FAILED"):
        return _reject(f"prepare 要求 CREATED，当前 {_read_state(run_dir)}")
    manifest = load_canonical(args.canonical_manifest)
    if manifest.get("errors"):
        return _fail(run_dir, f"canonical manifest 有验证错误: {manifest['errors'][:3]}")
    eligible = [s for s in manifest["samples"] if s.get("eligible")]
    if len(eligible) != manifest.get("eligible_total"):
        return _fail(run_dir, f"eligible 计数不符 {len(eligible)} != {manifest['eligible_total']}")

    # 协议：冻结摘录表示 + 模型参数。
    # representation 必须显式指定；changed-hunk-r0 不得作为默认值，
    # 且不得用于 RQ1-R prompt 生成（仅覆盖审计 / future V4）。
    representation = getattr(args, "representation", None)
    if representation not in ALLOWED_REPRESENTATIONS:
        return _fail(run_dir, f"必须显式指定 representation，取值 "
                              f"{sorted(ALLOWED_REPRESENTATIONS)}，实际 {representation!r}")
    protocol = {
        "model": MODEL, "model_digest": MODEL_DIGEST,
        "num_ctx": NUM_CTX, "num_predict": NUM_PREDICT,
        "temperature": TEMPERATURE, "top_p": TOP_P, "seed": SEED,
        "ollama_version": OLLAMA_VERSION,
        "representation": representation,
        "summary": SUMMARY,
        "max_code_chars": MAX_CODE_CHARS,
    }
    protocol.update(representation_fingerprints(representation))  # 绑实现 SHA，改代码即漂移

    # P1：冻结运行时版本，实际不符即 fail-closed（digest 相同不保证 runtime 行为一致）
    actual_ov = model_client.ollama_version_number()
    if actual_ov != OLLAMA_VERSION:
        return _fail(run_dir, f"Ollama 版本不符: 实际 {actual_ov} != 冻结 {OLLAMA_VERSION}")

    prompts_dir = run_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)

    # 接 CPG 链：stage 82 例 → 建库 → 跑 7 个 taint 查询（P0-2 修复，不再是纯源码）
    staging_dir = run_dir / "staging"
    staged = corpus_db.stage_exact_snapshot(manifest, staging_dir)
    query_files = [config.QUERIES_DIR / f"{qbase}.ql"
                   for _cwe, qbase in config.CWE_TAINT_QUERIES
                   if (config.QUERIES_DIR / f"{qbase}.ql").exists()]
    qsha = corpus_db.query_set_sha(query_files)
    cid = corpus_db.codeql_identity()
    db_path = staging_dir / "corpus_db"
    bundle = corpus_db.build_or_reuse_db(
        staged["staged_manifest_sha256"], qsha, cid, staging_dir, query_files, db_path)
    taint_rows = bundle.get("taint_rows", [])
    # cpg_cache_key 是输入身份（staged+query+CodeQL identity 的 cache key），
    # 不是 CPG 输出或 cpg_bundle.json 文件的 SHA（P0-3 命名纠正）。
    cpg_cache_key = bundle["cache_key"]
    # canonical_cpg_rows_sha256 才是"实际 CPG 输出内容"的规范身份（abs_path 已相对化）。
    canonical_rows_sha = canonical_cpg_rows_sha(taint_rows)
    (run_dir / "cpg_bundle.json").write_text(
        json.dumps({"cpg_cache_key": cpg_cache_key,
                    "codeql_version": cid,
                    "query_set_sha256": qsha,
                    "staged_manifest_sha256": staged["staged_manifest_sha256"],
                    "canonical_cpg_rows_sha256": canonical_rows_sha,
                    "queries": bundle.get("queries", []),
                    "n_taint_rows": len(taint_rows)},
                   ensure_ascii=False, indent=2), encoding="utf-8")
    # CPG provenance 纳入 protocol（P0-3：此前只写进 cpg_bundle.json，未被锁定/复核）
    protocol.update({
        "cpg_cache_key": cpg_cache_key,
        "query_set_sha256": qsha,
        "staged_manifest_sha256": staged["staged_manifest_sha256"],
        "canonical_cpg_rows_sha256": canonical_rows_sha,
    })

    prompt_manifest = []
    for s in eligible:
        cve = s["sample_id"]
        for side in ("vuln", "fixed"):
            # legacy-rq1-r0：用 staging 源（taint_rows 的 abs_path 指向 staging，
            # 与 legacy 的 hit_paths 前缀匹配一致）；staging 由 canonical manifest
            # 复制而来，树哈希需与 canonical 一致（preflight fail-closed）。
            # 必须 resolve()：taint 行的 abs_path 是绝对路径，相对路径会导致
            # legacy 的 hit_paths 前缀匹配失败并退化为头 100 行。
            side_root = (staging_dir / "corpus_src" / f"{cve}_{side}").resolve()
            preflight_legacy(side_root, s.get(f"{side}_tree_sha256_lf"))
            rows_side = [r for r in taint_rows
                         if f"/{cve}_{side}/" in (r.get("abs_path") or "").replace("\\", "/")]
            # 注：实测表明历史 cpg_slices 保持 CodeQL CSV 原始返回顺序（非 (src,sink) 升序）。
            # 强行排序会让等价性从 144/145 降到 137/145，故此处不排序。
            code_text = load_legacy_code_text(side_root, rows_side)
            # 复刻历史 LocalLLMScorer._build_prompt 的 code_text[:8000] 二次截断
            code_text = code_text[:protocol["max_code_chars"]]
            # 按 prefix 过滤该样本该侧的 taint 行，生成 cpg_slices（空则显式 success-zero）。
            # r0：历史 cpg_slices 保持 CodeQL CSV 原始返回顺序（非 (src,sink) 升序）；
            #     强行排序会让等价性从 144/145 降到 137/145，故 r0 不排序。
            # r1（canonical）：结构化行层按稳定键排序，消除跨运行流顺序非确定。
            rows_for_slice = (sort_taint_rows_canonical(rows_side)
                              if representation == CANONICAL_REPR else rows_side)
            cpg_slices = build_cpg_slices_text(rows_for_slice, code_text)
            # 历史 pipeline 经 _primary_cwe() → config.normalize_cwe() 输出 3 位补零
            # （CWE-22 → CWE-022）。legacy-rq1-r0 必须复刻，否则 prompt 头即不等价。
            _cwes = s.get("cwes") if isinstance(s.get("cwes"), list) else None
            cwe_disp = config.normalize_cwe((_cwes or [None])[0])
            prompt = prompt_renderer.render_prompt(
                {"cve_id": cve, "cwe": cwe_disp},
                code_text, cpg_slices, summary=protocol["summary"],
                max_code_chars=protocol["max_code_chars"],
            )
            sha = _sha256_text(prompt)
            pout = prompts_dir / f"{cve}_{side}.prompt.txt"
            pout.write_text(prompt, encoding="utf-8")
            rec = {
                "sample_id": cve, "side": side, "arm": "real",
                "prompt_path": str(pout.relative_to(run_dir)),
                "prompt_sha256": sha,
                # legacy 表示无结构化 selection plan，记录摘录内容 SHA 与表示版本
                "representation": protocol["representation"],
                "code_text_sha256": _sha256_text(code_text),
                "source_tree_sha256": s.get(f"{side}_tree_sha256_lf"),
                "cpg_cache_key": cpg_cache_key,
                "canonical_cpg_rows_sha256": canonical_rows_sha,
                "cpg_taint_rows": len(rows_side),
                "cpg_slices_chars": len(cpg_slices),
            }
            for k in _fingerprint_keys(representation):
                rec[k] = protocol[k]
            prompt_manifest.append(rec)

    # 固定 seed 打乱调用顺序（vuln/fixed 交错）
    rng = random.Random(SEED)
    order = prompt_manifest[:]
    rng.shuffle(order)
    run_schedule = [{"sample_id": p["sample_id"], "side": p["side"], "arm": p["arm"]}
                    for p in order]

    (run_dir / "prompt_manifest.jsonl").write_text(
        "\n".join(json.dumps(p, ensure_ascii=False) for p in prompt_manifest) + "\n",
        encoding="utf-8")
    (run_dir / "run_schedule.json").write_text(
        json.dumps(run_schedule, ensure_ascii=False, indent=2), encoding="utf-8")
    (run_dir / "protocol.json").write_text(
        json.dumps(protocol, ensure_ascii=False, indent=2), encoding="utf-8")

    _write_state(run_dir, "INPUTS_FROZEN", {"n_prompts": len(prompt_manifest)})
    print(f"[prepare] {len(prompt_manifest)} 份 prompt 冻结，schedule 已写入")
    return 0


def verify_inputs(args) -> int:
    """验证输入工件：prompt SHA 一致 + 无摘要泄漏 + fence 正确。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "INPUTS_FROZEN":
        return _reject(f"verify-inputs 要求 INPUTS_FROZEN，当前 {_read_state(run_dir)}")
    manifest = []
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            manifest.append(json.loads(line))
    errors = []
    for p in manifest:
        prompt = (run_dir / p["prompt_path"]).read_text(encoding="utf-8")
        if _sha256_text(prompt) != p["prompt_sha256"]:
            errors.append(f"{p['sample_id']}/{p['side']} prompt SHA 漂移")
        if "公告摘要" in prompt:
            errors.append(f"{p['sample_id']}/{p['side']} 含公告摘要泄漏")
        if prompt.count(CODE_START) != 1:
            errors.append(f"{p['sample_id']}/{p['side']} code 围栏结构错误 "
                          f"（CODE_START 出现 {prompt.count(CODE_START)} 次）")
    if errors:
        return _fail(run_dir, f"verify-inputs {len(errors)} 错误: {errors[:3]}")
    # 完整完整性校验（指纹 / schedule 集合 / 重复键 / prompt SHA）通过后才写
    # INPUTS_VERIFIED，否则状态会在未全量验证时被错误标为"已验证"。
    errs2 = _verify_inputs_integrity(run_dir)
    if errs2:
        return _fail(run_dir, f"verify-inputs 完整性校验失败（{len(errs2)} 项）: {errs2[:3]}")
    _write_state(run_dir, "INPUTS_VERIFIED", {"n_prompts": len(manifest)})
    print(f"[verify-inputs] PASS {len(manifest)} 份 prompt 验证通过 → INPUTS_VERIFIED")
    return 0


def _verify_inputs_integrity(run_dir: Path) -> list:
    """invoke 前独立复核（不能只信先前验证）：prompt SHA、指纹、schedule 一致性、重复键。"""
    errors = []
    manifest = []
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            manifest.append(json.loads(line))
    prot = json.loads((run_dir / "protocol.json").read_text(encoding="utf-8"))
    representation = prot.get("representation")
    fp_now = representation_fingerprints(representation)
    fp_keys = _fingerprint_keys(representation)
    seen = set()
    for p in manifest:
        key = (p["sample_id"], p["side"], p.get("arm"))
        if key in seen:
            errors.append(f"prompt manifest 重复键: {key}")
        seen.add(key)
        # 重新计算磁盘 prompt 的 SHA，必须与冻结值一致
        pp = run_dir / p["prompt_path"]
        if not pp.exists():
            errors.append(f"{key} prompt 文件缺失: {pp}")
            continue
        actual = _sha256_text(pp.read_text(encoding="utf-8"))
        if actual != p.get("prompt_sha256"):
            errors.append(f"{key} prompt SHA 漂移: 磁盘 {actual[:12]} != 冻结 "
                          f"{str(p.get('prompt_sha256'))[:12]}")
        # 每条记录的指纹必须与 protocol 及当前实现一致（git_commit 不参与比对）
        for k in fp_keys:
            v = fp_now[k]
            if p.get(k) != v:
                errors.append(f"{key} 指纹 {k} 与当前实现不一致")
            if prot.get(k) != v:
                errors.append(f"{key} 指纹 {k} 与 protocol 不一致")
    # schedule 与 manifest 集合必须一致；重复项必须先于任何模型调用检出
    # （不得先转 set，否则重复被去重，直到一次调用写入后才暴露）
    sched_list = json.loads((run_dir / "run_schedule.json").read_text(encoding="utf-8"))
    sched_keys = [(s["sample_id"], s["side"], s.get("arm")) for s in sched_list]
    if len(sched_keys) != len(set(sched_keys)):
        dup = [k for k in set(sched_keys) if sched_keys.count(k) > 1]
        errors.append(f"run_schedule 存在重复键: {sorted(dup)[:3]}")
    if set(sched_keys) != seen:
        errors.append(f"schedule 与 manifest 集合不一致: "
                      f"sched-only={sorted(set(sched_keys) - seen)[:3]} "
                      f"manifest-only={sorted(seen - set(sched_keys))[:3]}")
    return errors


def _locked_files(args, run_dir: Path) -> dict:
    """lock 绑定的文件清单（相对路径 + SHA，跨机器可复现，P0 第5点）。

    canonical_manifest 相对仓库根（base=repo），其余相对 run_dir（base=run）。
    """
    canonical = Path(args.canonical_manifest).resolve()
    files = {
        "canonical_manifest": ("repo", canonical.relative_to(ROOT).as_posix(), canonical),
        "protocol": ("run", "protocol.json", (run_dir / "protocol.json").resolve()),
        "prompt_manifest": ("run", "prompt_manifest.jsonl", (run_dir / "prompt_manifest.jsonl").resolve()),
        "run_schedule": ("run", "run_schedule.json", (run_dir / "run_schedule.json").resolve()),
        "cpg_bundle": ("run", "cpg_bundle.json", (run_dir / "cpg_bundle.json").resolve()),
    }
    out = {}
    for name, (base, rel, abspath) in files.items():
        if not abspath.exists():
            raise RuntimeError(f"[lock] 待锁定文件缺失: {name} -> {abspath}")
        out[name] = {"base": base, "path": rel, "sha256": _file_sha256(abspath)}
    return out


def _resolve_lock_path(run_dir: Path, f: dict) -> Path:
    """把锁文件条目解析为绝对路径（base=repo 相对 ROOT，base=run 相对 run_dir）。"""
    base = f.get("base", "run")
    if base == "repo":
        return (ROOT / f["path"]).resolve()
    return (run_dir / f["path"]).resolve()


def _lock_request_sha(run_dir: Path) -> str:
    """lock_request.json 磁盘原始文本的 SHA（所有引用点统一口径）。"""
    return _sha256_text((run_dir / "lock_request.json").read_text(encoding="utf-8"))


def lock_inputs(args) -> int:
    """生成 lock_request.json 并写 INPUTS_LOCKED（不自行签字，P0-2 第一阶段）。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "INPUTS_VERIFIED":
        return _reject(f"lock-inputs 要求 INPUTS_VERIFIED（须先跑 verify-inputs），"
                       f"当前 {_read_state(run_dir)}")
    errs = _verify_inputs_integrity(run_dir)
    if errs:
        return _fail(run_dir, f"lock-inputs 完整性校验失败（{len(errs)} 项）: {errs[:3]}")
    from datetime import datetime, timezone
    lock = {
        "state": "INPUTS_LOCKED",
        "locked_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "files": _locked_files(args, run_dir),
    }
    lock_text = json.dumps(lock, ensure_ascii=False, indent=2)
    (run_dir / "lock_request.json").write_text(lock_text + "\n", encoding="utf-8")
    _write_state(run_dir, "INPUTS_LOCKED", {"lock_request_sha256": _lock_request_sha(run_dir)})
    print(f"[lock-inputs] INPUTS_LOCKED，lock_request.json 已绑定 "
          f"{len(lock['files'])} 个文件（待 reviewer approve-lock）")
    return 0


def approve_lock(args) -> int:
    """reviewer 签字：校验 lock_request 后生成 review_approval.json → REVIEW_LOCKED。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "INPUTS_LOCKED":
        return _reject(f"approve-lock 要求 INPUTS_LOCKED（须先跑 lock-inputs），"
                       f"当前 {_read_state(run_dir)}")
    reviewer = getattr(args, "reviewer", None)
    if not reviewer:
        return _reject("approve-lock 必须指定 --reviewer（签字人身份）")
    # 签字前复核 lock_request 本身（文件 SHA 未漂移 + schema 严格）
    errs = _verify_lock_request(run_dir)
    if errs:
        return _fail(run_dir, f"approve-lock 复核 lock_request 失败: {errs[:3]}")
    from datetime import datetime, timezone
    approval = {
        "reviewer": reviewer,
        "decision": "APPROVED",
        "lock_request_sha256": _lock_request_sha(run_dir),
        "reviewed_git_commit": _git_commit(),
        "approved_at": datetime.now(timezone.utc).isoformat(),
    }
    (run_dir / "review_approval.json").write_text(
        json.dumps(approval, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    _write_state(run_dir, "REVIEW_LOCKED",
                 {"lock_request_sha256": approval["lock_request_sha256"],
                  "reviewer": reviewer})
    print(f"[approve-lock] REVIEW_LOCKED，reviewer={reviewer} 已签字")
    return 0


def _verify_lock_request(run_dir: Path) -> list:
    """严格校验 lock_request.json：state、files 精确 5 项、SHA、git commit。"""
    lock_path = run_dir / "lock_request.json"
    if not lock_path.exists():
        return ["lock_request.json 缺失（须先跑 lock-inputs）"]
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"lock_request.json 解析失败: {e}"]
    errors = []
    if lock.get("state") != "INPUTS_LOCKED":
        errors.append(f"lock state != INPUTS_LOCKED: {lock.get('state')!r}")
    if lock.get("git_commit") != _git_commit():
        errors.append(f"lock git_commit {lock.get('git_commit')} != HEAD {_git_commit()}")
    files = lock.get("files") or {}
    if set(files) != set(LOCKED_FILE_KEYS):
        errors.append(f"files 集合不符: 缺={sorted(set(LOCKED_FILE_KEYS) - set(files))} "
                      f"多={sorted(set(files) - set(LOCKED_FILE_KEYS))}")
    for name in LOCKED_FILE_KEYS:
        f = files.get(name)
        if f is None:
            continue
        p = _resolve_lock_path(run_dir, f)
        if not p.exists():
            errors.append(f"锁文件缺失: {name}")
            continue
        if _file_sha256(p) != f.get("sha256"):
            errors.append(f"锁文件 SHA 漂移: {name}")
    return errors


def _verify_run_lock(run_dir: Path) -> list:
    """invoke 前严格复核 RUN_LOCK（P0-1）：approval + lock_request + state 三件套。"""
    errors = []
    # 1. review_approval.json（reviewer 签字，缺失即拒绝）
    approval_path = run_dir / "review_approval.json"
    if not approval_path.exists():
        return ["review_approval.json 缺失（reviewer 未签 RUN_LOCK）"]
    try:
        approval = json.loads(approval_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"review_approval.json 解析失败: {e}"]
    if approval.get("decision") != "APPROVED":
        errors.append(f"review decision != APPROVED: {approval.get('decision')!r}")
    if not approval.get("reviewer"):
        errors.append("review_approval 缺 reviewer")
    if approval.get("reviewed_git_commit") != _git_commit():
        errors.append(f"reviewed_git_commit {approval.get('reviewed_git_commit')} "
                      f"!= HEAD {_git_commit()}")
    # 2. lock_request.json（结构 + 文件 SHA）
    errs = _verify_lock_request(run_dir)
    errors.extend(errs)
    # 3. approval 绑定 lock_request（SHA 一致），且 state.json 记录一致
    lock_path = run_dir / "lock_request.json"
    if lock_path.exists():
        req_sha = _lock_request_sha(run_dir)
        if approval.get("lock_request_sha256") != req_sha:
            errors.append("approval.lock_request_sha256 与 lock_request.json 不符")
        st = json.loads((run_dir / "state.json").read_text(encoding="utf-8"))
        if st.get("lock_request_sha256") != req_sha:
            errors.append("state.json 记录的 lock_request_sha256 与 lock_request.json 不符")
    return errors


def invoke(args) -> int:
    """调用模型。REVIEW_LOCKED/RETRY_REQUIRED/RUNNING → RUNNING → COMPLETE/RETRY_REQUIRED。

    RUNNING 表示上次进程被硬中断（断电/崩溃/终止），可 resume 续跑（P0-2）。
    """
    run_dir = args.run_dir
    if _read_state(run_dir) not in ("REVIEW_LOCKED", "RETRY_REQUIRED", "RUNNING"):
        return _reject(f"invoke 要求 REVIEW_LOCKED / RETRY_REQUIRED / RUNNING（中断恢复），"
                       f"当前 {_read_state(run_dir)}")

    # P0-1：invoke 前复核 run_lock（绑定文件 SHA 未漂移）
    lock_errs = _verify_run_lock(run_dir)
    if lock_errs:
        return _fail(run_dir, f"invoke run_lock 复核失败: {lock_errs[:3]}")

    # P0-1：invoke 自身独立复核输入完整性，不能只信先前验证
    errs = _verify_inputs_integrity(run_dir)
    if errs:
        return _fail(run_dir, f"invoke 输入完整性复核失败（{len(errs)} 项）: {errs[:3]}")

    client = ModelClient()
    client.verify_digest()  # 不一致抛异常

    # P1：核对 Ollama 运行时不符即拒绝（非变异，修复环境后可重试）
    actual_ov = model_client.ollama_version_number()
    if actual_ov != OLLAMA_VERSION:
        return _reject(f"Ollama 版本不符: 实际 {actual_ov} != 冻结 {OLLAMA_VERSION}")

    # P0-2：原子获取独占租约（防并发）。中断后残留租约若 pid 已死则清理重建。
    lease_id, lease_err = _acquire_lease(run_dir)
    if lease_err:
        return _reject(lease_err)

    schedule = json.loads((run_dir / "run_schedule.json").read_text(encoding="utf-8"))
    # 索引 prompt_manifest
    pmap = {}
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            p = json.loads(line)
            pmap[(p["sample_id"], p["side"])] = p

    try:
        return _run_invoke_loop(run_dir, client, schedule, pmap)
    finally:
        _release_lease(run_dir, lease_id)


def _run_invoke_loop(run_dir: Path, client, schedule: list, pmap: dict) -> int:
    """执行调用循环（lease 已获取，由 invoke 的 finally 释放）。"""
    _write_state(run_dir, "RUNNING")
    results_path = run_dir / "results.jsonl"
    attempts_path = run_dir / "attempts.jsonl"
    seen = set()
    # resume：done = 已存在的干净成功记录（results.jsonl 只含成功，不含错误）
    done = set()
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["sample_id"], r["side"], r["arm"], r["repeat"]))

    # attempts.jsonl：不可变审计日志，追加所有调用尝试（含错误），绝不删除
    with open(results_path, "a", encoding="utf-8") as rf, \
         open(attempts_path, "a", encoding="utf-8") as af:
        for item in schedule:
            key = (item["sample_id"], item["side"], item["arm"], 0)
            if key in done:
                continue
            if key in seen:
                return _fail(run_dir, f"唯一键重复: {key}")
            seen.add(key)
            p = pmap[(item["sample_id"], item["side"])]
            prompt = (run_dir / p["prompt_path"]).read_text(encoding="utf-8")
            extra = {
                "prompt_path": p["prompt_path"],
                "prompt_sha256": p["prompt_sha256"],
                # legacy 表示无 selection plan；改用实现指纹 + 摘录内容 SHA
                "representation": p.get("representation"),
                "code_text_sha256": p.get("code_text_sha256"),
                "source_tree_sha256": p["source_tree_sha256"],
                "cpg_cache_key": p.get("cpg_cache_key"),
                "canonical_cpg_rows_sha256": p.get("canonical_cpg_rows_sha256"),
            }
            for k in _fingerprint_keys(p.get("representation")):
                extra[k] = p.get(k)
            rec = client.call(prompt, prompt_renderer.SYSTEM,
                              sample_id=item["sample_id"], side=item["side"],
                              arm=item["arm"], repeat=0, extra=extra)
            # 所有尝试追加到 attempts.jsonl（不可变，审计证据不丢失）
            af.write(json.dumps(rec, ensure_ascii=False) + "\n")
            af.flush()
            # 只有干净成功记录进入 results.jsonl
            if rec.get("parse_status") == "OK" and not rec.get("run_error"):
                rf.write(json.dumps(rec, ensure_ascii=False) + "\n")
                rf.flush()

    # 全部成功才 COMPLETE；否则 RETRY_REQUIRED（resume 可重试缺失/错误键）
    final = set()
    if results_path.exists():
        for line in results_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                final.add((r["sample_id"], r["side"]))
    expected = {(s["sample_id"], s["side"]) for s in schedule}
    missing = expected - final
    if not missing:
        _write_state(run_dir, "COMPLETE")
        print(f"[invoke] 完成 {len(final)} 条干净成功记录 → COMPLETE")
    else:
        _write_state(run_dir, "RETRY_REQUIRED", {"missing": len(missing)})
        print(f"[invoke] 缺 {len(missing)} 条干净成功记录 → RETRY_REQUIRED，可 resume")
    return 0


def verify_results(args) -> int:
    """严格验证结果完整性（fail-closed）。COMPLETE → VERIFIED。"""
    run_dir = args.run_dir
    if _read_state(run_dir) != "COMPLETE":
        return _reject(f"verify-results 要求 COMPLETE，当前 {_read_state(run_dir)}")
    # P0-3：verify-results 也须复核 RUN_LOCK 与输入完整性（结果被替换/输入漂移不得通过）
    lock_errs = _verify_run_lock(run_dir)
    if lock_errs:
        return _fail(run_dir, f"verify-results run_lock 复核失败: {lock_errs[:3]}")
    integ_errs = _verify_inputs_integrity(run_dir)
    if integ_errs:
        return _fail(run_dir, f"verify-results 输入完整性复核失败: {integ_errs[:3]}")
    schedule = json.loads((run_dir / "run_schedule.json").read_text(encoding="utf-8"))
    prot = json.loads((run_dir / "protocol.json").read_text(encoding="utf-8"))
    pmap = {}
    for line in (run_dir / "prompt_manifest.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            p = json.loads(line)
            pmap[(p["sample_id"], p["side"])] = p
    results = []
    for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            results.append(json.loads(line))

    errors = []
    seen = set()
    for r in results:
        key = (r["sample_id"], r["side"], r.get("arm"), r.get("repeat"))
        # 唯一键（重复结果 = 坏）
        if key in seen:
            errors.append(f"结果唯一键重复: {key}")
        seen.add(key)
        # verdict 枚举
        if r.get("verdict") not in VALID_VERDICTS:
            errors.append(f"{r['sample_id']}/{r['side']} verdict 非法: {r.get('verdict')!r}")
        # parse_status 必须 OK（ERROR/网络失败不得通过）
        if r.get("parse_status") != "OK":
            errors.append(f"{r['sample_id']}/{r['side']} parse_status={r.get('parse_status')}")
        # run_error 必须为空
        if r.get("run_error"):
            errors.append(f"{r['sample_id']}/{r['side']} run_error={str(r.get('run_error'))[:60]}")
        # arm/repeat 契约
        if r.get("arm") != "real":
            errors.append(f"{r['sample_id']}/{r['side']} arm 非法: {r.get('arm')!r}")
        if r.get("repeat") != 0:
            errors.append(f"{r['sample_id']}/{r['side']} repeat 非法: {r.get('repeat')!r}")
        # provenance 全量核对（P0 第4点：结果被替换或来自错误参数不得通过）
        p = pmap.get((r["sample_id"], r["side"]))
        if p is not None:
            if r.get("prompt_sha256") != p.get("prompt_sha256"):
                errors.append(f"{r['sample_id']}/{r['side']} prompt_sha256 与 manifest 不符")
            if r.get("source_tree_sha256") != p.get("source_tree_sha256"):
                errors.append(f"{r['sample_id']}/{r['side']} source_tree_sha256 漂移")
            if r.get("code_text_sha256") != p.get("code_text_sha256"):
                errors.append(f"{r['sample_id']}/{r['side']} code_text_sha256 漂移")
        # schema / model / system / 指纹 与 protocol 一致
        if r.get("schema_version") != "model-call/1":
            errors.append(f"{r['sample_id']}/{r['side']} schema_version 非法: {r.get('schema_version')!r}")
        if r.get("model_name") != prot.get("model"):
            errors.append(f"{r['sample_id']}/{r['side']} model_name 漂移")
        if r.get("model_digest") != prot.get("model_digest"):
            errors.append(f"{r['sample_id']}/{r['side']} model_digest 漂移")
        if r.get("ollama_version_number") != prot.get("ollama_version"):
            errors.append(f"{r['sample_id']}/{r['side']} ollama_version 漂移 "
                          f"({r.get('ollama_version_number')!r} != {prot.get('ollama_version')!r})")
        if r.get("system_sha256") != prot.get("system_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} system_sha256 漂移")
        if r.get("representation") != prot.get("representation"):
            errors.append(f"{r['sample_id']}/{r['side']} representation 漂移")
        if r.get("representation_sha256") != prot.get("representation_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} representation_sha256 漂移")
        if r.get("prompt_renderer_sha256") != prot.get("prompt_renderer_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} prompt_renderer_sha256 漂移")
        if r.get("cpg_cache_key") != prot.get("cpg_cache_key"):
            errors.append(f"{r['sample_id']}/{r['side']} cpg_cache_key 漂移")
        if r.get("canonical_cpg_rows_sha256") != prot.get("canonical_cpg_rows_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} canonical_cpg_rows_sha256 漂移")
        # 模型参数：request.options 与 protocol 冻结值一致
        req = r.get("request") or {}
        opts = req.get("options") or {}
        for k in ("num_ctx", "num_predict", "temperature", "top_p", "seed"):
            if opts.get(k) != prot.get(k):
                errors.append(f"{r['sample_id']}/{r['side']} 请求参数 {k} 漂移 "
                              f"({opts.get(k)!r} != {prot.get(k)!r})")
        # prompt_eval_count 不得超过 num_ctx
        if r.get("prompt_eval_count") is not None and \
                r["prompt_eval_count"] > prot.get("num_ctx", 0):
            errors.append(f"{r['sample_id']}/{r['side']} prompt_eval_count 超 num_ctx")
        # 结果内容哈希重算（P0-3：request/raw_response 哈希必须与内容一致，防伪造）
        req = r.get("request") or {}
        req_sha_recalc = _sha256_text(json.dumps(req, sort_keys=True))
        if req_sha_recalc != r.get("request_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} request_sha256 与 request 内容不符")
        raw_text = r.get("raw_response_text")
        if raw_text is None:
            errors.append(f"{r['sample_id']}/{r['side']} 缺 raw_response_text（无法重算哈希）")
        elif _sha256_text(raw_text) != r.get("raw_response_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} raw_response_sha256 与原始响应不符")
        # P0-1：从原始响应文本重新解析，verdict/计数必须与结果记录一致（防仅篡改 verdict）
        if raw_text is not None:
            try:
                reparsed = json.loads(raw_text)
            except json.JSONDecodeError:
                reparsed = {"_raw": raw_text}
            if reparsed != r.get("raw_response"):
                errors.append(f"{r['sample_id']}/{r['side']} raw_response 与原始响应重解析不等价")
            resp_field = reparsed.get("response", "") if isinstance(reparsed, dict) else ""
            derived = ModelClient._extract_verdict(resp_field)
            if derived != r.get("verdict"):
                errors.append(f"{r['sample_id']}/{r['side']} verdict 与原始响应重解析不符 "
                              f"({derived!r} != {r.get('verdict')!r})")
            rp_count = reparsed.get("prompt_eval_count") if isinstance(reparsed, dict) else None
            if rp_count != r.get("prompt_eval_count"):
                errors.append(f"{r['sample_id']}/{r['side']} prompt_eval_count 与原始响应不符")
            rp_reason = reparsed.get("done_reason") if isinstance(reparsed, dict) else None
            if rp_reason != r.get("done_reason"):
                errors.append(f"{r['sample_id']}/{r['side']} done_reason 与原始响应不符")
        # 核对 request 中的 prompt/system 与磁盘/SYSTEM 一致
        p = pmap.get((r["sample_id"], r["side"]))
        if p is not None:
            disk_prompt = (run_dir / p["prompt_path"]).read_text(encoding="utf-8")
            if req.get("prompt") != disk_prompt:
                errors.append(f"{r['sample_id']}/{r['side']} request.prompt 与磁盘 prompt 不符")
        if req.get("system") != prompt_renderer.SYSTEM:
            errors.append(f"{r['sample_id']}/{r['side']} request.system 与 SYSTEM 不符")
        # cpg_eval_sha256（canonical 表示时）
        if prot.get("representation") == CANONICAL_REPR and \
                r.get("cpg_eval_sha256") != prot.get("cpg_eval_sha256"):
            errors.append(f"{r['sample_id']}/{r['side']} cpg_eval_sha256 漂移")
    # 集合必须与 schedule 完全一致
    got = {(r["sample_id"], r["side"]) for r in results}
    expected = {(s["sample_id"], s["side"]) for s in schedule}
    if got != expected:
        missing = expected - got
        extra = got - expected
        errors.append(f"结果集合不符: 缺 {len(missing)} 项 {sorted(missing)[:3]}，"
                      f"多 {len(extra)} 项 {sorted(extra)[:3]}")
    if errors:
        return _fail(run_dir, f"verify-results {len(errors)} 错误: {errors[:5]}")
    _write_state(run_dir, "VERIFIED", {"n_results": len(results)})
    print(f"[verify-results] PASS {len(results)} 项结果完整")
    return 0


def summarize(args) -> int:
    """聚合统计（只读，不改状态）。"""
    run_dir = args.run_dir
    if _read_state(run_dir) not in ("COMPLETE", "VERIFIED"):
        return _reject(f"summarize 要求 COMPLETE/VERIFIED，当前 {_read_state(run_dir)}")
    results = []
    for line in (run_dir / "results.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            results.append(json.loads(line))
    by_pair = {}
    for r in results:
        by_pair.setdefault(r["sample_id"], {})[r["side"]] = r["verdict"]
    strict = sum(1 for cve, d in by_pair.items()
                 if d.get("vuln") == "vulnerable" and d.get("fixed") == "benign")
    n = len(by_pair)
    summary = {"n_pairs": n, "strict_success": strict,
               "rate": round(strict / n, 4) if n else None}
    (run_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[summarize] strict_success={strict}/{n}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["prepare", "verify-inputs", "lock-inputs",
                                        "approve-lock", "invoke", "verify-results",
                                        "summarize"])
    ap.add_argument("--protocol", type=Path)
    ap.add_argument("--representation", default=None,
                    choices=sorted(ALLOWED_REPRESENTATIONS),
                    help="摘录表示版本，必须显式指定（不允许 changed-hunk-r0）")
    ap.add_argument("--canonical-manifest", type=Path,
                    default=ROOT / "cpg/ablation/artifacts/canonical_corpus_manifest.json")
    ap.add_argument("--reviewer", default=None,
                    help="approve-lock 的签字人身份（reviewer 名字）")
    ap.add_argument("--run-dir", required=True, type=Path)
    args = ap.parse_args()

    fn = {"prepare": prepare, "verify-inputs": verify_inputs, "lock-inputs": lock_inputs,
          "approve-lock": approve_lock, "invoke": invoke, "verify-results": verify_results,
          "summarize": summarize}[args.command]
    try:
        return fn(args)
    except Exception as e:
        return _fail(args.run_dir, f"{args.command} 异常: {e}")


if __name__ == "__main__":
    sys.exit(main())
