# CODEX 施工顺序与验收（IMPLEMENTATION-PLAN）

> 来源：外部评审 codex 的施工计划，逐字转录（原文审计基线 `origin/main = 644f713`）。
> 本文件为当前阶段的上位执行约束。冲突裁决：**施工顺序与验收以本文件为准**。
> **执行状态（2026-09-09）**：第 0-9 阶段已实现，但 codex 增量审查追加 P0-1~P0-8（见文件末尾「后续增量审查」节），其中部分已修复、部分未闭环。

---

以下可直接交给主项目 AI，按顺序施工。不要跳步，不要继续修补 `61539` 专用脚本，更不要先跑 `67435` 或全量模型。

## 审计基线

- 远端最新 HEAD：`644f71310f17c3718de9b94cfdcfeb43da6406ce`
- 工作区干净，远端 HEAD 已核对一致。
- 本次为只读审计，未修改仓库。

## 当前必须立即停止模型调用的 P0

1. **最新 `rerun_61539.py` 根本不能执行。**
   `rerun_61539.py:120` 在字典字面量内部定义 `_has_danger_eval()`，Python 3.9 与 3.13 均实测 `SyntaxError`。主 AI 所称"语法检查通过"与最新代码不符。
   另外，项目宣称支持 Python ≥3.9，但 `upstream_manifest.py:365` 在 Python 3.9 也无法解析。

2. **正式批量运行器完全没有消费 corpus-v2。**
   `corpus_db.py:49` 将来源硬编码为 `cpg/corpus_pairs`；`run_ablation.py:382` 仍调用该旧路径。因此现在若跑全量，14 个 v2 重建样本并不会进入正式实验。

3. **staging 和 CodeQL 缓存会串库。**
   `_stage_corpus()` 使用 `copytree(..., dirs_exist_ok=True)` 合并覆盖、不删除旧文件。v1→v2 文件集合改变后，旧文件会留在 staged 源树。
   `build_corpus_db()` 只凭数据库/CSV/SARIF"存在且非空"就复用，没有绑定：canonical manifest SHA、staged source tree SHA、查询文件 SHA、CodeQL 版本。这意味着新语料可能继续使用旧 DB 和旧查询结果。

4. **干净克隆根本拿不到规范 manifest 宣称的全部 83 例。**
   全新克隆中逐例验证：D1 manifest eligible 83；实际存在源码 71；有 12 个 eligible v1 样本路径不存在且 Git 从未跟踪（`53504/54284/55618/62676/62677/70479/70483/71870/73228/73229/84310/84366`）。74 主集恰好 74/74 存在；并集 eligible 91 中仅 79 存在。
   但 `verify_claims.py` 只数 `77/14/2`，不检查路径与树哈希，仍会输出 corpus gate PASS。

5. **重建和审计在干净克隆中也跑不通。**
   `rebuild_pair.py` 和 `upstream_five_state_audit.py` 的 `read_meta()` 仍硬读 `corpus_pairs/<CVE>/meta.json`。至少 53500/53503/59224/70485 的旧 meta 在干净克隆中不存在。
   同时：`cpg/corpus_raw` 0 个文件被跟踪；`.work/upstream_api_cache` 0 个文件被跟踪。因此此前"干净克隆可重建/可审计"的链条并未成立。

6. **manifest 树哈希受 Git autocrlf 影响。**
   仓库没有 `.gitattributes`，当前 Git 配置为 `core.autocrlf=true`。61539 corpus-v2 的 raw 工作树哈希在新克隆中与 manifest 不同；将 CRLF 规范化为 LF 后才一致。`canonical_manifest.tree_sha()` 当前直接哈希工作树字节，因此跨平台不可复算。

7. **claims 门禁仍是 fail-open。**
   `verify_claims.py:52` 只打印 `[result_gate] PROVISIONAL` 却不令 `ok=False`，最终仍可能 `VERIFY_CLAIMS: PASS`。

8. **61539 工件已经相互漂移。**
   `summary.json` 仍保存带公告摘要的旧 prompt SHA；当前 `v1/meta.json`、`v2/meta.json` 是无摘要的新 SHA。当前 HEAD 无法用已损坏的 `rerun_61539.py` 重生成任何一套。

9. **A5 消融仍无效。**
   `v1_add_utils` 实际出现 `"choices": [# ===== FILE: utils.py ...`，即新文件块粘进未完成语句；同时违反 8000 字符预算。A5 只能保留审计轨迹，不能支撑模型上下文机制结论。

## 强制施工顺序

### 第 0 阶段：止血与代码可执行门禁

先做，不得运行模型。

修改：

- 将 `_has_danger_eval()` 移到模块顶层，修复 `rerun_61539.py` 语法。
- 修复 `upstream_manifest.py` 的 Python 3.9 f-string。
- 新增 `cpg/ablation/tests/test_source_parse.py`：遍历 `cpg/ablation/*.py`，使用 `ast.parse`，Python 3.9 与实际运行 Python 都必须通过。
- protocol 追加 A6：A5 因块粘连、预算违例作废；不删除 A4/A5 历史。
- 把陈旧 `summary.json` 标为 invalid，禁止手工改数字；以后必须由工件聚合器重建。

验收：

```powershell
py -3.9 -m compileall -q cpg/ablation
python -m compileall -q cpg/ablation
python -m unittest cpg.ablation.tests.test_source_parse -v
```

任一非零即停止。

### 第 1 阶段：建立唯一、可复算的 corpus-v3

不要继续维护"77 份 v1 + 14 份 v2"的混合物。用同一个通用生成器，从上游 parent/fix 对全部 83 个 eligible 样本统一重建。

修改 `rebuild_pair.py`，拆成通用函数：

```python
resolve_sample_spec(dataset_rows, sample_id) -> SampleSpec
preflight_repo(spec) -> RepoSnapshot
read_blob_bytes(repo, commit, path) -> bytes
build_pair_in_staging(spec, staging_dir) -> PairManifest
validate_pair(pair_manifest, staging_dir) -> ValidationReport
atomic_promote(staging_dir, final_dir)
```

必须满足：

- 元数据从 `dataset.jsonl/dataset_d1.jsonl` 读取，不依赖旧 `corpus_pairs/meta.json`；
- `git show` 使用 `text=False`，保留原始 blob 字节；
- M/A/D/R/C/T 全部显式处理，未知状态直接失败；
- 输出先写独立临时目录，完整验证后原子提升；
- 任何一例失败，批次退出非零；
- `main()` 不得无条件返回 0；
- manifest 保存：`repo_slug`、完整 parent/fix SHA、每个文件的 status/old/new path/mode、原始 blob SHA、规范 LF 内容 SHA、generator SHA、Git/Python 版本、完整调用参数；
- 禁止任何 `if cve == "61539"` 一类分支。

新建完整 corpus-v3：

- 对 83 例全部使用同一生成器；
- 两个跨语言样本只写排除记录，不生成伪 Python pair；
- 统一 83 例预计仍在普通 Git 可承受范围；优先直接跟踪；
- 若最终改为外部归档，则仓库必须提供下载器、完整 SHA 和断网时的明确错误，不允许依赖本机隐藏目录。

增加 `.gitattributes`，至少冻结：

```gitattributes
*.py text eol=lf
*.json text eol=lf
*.jsonl text eol=lf
*.md text eol=lf
```

树哈希统一使用 Git blob 或明确的 LF 规范化字节，不能哈希平台工作树原始字节。

测试 `test_rebuild_pair.py`，用临时 Git 仓库合成覆盖：modified、added、removed、renamed、copied、type change、CRLF/LF、UTF-8 编码声明、大小写冲突、symlink、缺 blob、一个样本失败时批次退出非零、失败时正式目录不存在、两次独立进程重建 SHA 完全一致。

### 第 2 阶段：重写 canonical manifest 和 corpus gate

`canonical_manifest.py` 不得读取陈旧 `.work/upstream_five_state.json` 来决定真值。应直接消费：数据集行、corpus-v3 每例 `pair_manifest.json`、明确的排除记录。

每个样本至少包含：

```json
{
  "sample_id": "...",
  "repo_slug": "...",
  "parent_commit": "...",
  "fix_commit": "...",
  "source_path": "...",
  "vuln_tree_sha256_lf": "...",
  "fixed_tree_sha256_lf": "...",
  "pair_manifest_sha256": "...",
  "eligible": true,
  "exclusion_reason": null,
  "in_74": true,
  "in_85": true
}
```

生成器必须验证：eligible=83；83/83 路径存在；83/83 树哈希匹配；fix/parent 完整 40 位；无重复样本；无大小写碰撞；两个排除样本理由精确匹配。

`verify_claims.py` 拆成真正两道门：

- `corpus_gate` 失败 → 非零；
- `result_gate=PROVISIONAL` → canonical 模式非零；
- 可另设 `--historical-only` 允许仅复算历史数字，但输出必须明确 `HISTORICAL_ONLY_PASS`，不得叫 canonical PASS；
- 删除硬编码 77/14/2，全部从 manifest 推导；
- manifest 只有计数正确但任一路径/哈希错误，也必须失败。

### 第 3 阶段：重写 staging 与 CodeQL 缓存契约

`corpus_db.py` 删除：固定 `CORPUS_PAIRS`、`copytree(..., dirs_exist_ok=True)` 合并不删、仅凭 DB/CSV/SARIF 存在就复用。

改为：

```python
stage_exact_snapshot(canonical_manifest, run_root) -> StagedManifest
build_or_reuse_db(staged_manifest_sha256, query_set_sha256, codeql_identity) -> CpgBundle
```

规则：

- staging 使用新的 run-specific 空目录；
- 每个 side 从 canonical manifest 显式 source_path 复制；
- 复制后重新验树哈希；
- 缺任一 side 直接失败，不能 continue；
- DB cache key 至少为 `sha256(staged_manifest + CodeQL 完整版本 + query 文件 SHA 集合)`；
- key 不匹配时禁止复用；
- 每个 query 保存 `rc/status/rows/bqrs_sha/csv_sha/command/duration`；
- query 失败是基础设施错误，不得伪装成 0 行；
- 显式区分 `SUCCESS_WITH_ROWS` / `SUCCESS_ZERO_ROWS` / `UNSUPPORTED_CWE` / `QUERY_FAILED`；
- 当前 `cpg_evidence_available=bool(rows)` 必须删除；"查询成功但 0 行"不等于"查询没运行"。

测试 `test_corpus_snapshot.py`：上一次有文件 A、本次源树删除 A，staging 中不得残留 A；改一个源字节 DB cache 失效；改一个 query 字节 cache 失效；query rc 非零整轮失败；success-zero 必须保留为合法状态；staging 结果跨进程完全一致。

### 第 4 阶段：替换 `_load_sample_code`

抽成新模块 `excerpt_plan.py`，先生成结构化计划，再渲染文本。

当前函数的承重缺陷：按每侧文件大小排序（vuln/fixed 可能选择不同文件和顺序）；无 taint 时只取头 100 行（可能漏掉安全 hunk）；`text[:remain]` 从语句中间截断；只输出 basename（同名文件不可区分）；CPG 命中状态与摘录内容耦合；renderer 二次 `code_text[:8000]` 双重隐藏截断。

新接口：

```python
build_pair_selection_plan(sample_spec, pair_manifest, cpg_bundle, excerpt_policy) -> PairSelectionPlan
render_side(plan, side) -> RenderedCode
```

`PairSelectionPlan` 必须在看模型输出前一次性生成，并由 vuln/fixed 共享。

规则：

- 文件顺序依据完整相对路径，不能依据各侧文件大小；
- 同一逻辑文件在两侧使用配对窗口；
- added/deleted 显式记录 side absence；
- 只能在完整行/完整块边界截取；
- 文件标记使用完整相对路径；
- 达预算时缩小窗口或舍弃完整低优先块，绝不截半行；
- 记录每个块 `path/side/lo/hi/reason/content_sha/token_count`；
- 对所有上游 changed hunk 输出 `FULL/PARTIAL/ABSENT`；
- 主实验允许何种 coverage 必须在协议里预先冻结；
- 不得看到 61539 结果后直接决定"剥离 license"；
- primary 条件保持原文；license/中性块作为单独预注册鲁棒性实验。

若研究任务确实是判断候选补丁充分性，建议机械化采用"上游 changed hunk 中心窗口"作为无 taint fallback，并对两侧对称应用；若坚持历史 head-100 策略，则必须把 hunk 缺失率作为表示失败公开报告。二者先由导师选择，选定后不再根据结果调整。

测试 `test_excerpt_plan.py` 至少包括：相同输入跨进程 SHA 一致；`PYTHONHASHSEED` 变化不影响；pair 两侧逻辑文件顺序相同；无 FILE marker 粘入未完成行；每个块以换行结束；无半行截断；总 token 不超预算；完整相对路径唯一；非目标区域字节不变；changed-hunk coverage 计算正确；61539 fixture 必须检测到 `utils.py` 安全 hunk 在约 L750（不能把 L1–100 冒充安全 hunk）；73498 added 文件；renamed/deleted fixture；同名 basename 不同目录。

### 第 5 阶段：prompt renderer 只负责渲染，不再截断

修改 `LocalLLMScorer._build_prompt()`：

- 接收已经过预算验证的 `RenderedCode`；
- 删除 `code_text[:8000]`、`cpg_slices[:12000]`；
- 超预算直接失败；
- SYSTEM 仅保留一份权威定义，`invoke_61539.py` 不得复制；
- summary 政策由 protocol 控制，主实验必须显式 `summary=false`；
- prompt metadata 保存 renderer SHA、SYSTEM SHA、selection-plan SHA。

测试：snapshot 测试；summary 关闭时任何 prompt 不得出现公告摘要；四条件除允许字段外逐字节等价；fence、标题、FILE marker 数严格正确；prompt 保存后重读 SHA 不变；prompt 生成阶段不允许任何模型调用。

### 第 6 阶段：统一模型客户端与工件 schema

建立通用 `model_client.py` 和 `run_experiment.py`（不要让 `invoke_61539.py` 成为正式 runner）。

客户端规则：

- 调用前读取并验证完整 64 位 digest；不一致立即退出，不能只 WARN；
- 完整冻结 `model/digest/num_ctx/num_predict/temperature/top_p/seed/repeat`；
- 网络错误、超时、非 JSON、schema 错误属于 `RUN_ERROR/PARSE_ERROR`，不得转换成科学意义的 abstain；
- 原始日志写失败必须中止，不能 `except: pass`；
- 调用参数显式携带 `sample_id/side/arm/repeat`，不能靠 `getattr(ctx,"version",None)`；
- 全部 prompt 先冻结并验证，再开始调用；
- 调用顺序由固定 seed 生成并提前写入 manifest；
- 支持 resume，但唯一键重复必须失败；
- 所有结果完成后再聚合，不边看结果边改代码。

每次调用的必需字段：

```json
{
  "schema_version": "model-call/1",
  "run_id": "...",
  "sample_id": "...",
  "side": "vuln|fixed",
  "arm": "...",
  "repeat": 0,
  "source_tree_sha256": "...",
  "cpg_bundle_sha256": "...",
  "selection_plan_sha256": "...",
  "prompt_path": "...",
  "prompt_sha256": "...",
  "system_sha256": "...",
  "request": {},
  "request_sha256": "...",
  "model_name": "...",
  "model_digest": "64hex",
  "raw_response": {},
  "raw_response_sha256": "...",
  "parse_status": "OK|ERROR",
  "verdict": "...",
  "prompt_eval_count": 0,
  "done_reason": "...",
  "duration_ms": 0
}
```

API 密钥、Authorization header 不得落盘。

### 第 7 阶段：建立通用批量 runner

```text
run_experiment.py prepare / verify-inputs / invoke / verify-results / summarize
```

状态机：

```text
CREATED → INPUTS_FROZEN → RUNNING → COMPLETE → VERIFIED
```

任何失败进入 `FAILED`，不得继续统计。

正式 runner 只接受 `--protocol / --canonical-manifest / --run-dir`，不得再接受人工拼的 `--exclude-cves` 作为主分析口径。

先跑纯输入 smoke，覆盖：逻辑 CWE/零 taint、taint 命中、added 文件、deleted/renamed、大补丁、61539 只作普通样本（代码中不得出现其 ID）。

通过后先生成 83×2 全部 prompt 并冻结 SHA；由 reviewer 只审输入工件；输入验收通过后才调用模型。

### 第 8 阶段：机制消融另建通用 runner

`ablate_61539.py` 归档，不再修。新建 `context_robustness.py`，操作结构化 `SelectionPlan`，禁止解析并拼接 Markdown prompt。

变体必须：从同一 base plan 生成；在完整文件块边界操作；重新经过同一预算分配器；总 token 匹配；非目标块 SHA 完全相同；至少包含中性注释、license 文本、非 license 代码、多个不同中性模板；样本与变体在看结果前冻结；单样本 61539 只能叫 pilot，不得作为主贡献。

### 第 9 阶段：clean-clone 复算门禁

新增 `scripts/reproduce_clean_clone.py`，使用系统临时目录，完成：

1. clone 指定 commit；2. 检查 Python 版本；3. 验证 83/83 canonical 源语料；4. 重算 manifest 与树哈希；5. 跑全部 unit/invariant tests；6. 生成全部 prompt 但不调模型；7. 比对预期 prompt SHA；8. 验证 run schema；9. 确认仓库无未跟踪依赖。

最终验收命令：

```powershell
py -3.9 -m compileall -q cpg/ablation
python -m unittest discover -s cpg/ablation/tests -p "test_*.py" -v

python cpg/ablation/rebuild_corpus.py --dataset cpg/dataset_d1.jsonl --all-eligible --from-zero --out cpg/corpus-v3 --manifest cpg/ablation/artifacts/corpus_v3_manifest.json

python cpg/ablation/validate_corpus.py --manifest cpg/ablation/artifacts/corpus_v3_manifest.json --require-eligible 83 --fail-on-missing --fail-on-hash-drift

python cpg/ablation/run_experiment.py prepare --protocol cpg/ablation/protocols/v3.json --canonical-manifest cpg/ablation/artifacts/corpus_v3_manifest.json --run-dir <run-dir>

python cpg/ablation/run_experiment.py verify-inputs --run-dir <run-dir>
```

在 `verify-inputs` PASS 且 reviewer 签字前，不得执行 `invoke`。

最终模型完成后：

```powershell
python cpg/ablation/run_experiment.py verify-results --run-dir <run-dir> --require-complete
python cpg/ablation/paired_metrics.py --run-manifest <run-dir>/run_manifest.json
python cpg/ablation/.work/verify_claims.py --canonical --run-manifest <run-dir>/run_manifest.json
python scripts/reproduce_clean_clone.py --commit <最终提交SHA> --inputs-only
```

## 禁止项

- 禁止继续用 61539/67435 专用脚本生产正式结果；
- 禁止任何 CVE 专用分支；
- 禁止手工编辑已生成 prompt；
- 禁止在看到模型输出后修改摘录策略；
- 禁止缓存未绑定输入 SHA；
- 禁止把基础设施错误或解析错误记作 abstain；
- 禁止用 WARN 代替 digest/hash/缺文件失败；
- 禁止从中间语句截断；
- 禁止仅因"输出 3/3 一致"宣称机制成立；
- 禁止执行者自行给 Gate PASS 或勾 `[x]`；
- 禁止在 83 份输入工件全部冻结前开始全量调用。

## 真正的完成判据

只有同时满足以下条件，才允许复验 67435 和全量 83 对：

- Python 3.9/3.13 全仓实验脚本可解析；
- corpus-v3 83/83 在干净克隆可取；
- 83/83 外部锚定与树哈希通过；
- staging 无残留、DB/query 缓存全部有输入 SHA 绑定；
- pair-symmetric 摘录策略冻结；
- changed-hunk 覆盖报告已生成；
- 全部 prompt 先冻结，且无摘要泄漏；
- 完整模型 digest 与请求参数冻结；
- 工件 schema、原始响应、错误分类完整；
- `corpus_gate` 与 `result_gate` 真正 fail-closed；
- reviewer 只审工件并签字。

当前最重要的战略调整是：**停止围绕 61539 继续补专用脚本，先把"83 例统一语料→精确 staging→CPG→配对摘录→prompt→模型→工件→claims"的通用流水线建成。** 这条链一旦建成，67435 和全量重跑才会一次性推进，而不是继续产生新一轮局部返工。

---

## 后续增量审查（2026-09-09 codex 追加，非原文）

codex 在 `420d829` 后追加 P0-1~P0-8 承重问题，逐条属实，修复状态如下：

| P0 | 问题 | 状态 |
|---|---|---|
| P0-1 | 11 added 文件无 changed_hunks，fallback 未跟踪 corpus_raw | 代码+provenance 已修（ad74148/9078b90），clean-clone 全链路未真跑 |
| P0-2 | 164 prompt 零 CPG | 接线已修（420d829，164/164 有 CPG 状态），样本/侧隔离未证明 |
| P0-3 | 无 RUN_LOCK，--protocol 未读 | 未修 |
| P0-4 | result verifier 接受失败调用 | 未修 |
| P0-5 | 扰动块 side=__perturb__ | no-op 已修（420d829），tokenizer/三模板/预算未做 |
| P0-6 | corpus-v3 provenance 漂移 | SHA 已重算（9078b90），从零重建一致未验证 |
| P0-7 | 配对预算砍半 + 覆盖按任一侧 | 已修（0182ec0） |
| P0-8 | canonical 只覆盖 D1，8 个 74-only 缺失 | 未修 |
