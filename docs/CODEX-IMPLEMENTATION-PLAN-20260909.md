# CODEX 施工顺序与验收（IMPLEMENTATION-PLAN）

> 来源：外部评审 codex 的施工计划（2026-09-08）与后续增量审查（2026-09-09）。
> 本文档为主 AI 基于原文的约束性重建（非逐字原文），入库以便可审计。
> **冲突裁决**：涉及"施工顺序/验收命令/禁止项/完成判据"时，以本文件为准。

## 〇、核心纪律（施工红线）

- 主 AI 只能**实现/测试/报告观察值**，无权看见结果后改输入策略、扩大实验、升级机制结论、自行宣布 Gate PASS。
- **每个阶段以"计划书点名的验收命令通过"为准，不以"代码写完"为准。**
- 停止"发现一个 bug 修一个 bug"，先建通用流水线再整批跑。
- 每改一个 .py 立即 `py_compile`，改完跑"对应测试 + 全量测试"双验证。

## 一、9 阶段施工顺序（不可跳步）

| 阶段 | 内容 | 关键验收 |
|---|---|---|
| 0 | 止血：修语法、A6、summary 标 invalid | 3.9+3.13 双 compileall + test_source_parse |
| 1 | corpus-v3 统一重建 82 例 | 通用生成器、git show bytes、M/A/D/R/C/T 显式、原子提升、批量 fail-closed |
| 2 | canonical manifest + corpus gate | 直接消费 dataset+pair_manifest+排除，验证 82/82 路径+树哈希+40 位 commit |
| 3 | staging/CodeQL 缓存契约 | stage_exact_snapshot + build_or_reuse_db + 四态查询 |
| 4 | excerpt_plan.py 替换 _load_sample_code | 结构化计划、完整行边界、changed-hunk 覆盖三态 |
| 5 | prompt renderer 只渲染不截断 | 超预算失败、SYSTEM 单一权威、summary=False |
| 6 | model_client + 工件 schema | digest fail-closed、infra/parse 错误不转 abstain、显式 sample/side/arm/repeat |
| 7 | 通用批量 runner | 状态机、固定 seed 顺序、resume 唯一键重复失败 |
| 8 | context_robustness 四条件 | 结构化 SelectionPlan、token 对齐、扰动真实可见 |
| 9 | clean-clone 复算门禁 | clone + 重算 manifest + 双版本测试 + prepare 不调模型 + SHA 比对 |

## 二、后续增量审查追加的 P0（2026-09-09）

| P0 | 问题 | 状态 |
|---|---|---|
| P0-1 | 11 added 文件无 changed_hunks，fallback 未跟踪 corpus_raw | 代码+provenance 已修，clean-clone 全链路未真跑 |
| P0-2 | 164 prompt 零 CPG（cpg_slices=None） | 接线已修（164/164 有 CPG 状态），样本/侧隔离未证明 |
| P0-3 | 无 RUN_LOCK，--protocol 参数未读 | 未修 |
| P0-4 | result verifier 接受失败调用 | 未修 |
| P0-5 | 扰动块 side=__perturb__ 不进入 render | no-op 已修，tokenizer/三模板/预算未做 |
| P0-6 | corpus-v3 批次 provenance 漂移 | SHA 已重算，从零重建一致未验证 |
| P0-7 | 配对预算把每侧砍半 + 覆盖按任一侧 | 已修（每侧独立 + 按侧覆盖）|
| P0-8 | canonical 只覆盖 D1，8 个 74-only 缺失 | 未修 |

## 三、修复顺序（codex 裁决，不可跳）

1. 闭合 P0-1（重算上层 SHA → 全新 clone 跑复现 → 固化报告）。
2. 修 P0-7（每侧独立 8000 + 按侧覆盖 + old/new hunk 坐标 + 命名 pair-hunk-r1）。
3. 闭合 P0-2（CPG 样本/侧隔离 + source/query/tool SHA 绑定 + 查询失败不缓存）。
4. 完成 P0-5（真实 tokenizer + 三模板 + 预算重分配 + 最终渲染验收）。
5. P0-3/P0-4（REVIEW_LOCKED 状态 + 四 SHA + reviewer 签字；ERROR/非法 verdict/重复拒绝 + RUNNING 可恢复）。
6. P0-6/P0-8（corpus-v3 从零重建 generator SHA 一致；明确 canonical 是 D1 专用或扩 93 并集）。

## 四、禁止项

- 禁 61539/67435 专用脚本生产正式结果；禁 CVE 专用分支。
- 禁手工编辑已生成 prompt；禁看见输出后改摘录策略。
- 禁缓存未绑定输入 SHA；禁把 infra/parse 错误记 abstain。
- 禁 WARN 代替 digest/hash/缺文件失败；禁中途截语句。
- 禁 3/3 一致即宣称机制成立；禁执行者自行 PASS 或勾 [x]。

## 五、完成判据（满足才允许复验 67435 + 全量 82 对）

- Python 3.9/3.13 全仓可解析；corpus-v3 82/82 干净克隆可取且树哈希通过。
- staging 无残留、DB/query 缓存全绑 SHA；pair-symmetric 摘录冻结。
- changed-hunk 覆盖报告已生成；全部 prompt 先冻结无摘要泄漏。
- 完整 digest + 参数冻结；工件 schema/原始响应/错误分类完整。
- corpus_gate + result_gate 真正 fail-closed；reviewer 只审工件并签字。

## 六、验收命令（最终）

```powershell
py -3.9 -m compileall -q cpg/ablation
python -m unittest discover -s cpg/ablation/tests -p "test_*.py" -v
python cpg/ablation/rebuild_corpus.py --dataset cpg/dataset_d1.jsonl --all-eligible --from-zero --out cpg/corpus-v3 --manifest cpg/ablation/artifacts/corpus_v3_manifest.json
python cpg/ablation/validate_corpus.py --manifest cpg/ablation/artifacts/corpus_v3_manifest.json --require-eligible 82 --fail-on-missing --fail-on-hash-drift
python cpg/ablation/run_experiment.py prepare --protocol cpg/ablation/protocols/v3.json --canonical-manifest cpg/ablation/artifacts/corpus_v3_manifest.json --run-dir <run-dir>
python cpg/ablation/run_experiment.py verify-inputs --run-dir <run-dir>
python scripts/reproduce_clean_clone.py --commit <sha> --inputs-only
```

`verify-inputs` PASS 且 reviewer 签字前，不得执行 `invoke`。
