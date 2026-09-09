# CODEX 仓库状态审计（REPO-STATE）

> 来源：外部评审 codex 对仓库 `llm-vuln-detector` 的只读审计（2026-09-08/09 多轮）。
> 本文档为主 AI 基于审计原文的约束性重建（非逐字原文），入库以便可审计、可回溯。
> **冲突裁决**：涉及"仓库事实是什么"时，以本文件为准。

## 一、已真实完成的部分

- 五态审计机器结果：并集 93 例 = 77 OK + 16 CORPUS_ERROR + 0 unverifiable。
- corpus-v3 已跟踪 82 个 D1 eligible 样本（原先缺失的 12 例已补入）。
- 排除项：70486/70492（跨语言）、53656（多父复合提交）。
- canonical manifest 验证 82 eligible + 3 excluded。
- 164 份 prompt（82 例 × vuln/fixed 两侧），唯一键完整，均有代码、无公告摘要、CWE 非空。
- verify_claims 已拆两层：canonical 模式 PROVISIONAL 退出 1；--historical-only 退出 0。
- 单元测试（35 项）Python 3.9 + 3.13 双版本通过。
- prompt renderer 不再隐式截断；模型客户端完整 digest 常量；Ollama 0.33.3（qwen2.5-coder:7b digest `dae161e2…64364` 未变）。

## 二、三轨结构（不得混用）

| 轨道 | 内容 |
|---|---|
| **H** | 历史 82 对语料与结果端到端重跑（RQ1-R + S-67435 + CR-1） |
| **V** | V4 15 例四臂（real/partial/placebo/shuffled）Gate A/B —— 论文主实验 |
| **M** | 上下文鲁棒性探索（CR-1，61539 仅作 pilot） |

## 三、P0 清单（截至 2026-09-09）

1. canonical manifest 不是真正纳入门禁（机械映射旧审计，未执行 freeze 规则）。
2. canonical tree hash 直接哈希工作树字节，受 core.autocrlf 影响不可跨机复现。
3. verify_claims 结果未闭环仍可能 PASS。
4. 多父提交（53656）未 fail-closed。
5. 内容审计 fail-open（非 200/超时静默绕过）。
6. rebuild_pair 非字节级、批量不 fail-closed。
7. 61539 A5 消融无效（代码粘连 + 预算违规 + 反事实未过摘录器）。
8. V4 Gate A 未建立（v4_upstream_real_report.json 缺失，15 例 manifest 字段空）。

（后续 codex 增量审查追加的承重问题，见 CODEX-IMPLEMENTATION-PLAN 的 P0-1~P0-8。）

## 四、缺失的关键工件

- `v4_upstream_real_report.json`
- `make_partial_diffs.py`、`partial_diffs.json`
- `prompt_snapshot/`
- `shuffled_manifest.json`

## 五、关键路径

1. 停止单 CVE 试验；追加 A6 作废 A5。
2. 修基础工件（git blob bytes 提取、批量原子化、五态 fail-closed、53656 base、缺失 12 例公开重建、canonical hash 改 Git blob id、verify_claims 逐样本验证）。
3. 三轨并行：H（82 对重跑）/ V（V4 四臂）/ M（上下文鲁棒性）。
4. 复验 67435 或全量调用前，先冻结通用 prompt/excerpt 规范。
5. 历史无 digest，继承不可证 → 按单一冻结协议重跑 82 对。

## 六、报告与工件不一致（需修正的文档）

- 五态审计报告.md：写 79 OK / 14 error，机器 JSON 实际 77 / 16；仍把 61539 写 SSRF（实为 CWE-95）。
- D1-语料缺口与可复现性说明.md：仍称"17/85 缺口不存在"。
- raw_prompt审计.md：仍称 14 例历史结果可直接继承。
- EXPERIMENT-FREEZE.md：仍称 API key 是"唯一阻塞项"。
