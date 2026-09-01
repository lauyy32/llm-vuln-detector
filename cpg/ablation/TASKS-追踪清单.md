# P0/P1/P2 任务追踪清单（2026-08-28 立论修正版）

> 本清单为"防幻觉"权威记录：每项任务的状态、完成提交、关键数字都以此为准。
> 更新规则：每完成一项，在此标记 ✅ + commit SHA + 关键数字；新发现的任务追加在末尾。
> 参照：B3-消融与互补性报告.md §6（主结果）｜ MEMORY.md（记忆）｜ 2026-08-28.md（日志）

## 状态图例
- ⬜ 未开始 ｜ 🔄 进行中 ｜ ✅ 已完成 ｜ ⛔ 已放弃（附原因）

---

## P0 — 不修复就无法投稿（三项全部完成）

### 1. 移除标签泄漏 ✅（f4ef252，2026-08-28）
- **实现**：`context_build.py` 默认不注入公告摘要（`--with-summary` 才注入）；`scorers.py` prompt 去摘要依赖
- **决策**：CWE **保留**在 advisory_meta——它是任务定向（CodeQL/结构启发式等基线共用），非泄漏；仅 summary 构成泄漏（描述漏洞位置/成因）
- **实测对比**（54 版本重跑）：带摘要 LLM 0.449 → 无摘要 0.409（Δ-0.040）；B 组 0.316→0.000；CPGEvidence 不变 0.435
- **统计影响**：bootstrap 差值 CI [-0.091, 0.000]、LLM 高于 CPG 比例 0.0%——原"99.7% 显著"来自摘要泄漏，已撤销
- **主协议**：无摘要成为默认主结果

### 2. 修复三模式 ✅（f4ef252，2026-08-28）
- **决策**：选择"明确声明"分支——本系统是 code-level 检测器；request 模式按设计恒 abstain（语料无请求字段）；both=code（request_info 恒 None）
- **实现**：`run_ablation.py --modes` 默认 `code`；request/both 显式启用时打印警告
- **文档**：README / ARCHITECTURE / SPEC / DESIGN / B3 全部同步"三模式协议修正"
- **额外修复**：`--skip-baseline` 连带跳过 ConfigSig/CPGEvidence/LLM 的 bug

### 3. 暴露原始产物 ✅（f4ef252，2026-08-28）
- **实现**：`LocalLLMScorer` 增 `raw_log` 参数，每次调用落盘 prompt+raw 响应 → `raw_llm_responses.jsonl`（54 条）
- **入库**：seeds/v6_54_{A,B,14b}/results.csv + summary.md 强制跟踪（git add -f）
- **核对**：*.csv 原本就未全局 ignore（仅 seeds/ 与 .work/ 被 ignore），results.csv 一直在版本控制中

---

## P1 — 投稿前应修复

### 4. 加 seed 参数 ✅（提交中，2026-08-28 晚）
- **实现**：`LocalLLMScorer(seed=...)` → `/api/generate` options 加 `"seed"`；`run_ablation.py --seed N`；raw 日志记录 seed+temperature 字段
- **验证**：`--seed 42` 冒烟跑通，raw_llm_responses.jsonl 正确记录 seed=42；temperature=0 下结果与无 seed 一致（F1=0.667 复现）
- **注意**：temperature=0 时 seed 不改变结果，其价值在代码层面显式声明 + 审稿可复现审计

### 5. no-summary 正式报告 ✅（被 P0-1 超越完成，f4ef252）
- **原目标**：--no-summary 作为独立消融维度跑 54 版本并报告 F1 对比
- **实际**：无摘要已成为主协议（P0-1），带摘要反成对照实验；B3 §6.6 报告完整对比表
- **状态**：比原计划更彻底，关闭

### 6. 路径配置化 ✅（提交中，2026-08-28 晚）
- **实现**：config.py 新增 DATA_ROOT（环境变量 CPG_DATA_ROOT 可覆盖）/ CORPUS_SRC / CORPUS_DB / CORPUS_SARIF / BANDIT_EXE（BANDIT_EXE 可覆盖）/ OLLAMA_BASE（OLLAMA_BASE 可覆盖）
- **更新**：corpus_db.py / bandit_compare.py / ctx_form_ablation.py / _rebuild_corpus.py / _viz_report.py / scorers.py（DEFAULT_BASE 同源 OLLAMA_BASE）
- **残留**：pipeline.py DEFAULT_DB（单机脚本，与消融框架隔离，暂留）；_viz_report.py 的 out 路径指向 workspace artifacts（保留）；config.py 内默认值本身（单点定义，符合设计）
- **验证**：bandit_compare 回归结果一致（Bandit 0.182 / LLM 0.409）；demo 冒烟通过

---

## P2 — 可选改进（B-2 升为最高研究优先）

### 7. B-2 基准：部分/歧义证据需语义推理 ✅（提交中，2026-08-28 晚）
- **设计（b2_evidence_ablation.py）**：在现有 27 CVE 上构造三档证据形态（full / sink_only / truncated 歧义证据——保留 CWE 头+source，移除 "reaches sink at" 行）
- **全量结果（7B，54 版本）**：
  - full：CPG 0.435 / LLM 0.409（基线）
  - sink_only：CPG **0.000** / LLM 0.229
  - truncated：CPG **0.000** / LLM **0.372**（Δ仅-0.037）
- **结论**：确定性解析器完全依赖流结论行、证据降级即归零；LLM 靠源码语义补全——8 个 vuln 样本 CPG 失明而 LLM 判对（50558/53502/54706/67424/67435/45019/67428/70491），误报不增（8=8）
- **意义**：LLM 独特价值 = "证据不完整/歧义时的语义补全"——互补性立论闭环（B3 §7.8 第 3 条）
- **产物**：B2-v2-证据降级基准报告.md + b2_evidence_7b.json（C:/Users/lenovo/cpg_db/）
- **待办**：14B 在 B-2 形态上的模型规模对照（当前仅 7B）

### 8. 扩样本 27→74 CVE ✅（2026-08-29 完成）
- **目标达成**：27→30（18ada87）→35（f9e9388）→ **74（4445ee3）**，远超 50 目标
- **新增 39 样本**（445/4 提交通道）：双侧文件校验 + 内容级 diff 验证（diff_lines>0 且 missing_pair=0 才 VALID）后入库
- **纠错**：47192/48710/59894 曾被旧版 fetch 缺陷误阻断，新代码重跑双侧齐全（diff 内容级验证 5/40/32 行差异）
- **零污染**：55244/55419/55558/69248/69249/73974/70486/70492/70483 全部排除；70483 双侧不完整（fixed 侧 0 文件）
- **提取统计**：209 候选 → 40 新 meta（成功率约 19%）；12 个 blocked 残留目录已清理
- **重跑结果（3d3da4f，74 样本无摘要 7B）**：LLM F1=**0.321** / CPGEvidence **0.330** / Structural 0.196 / CodeQL 0.051
- **bootstrap（74 样本）**：差值 CI **[-0.041, 0.008]**（54 样本为 [-0.091, 0.000]，CI 收窄 55%）；LLM 高于 CPG 比例 24.2%
- **结论**：CI 显著收窄但 LLM 与 CPG 仍无显著差异；CPG 判别必要条件立场不变

### 9. DVWA 改造 ✅（弃用决策，b28c366，2026-08-28）
- **决策**：**弃用**（倾向弃用 → 正式弃用）
- **理由**：① 与 CPG 代码级主线无关（请求侧 MVP 评测）；② 三档难度共用同一组 payload，仅换 security cookie，不构成独立维度（DeepSeek 评审确认）；③ 请求侧分析上限已实证（v2.4 No-Context 反而略优）
- **落地**：README 标注弃用声明 + v2.2 章节标注历史记录；脚本保留作历史冒烟工具，结果不再进入任何消融/对比报告

---

## 已发现的追加任务（防遗忘）

### A. 14B 主协议重跑 ✅（2026-08-29，待提交）
- 现状：14B 结果（F1=0.531）是带摘要对照运行；主协议已改无摘要，14B 应重跑以对齐
- **完成**：74 样本无摘要重跑（seeds/v8_74_14b，qwen2.5-coder:14b，35min）：
  LLM F1 0.321→**0.365**（P 0.531→0.512 / R 0.230→0.284；taint 0.500→0.524、
  logic 0.212→0.274）；bootstrap 差值 CI **[-0.003, 0.085]**、LLM 高于 CPG 比例
  **95.4%**（7B 为 [-0.041, 0.008] / 24.2%）——规模提升使 LLM 接近显著占优
- 分歧：vuln 侧 4 TP 新增零回退（53656/54707/61539/61632，其中 3 个 CPG 亦漏报）、
  benign 侧 +5 FP；结构型 CWE 仅 863 突破（0→0.667），400/444/639/862 仍全盲
- **B 组（无 taint）14B 对照 ✅（2026-09-01，seeds/v8_74_14b_B）**：14B B 组 LLM F1=**0.073**
  （TP=3，bootstrap 差值 CI [0.000, 0.156]、LLM>CPG 95.6% 但不显著）；7B B 组全漏 0.000、
  14B 恢复 3 个语义可判样本，将「CPG 严格必要条件」修正为「14B 下近似必要」（taint 贡献 +0.292 F1）
- 脚本改进：bootstrap.py 增 --csv/--out 参数（路径配置化收尾）

### B. 采集管线双侧文件校验 ✅（已落地，82ce224/4445ee3）
- 55419 教训：重构式修复（文件移动/拆分）让"同名文件 checkout"漏掉 vuln 侧
- **实现**：corpus_builder `clone_and_extract` 提取修复 diff 改动文件双侧；缺失率 ≥30% 判定重构式修复 → 阻断入库（blocked signal + 清理临时目录）
- **验证**：209 候选提取时 12 个 blocked 残留全部被正确拦截；70483（fixed 侧 0 文件）被内容级 diff 校验拦截

---

## 当前 HEAD 基线
- 主分支：`0b95f0b`（14B 主协议重跑 + 结构型 CWE 覆盖率评估 + B 组 14B 对照，已推 origin/main）
- 主结果（74 样本无摘要 7B）：LLM F1=**0.321** / CPGEvidence **0.330** / 差值 CI [-0.041, 0.008] / LLM 高于 CPG 比例 24.2%
- **模型规模对照（74 样本无摘要 14B，v8_74_14b）**：LLM F1=**0.365** / 差值 CI **[-0.003, 0.085]** / LLM 高于 CPG 比例 **95.4%**
- **B 组（无 taint）14B（v8_74_14b_B）**：LLM F1=**0.073**（TP=3）/ 差值 CI [0.000, 0.156] / 比例 95.6%（不显著）
- 历史主结果（54 样本）：LLM 0.409 / CPG 0.435 / 差值 CI [-0.091, 0.000] / 比例 0.0%
- 下次会话开始时：先读本文件确认已完成项，再决定下一步，不凭记忆猜测
