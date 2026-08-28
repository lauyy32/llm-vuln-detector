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

### 7. B-2 基准：部分/歧义证据需语义推理 ⬜（最高研究优先）
- **背景（立论修正后）**：无泄漏下 LLM(0.409) 未优于 CPGEvidence(0.435)，bootstrap 0.0%——LLM 独有价值悬而未决
- **B-2 目标**：构造确定性解析器必然失败、需要语义推理的样本集，量化 LLM 独有贡献
- **已有素材**：CVE-2026-53505（thumbor CWE-400，无 taint 证据，CPGEvidence 判 benign 错、LLM 判 vulnerable 对）
- **完成标准**：样本集 + 消融结果 + 报告；若 B-2 成功 → 互补性立论闭环；失败 → 立论降级为"CPG 提取层"

### 8. 扩样本 27→50+ CVE ⬜
- **目标**：bootstrap CI 更窄；采集管线已有（GitHub Advisory API 分层抽样）
- **注意**：不要押注"LLM 反超"方向（当前 0.0%）；扩样本服务的是逻辑域窄结论的统计效力
- **风险**：采集管线弱点——重构式修复会让"同名文件 checkout"漏掉 vuln 侧（55419 教训），须先加双侧校验

### 9. DVWA 改造 ⬜（最低优先）
- **现状**：12 场景 × 3 安全级别 payload 相同，仅 cookie 变化（DeepSeek 评审确认）
- **倾向**：弃用 DVWA 基准（与 CPG 代码级主线无关，价值低）；或改造为不同级别不同 payload
- **决策点**：等主线实验（7/8）完成后由用户拍板

---

## 已发现的追加任务（防遗忘）

### A. 14B 主协议重跑 ⬜
- 现状：14B 结果（F1=0.531）是带摘要对照运行；主协议已改无摘要，14B 应重跑以对齐
- 依赖：P1-4 seed 参数完成后可执行（耗时，需 Ollama 14B 在线）

### B. 采集管线双侧文件校验 ⬜
- 55419 教训：重构式修复（文件移动/拆分）让"同名文件 checkout"漏掉 vuln 侧
- 目标：corpus_builder 采集时校验 vuln/fixed 双侧关键文件都存在

---

## 当前 HEAD 基线
- 主分支：`f4ef252`（P0 三项完成，已推送远程 origin/main）
- 主结果：无摘要 LLM F1=0.409 / CPGEvidence 0.435 / CPG 增益 +0.409
- 下次会话开始时：先读本文件确认已完成项，再决定下一步，不凭记忆猜测
