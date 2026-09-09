# CODEX 实验设计冻结（EXPERIMENT-DESIGN-FREEZE）

> 来源：外部评审 codex 的实验设计冻结执行令（2026-09-08）。
> 本文档为主 AI 基于原文的约束性重建（非逐字原文），入库以便可审计。
> **冲突裁决**：涉及"实验边界/estimand/样本/停止条件"时，以本文件为准。

## 〇、核心纪律（红线）

> 主 AI 可以实现、测试和报告观察值，但**无权**在看见结果后改变输入策略、扩大实验、升级机制结论或自行宣布 Gate PASS；所有主张只按冻结 estimand 和完成判据生成。

三项必须分开（不得混称"实验层已全部闭环"）：
1. `RQ1-R`：82 对修复语料后的端到端基线重跑；
2. `S-67435`：历史唯一剩余 clean 正例的哨兵复验；
3. `CR-1`：独立的上下文鲁棒性子实验。

## 一、RQ1-R：82 对主重跑

### 对象与定位
- 集合：D1 85 − {70486, 70492}（跨语言）− {53656}（复合）= **82 例**。
- 82 例对应 82 个 fix commit，来自 56 个仓库；open-webui 单仓 11 例 → 必须做仓库聚类敏感性。
- estimand 是"冻结的源码摘录+CPG 端到端管线能否区分同一 CVE 的 vulnerable/fixed 快照"，**不是**"LLM 内在漏洞理解能力"。

### 摘录策略
- 本轮使用 `representation = legacy-rq1-r0`（历史兼容），不得因 61539 结果调整（不删 license、不加 hunk 优先级、不调窗口、不加 CVE 分支）。
- 改进后的摘录器必须另立版本（`pair-hunk-r1`），不得混进本轮。

### 覆盖审计（不删样本，用于拆分）
- 每份 prompt 记录 FULL/PARTIAL/ABSENT（从上游 git diff -U0 获取每侧 Python 改动行）。
- 拆分：主结果（83 对端到端）+ 次结果（FULL/FULL 条件）+ 表示失败率（至少一侧 PARTIAL/ABSENT 比例）。

### 主 estimand
```
strict_success = prediction(vuln)==vulnerable AND prediction(fixed)==benign
θ_E2E = Σ(strict_success) / 82
```
报告：θ_E2E + Clopper–Pearson 95% CI、vuln/fixed acceptance、abstain 率、3×3 转移表、desired/inverse transition、McNemar（辅助）、FULL/FULL 条件子集、69 v1/14 v2 分层（仅描述）、leave-one-repository-out、repository-cluster bootstrap。

### 模型契约
```
model=qwen2.5-coder:7b
digest=完整64位每批前校验
temperature=0  top_p=1.0  num_ctx=32768  num_predict=1024  seed=20260908
summary=False  request_info=False
```
硬规则：166（实际 164）份 prompt 全冻结后才调用；固定 seed 打乱顺序；不打印单项 verdict；保存完整请求/响应；解析失败=invalid_output 不映射 abstain；日志写失败终止。

### 停止条件
- 调用开始后不得改 prompt/样本/阈值/estimand。
- digest/source SHA/prompt SHA/标签绑定错误 → 整批 INVALID 后重跑。
- 不许只补跑"结果不好"的案例。
- 完成预注册统计 + 一次独立复算后封口。

## 二、S-67435：哨兵（不是设计裁决器）

- 先冻结 RQ1-R 全部 prompt 后才运行，看到翻转也不能改主协议。
- 两种输出分开：
  1. 历史 prompt 复放诊断（vuln SHA `81748de7…`、fixed SHA `8f5a1a49…`，直接从历史 raw 日志读，各跑 3 次）；历史 digest 未知 → 只能称"当前 digest 对历史 prompt 的复放诊断"。
  2. 当前主协议输出（作为 82 对普通一对，进 82 对分子）。
- 哨兵无独立推断统计；不得因 67435 是历史正例而调其 CWE/CPG/窗口。

## 三、CR-1：上下文鲁棒性子实验

### 样本
- 排除 61539（发现样本）、67435（结果导向哨兵）；从其余 81 例分层抽 **30 CVE = 60 side-level prompt**。
- 抽样只用前模型属性（corpus v1/v2、CPG 有/无、prompt 长度四分位、仓库，每仓≤2，固定 SHA seed），**不得按历史 verdict/成功失败挑**。
- 理由：0 翻转时 prompt-level 双侧 95% 精确上界约 6%。

### 结构（禁解析拼接 Markdown）
- 用 `PromptDocument`（header/code_blocks/cpg_section/output_contract）+ renderer 统一渲染。
- 每块完整、预留 256 真实 token 扰动 slot、原代码字节/位置不变、变体不触发截断、variant 名不进模型输入。

### 四条件（重复测量，非 2×2）
| 条件 | 内容 |
|---|---|
| C0 | baseline 无新增块 |
| C1 | 256-token license 注释块 |
| C2 | 256-token 非 license 中性注释块 |
| C3 | 256-token AST 可解析惰性 Python 块 |
C1–C3：token 等（±1）、行数/文件头/插入位置同、无 CVE/CWE/vulnerable/fixed/security/fix 等词、不引用项目/样本标识、3 套冻结 block set 按 Latin-square/固定 seed、双 reviewer 看结果前确认任务无关。

### estimand
- 主：`φ_license = P(verdict(C1)!=verdict(C0))`，报翻转率 + 转移矩阵 + 95% CI。
- 次：φ_neutral、φ_code、correct→incorrect 方向、CVE 级任一侧翻转率、license vs matched-neutral 配对差异、cluster bootstrap；两个内容特异性比较用 Holm。
- 结论边界：观察到翻转→"存在上下文敏感性"；只有 license 相对 neutral 显著更高且两套 block 方向一致→"license 特异效应"；否则不得写 license 机制。

### 运行规则
30 CVE × 四条件 × 两侧 = 240 次主调用；固定 primary seed + 10% 技术重复；prompt/SHA 先冻结；跑完 240 次生成预注册统计后结束；新想法进 backlog。

## 四、四天截止表

| 日程 | 交付 |
|---|---|
| Day1 上午 | A6、RQ1-R/CR-1 protocol、统计 spec |
| Day1 下午 | 164 主 prompt + 覆盖表 + 240 上下文 prompt + 全部 SHA（零模型调用）|
| Day2 上午 | reviewer 审工件签 RUN_LOCK |
| Day2 下午 | 67435 哨兵 + RQ1-R 164 次 |
| Day3 | RQ1-R 分析 + CR-1 240 次 |
| Day4 | CR-1 分析 + cluster sensitivity + 冻结 |

超 Day4 非 P0 建议进 backlog。P0 仅限：标签/数据源错、hash 错绑、digest 不符、请求响应丢失、统计实现不符公式。
