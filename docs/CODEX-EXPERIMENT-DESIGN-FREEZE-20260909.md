# CODEX 实验设计冻结（EXPERIMENT-DESIGN-FREEZE）

> 来源：外部评审 codex 的「后续实验冻结执行令」，逐字转录（原文审计基线 `origin/main = 644f713`）。
> 本文件为当前阶段的上位执行约束。冲突裁决：**实验边界以本文件为准**。
> **执行状态（2026-09-09 后续发现）**：原文写"83 对"（D1 85 − {70486,70492}）；后经重建发现 53656 为多父复合提交，实际 eligible = 82。此修订见 IMPLEMENTATION-PLAN 的 P0-8 / scope，正文保留 codex 原文数字。

---

# 后续实验冻结执行令

你的角色从现在起是"实现冻结协议"，不是继续发现一个现象就新增解释或重写方法。以下三项必须分开：

1. `RQ1-R`：83 对修复语料后的端到端基线重跑；
2. `S-67435`：历史唯一剩余 clean 正例的哨兵复验；
3. `CR-1`：独立的上下文鲁棒性子实验。

它们均不等同于 v4 四臂 patch-sufficiency 主实验，不得混称"实验层已全部闭环"。

## 一、先封存 A5，不再围绕 61539 返工

A5 的四组输出真实，但机制实验无效，追加 A6 说明后停止继续修改 61539：

- `ablate_61539.py:101` 把 `utils.py` 追加到已被截断的 `test_utils.py` 后，实际形成：

  ```python
  "choices": [# ===== FILE: utils.py ...
  ```

  新文件头粘进未完成语句。

- `v1_add_utils` 为 9,344 字符，违反原 8,000 字符摘录契约。
- `v2_no_utils` 删除块后没有用释放的预算回填后续内容，因此不是"同一摘录器下不含 utils"的反事实。
- `utils.py L1–100` 不是纯 license：license 约 13 行，其余是 import、常量和实现；该文件本身也是安全提交修改文件，只是安全 hunk 位于约 L750，当前片段没有展示。
- A5 未传固定 seed，按变体顺序成组运行；3/3 只能称本机稳定性抽查。
- 61539 已被反复观察，不能再进入确认性上下文实验。

A6 固定措辞：

> A5 输出保留作审计记录；因内部代码粘连、预算违规及反事实未重新经过摘录器，其机制性解释作废。61539 仅作为发现型 pilot，不进入 CR-1 的估计样本。

此后不再为 61539 增加 A7/A8。

## 二、RQ1-R：83 对主重跑

### 1. 研究对象与定位

集合严格取：

```text
D1 85例 − {70486, 70492} = 83例
= 69个验证干净的v1样本 + 14个重建v2样本
```

仓库现状还显示：

- 83 例对应 83 个不同 fix commit；
- 来自 56 个仓库；
- `open-webui/open-webui` 单仓占 11 例，因此必须做仓库聚类敏感性。

本轮估计的是：

> 当前完整 digest 下，冻结的"源码摘录+CPG"端到端管线能否区分同一 CVE 的 vulnerable/fixed 快照。

它不是"LLM 内在漏洞理解能力"，因为摘录失败也属于该管线的失败。

### 2. 禁止此时改摘录策略

RQ1-R 使用当前无摘要、历史兼容的摘录器，版本命名为：

```text
representation = legacy-rq1-r0
```

不得因为 61539 的结果：

- 删除 license；
- 给安全 hunk 加特殊优先级；
- 手工调整某个文件顺序；
- 扩大/缩小单例窗口；
- 对某个 CVE 添加分支。

这样做的理由不是当前摘录器完美，而是本轮任务是把历史基线在修复语料、统一 digest 下重新跑清。改进后的摘录器必须另立版本，不能混进本轮。

### 3. 在不改变 prompt 文本的前提下补"覆盖审计"

生成模型输出前，为 166 份 prompt 全部记录：

```text
FULL / PARTIAL / ABSENT
```

机械定义：

- 从上游 `git diff -U0 parent fix` 获取每侧对应的 Python 改动行；
- FULL：该侧所有改动 hunk 均进入摘录；
- PARTIAL：至少一个但非全部进入；
- ABSENT：一个也未进入；
- added/removed 文件只检查实际存在的相应侧；
- 同时记录是否在完整行、完整文件块边界结束。

不要据此删除主分析样本。它用于拆分：

- 主结果：83 对端到端管线表现；
- 次结果：FULL/FULL 子集上的模型条件表现；
- 表示失败率：至少一侧 PARTIAL/ABSENT 的比例。

当前 `_load_sample_code()` 在 `run_ablation.py:180` 会按字符切断语句；本轮保留该行为以复现管线，但必须记录为表示属性，不能再把这类失败全部归因于模型。

### 4. 主 estimand

对每个 CVE：

```text
strict_success =
    prediction(vuln) == vulnerable
    AND prediction(fixed) == benign
```

主估计量：

```text
θ_E2E = Σ(strict_success) / 83
```

报告：

- `θ_E2E` 及 Clopper–Pearson 95% CI；
- vuln acceptance；
- fixed acceptance；
- vuln/fixed 各自 abstain 率；
- 3×3 verdict 转移表；
- desired transition 与 inverse transition；
- exact McNemar/sign test 只作辅助，不作为唯一结论；
- FULL/FULL 条件子集结果；
- 69 个 v1 与 14 个 v2 分层结果，仅描述，不作因果比较；
- leave-one-repository-out；
- 以 repository 为 cluster 的固定 seed bootstrap CI。

不得再次写"随机水平"，除非先明确定义随机分类器及其类别概率。

### 5. 运行前必须一次性生成的工件

建议固定目录：

```text
cpg/ablation/.work/rq1-r-v3/
```

必须先于任何模型调用落盘：

- `protocol.json`
- `canonical_corpus_manifest.json` 及 SHA
- `source_manifest.jsonl`：166 行，含树 SHA
- `db_manifest.json`：源码树 SHA、CodeQL 版本、7 个 query SHA
- `prompt_manifest.jsonl`：166 行，完整 prompt 路径、SHA、token 数
- `coverage_manifest.jsonl`
- `run_schedule.json`：固定随机顺序
- `analysis_spec.json`
- `RUN_LOCK.json`

`canonical_manifest.py` 当前生成日期是硬编码且没有 HEAD 字段，不能直接充当 run lock；新 run manifest 必须写入真实 HEAD、schema version 和自身 SHA。

### 6. 模型调用契约

统一使用：

```text
model=qwen2.5-coder:7b
digest=完整64位并在每批前校验
temperature=0
top_p=1.0
num_ctx=32768
num_predict=1024
seed=20260908
summary=False
request_info=False
```

其他硬规则：

- 166 份 prompt 全部冻结后才能调用；
- 顺序由公开固定 seed 打乱，vuln/fixed 交错；
- 运行期间不打印单项 verdict；
- 保存完整请求、完整原始 HTTP 响应和解析结果；
- 解析失败是 `invalid_output`，不得自动映射为 `abstain`；
- 网络错误最多按预注册次数重试，同一 payload 不变；
- 日志写入失败必须终止。现有 `_log_raw()` 在 `scorers.py:300` 静默忽略写入失败，主跑批不得复用这一 fail-open 行为。

### 7. RQ1-R 停止条件

开始模型调用后：

- 不得改 prompt、样本、阈值、estimand；
- 若发现 digest、source SHA、prompt SHA 或标签绑定错误，整批标记 INVALID，修复后整批重跑；
- 不允许只补跑"结果不好"的案例；
- 166 份原始响应齐全后立即分析；
- 完成预注册统计与一次独立复算后封口；
- 任何新机制想法进入 backlog，不再扩建 RQ1-R。

## 三、S-67435：哨兵，不是设计裁决器

67435 的任务是检查历史正例在当前运行时的表现，不负责决定摘录策略。

### 1. 必须在何时运行

先冻结 RQ1-R 全部 166 份 prompt 及 `RUN_LOCK.json`，再运行 67435。这样即使看到它翻转，也不能改主协议。

### 2. 两种输出严格分开

#### 历史 prompt 复放诊断

当前 2/82 主张对应的 v10 D1 历史 prompt 应绑定：

- vuln SHA：`81748de7c78d73f621d85c8ee3811666f2d9ffc888a6f9b142c61aa989bb1c57`
- fixed SHA：`8f5a1a495097115df5acb60acd04a417d7909b1208308f8f959449821316f896`

直接从 tracked 历史 raw 日志读取字节，不重新生成。历史 digest 未知，所以只能称：

> 当前 digest 对历史 prompt 的复放诊断。

不得称严格复现旧模型。

#### 当前主协议输出

67435 同时作为 83 对中的普通一对，使用 RQ1-R 冻结 prompt 和固定 seed。它的该项结果才进入 83 对分子。

### 3. 哨兵规则

- 历史 prompt 各运行 3 次，可报告 3/3 分布；
- 语义输出无论是什么都不触发改协议；
- 只有 hash/digest/请求落盘失败才停止；
- 哨兵没有独立推断性统计；
- 不得因 67435 是历史正例而调整其 CWE、CPG 或窗口。

## 四、CR-1：真正的上下文鲁棒性子实验

### 1. 定位

61539 只作为发现型 pilot。确认性/预先冻结的 CR-1 样本中排除：

```text
61539（发现样本）
67435（结果导向选中的哨兵）
```

从其余 81 例中，在任何新模型输出产生前，固定抽取 30 个 CVE，即 60 个 side-level prompt。

抽样只使用前模型属性分层：

- corpus 版本 v1/v2；
- CPG 有命中/无命中；
- baseline prompt 长度四分位；
- 仓库；
- 每仓最多 2 例；
- 固定公开 SHA seed。

不得按历史 verdict、成功/失败挑样本。

30 个 CVE/60 个 prompt 的理由：若 0 次翻转，prompt-level 双侧 95% 精确上界约 6%；10 例 pilot 的区间过宽，不足以成为论文贡献。

### 2. 不再手工修改渲染后 prompt

必须先实现结构化对象：

```text
PromptDocument
  header
  code_blocks[]
  cpg_section
  output_contract
```

在 `code_blocks` 层做变体，再由一个 renderer 统一渲染。禁止正则切成字符串后拼接。

基础 prompt 要求：

- 每个文件块和每一行完整；
- 预留 256 个真实模型 token 的 perturbation slot；
- 原始安全代码在所有条件下字节及位置完全一致；
- 不因加入变体触发截断；
- 所有变体总输入均在 context 上限内；
- variant 名称不进入模型输入。

### 3. 四条件设计

这是四条件重复测量，不再叫 2×2：

| 条件 | 内容 |
|---|---|
| C0 | baseline，无新增块 |
| C1 | 256-token license 注释块 |
| C2 | 256-token 非 license 中性注释块 |
| C3 | 256-token AST 可解析的惰性 Python 块 |

C1–C3 须：

- token 数相等（允许 ±1）；
- 行数、文件头和插入位置相同；
- 不出现 CVE/CWE/vulnerable/fixed/security/fix 等词；
- 不引用目标项目或样本标识；
- 使用 3 套预先冻结的 block set，按 Latin-square/固定 seed 分配，避免单一模板特异性；
- 两位 reviewer 在看模型输出前确认任务无关性。

### 4. estimand

主估计：

```text
φ_license = P(verdict(C1) != verdict(C0))
```

在 60 个 prompt 上报翻转率、转移矩阵和 95% CI。

次要：

- `φ_neutral`
- `φ_code`
- correct→incorrect 与 incorrect→correct 方向；
- CVE 级"任一侧翻转率"；
- license vs matched-neutral 的配对差异；
- repository-cluster bootstrap。

若做两个内容特异性比较，使用 Holm 校正。

允许的结论边界：

- 观察到翻转：可称"当前模型/表示下存在上下文敏感性"；
- 只有 license 相对 matched-neutral 显著更高，且至少两套 block 方向一致，才可称"license 特异效应"；
- 否则不得把一般长度/附加上下文效应写成 license 机制。

### 5. 运行规则与截止

- 30 个 CVE、四条件、两侧：240 次主调用；
- 固定一个 primary seed；
- 再对固定抽取的 10% 输入做技术重复，不按结果挑；
- 全部 prompt 和 SHA 先冻结；
- 固定随机交错顺序；
- 不得因中途结果增加第五个条件或扩大样本；
- 跑完 240 次、生成预注册统计后结束；
- 新想法全部进入投稿后 backlog。

## 五、四天截止表

| 日程 | 必须交付 |
|---|---|
| Day 1 上午 | A6；RQ1-R/CR-1 protocol；统计 spec |
| Day 1 下午 | 166 份主 prompt、覆盖表、60×4 上下文 prompt、全部 SHA；零模型调用 |
| Day 2 上午 | reviewer 只审工件与不变量，签 `RUN_LOCK` |
| Day 2 下午 | 67435 哨兵；随后 RQ1-R 166 次 |
| Day 3 | RQ1-R 分析与独立复算；CR-1 240 次 |
| Day 4 | CR-1 分析、cluster sensitivity、最终结果冻结 |

超出 Day 4 仍出现非 P0 改进建议，一律进入 backlog。这里的 P0 仅限：

- 标签/数据源错误；
- prompt 或 source hash 错绑；
- digest 不符；
- 请求/响应丢失；
- 统计实现不符合冻结公式。

措辞、可视化、更多机制猜想都不能继续阻塞跑批。

最终纪律只有一句：

> 主项目 AI 可以实现、测试和报告观察值，但无权在看见结果后改变输入策略、扩大实验、升级机制结论或自行宣布 Gate PASS；所有主张只按冻结 estimand 和完成判据生成。
