# P0-1 · placebo 跨模型复现报告（2026-09-04）

> 目的：把全篇唯一 p<0.01 的正面发现（placebo 三臂）从"单模型 n=15 的 case study"升为"跨模型复现"。
> 协议：`patch_verify_control.py --dataset cpg/dataset_d1.jsonl`，CPG 双标记子集（理论 17，有效 n=15，2 个 fixed 源缺失），real/placebo/shuffled 三臂，本地 Ollama temp=0。
> 产物：`patch_verify_control_p0_2_full_{7b,14b,codellama-instruct}.json` + 对应 raw。

## 1. 结果（三模型对照，最终）

| 模型 | real (benign) | placebo (benign) | shuffled (benign) | real−placebo 单侧精确 p | 有效判定率 |
|---|---|---|---|---|---|
| qwen2.5-coder:7b（B4 原） | 8/15 (0.533) | 0/15 (0.000) | 3/15 (0.200) | **0.0039** | 45/45 |
| qwen2.5-coder:14b | 8/15 (0.533) | 0/15 (0.000) | **0/15 (0.000)** | **0.0039** | 45/45 |
| codellama:7b-instruct | 无法计算（1/15 有判定） | 无法计算（2/15） | 无法计算（0/15） | — | **3/45**（42/45 弃权 "?"） |

## 2. 结论

1. **placebo 正面发现跨规模复现**：qwen 7B→14B 下 placebo 0/15、real 8/15、p=0.0039 **逐字一致** —— 满足评审"跨模型复现"的核心要求（至少跨规模）。
2. **shuffled 在 14B 更干净**（0/15 vs 7B 3/15）——"无关但结构相似补丁"的误判在更大模型反而更少。
3. **跨族（CodeLlama-7b-instruct）不成立，但原因是"能力缺口"而非"结果矛盾"**：42/45 样本 verdict="?"（无法产出结构化 JSON 判定），只有 3 个可解析——CodeLlama-7b 在此结构化补丁判定任务上几乎完全弃权。这与 Devign 外部效度已观察到的"模型族依赖 + 弃权率分化"一致（qwen 弃权 82.4% vs CodeLlama 27.2% 是**函数级 vuln 检测**任务；在**补丁结构化判定**任务上二者行为反转——CodeLlama 反而大量弃权）。
4. **harness 卫生修复**：`ask_llm` 原未设 `num_predict` 生成上限 → CodeLlama 对混淆输入（shuffled 异源 diff）无限续写、600s 超时；已加 `num_predict=512`（qwen 无害，其 verdict 远小于此）。任何结构化判定评测都应设生成上限，否则"模型不收敛"伪装成"超时无结果"。

## 3. 对论文的意义

- placebo 结果从"单模型"升为"**跨规模复现（qwen 家族内）**"，正面牌的稳健性成立；跨族须如实写"**模型族依赖：Qwen 内稳健，CodeLlama-7b 无法产出有效结构化判定**"。
- 这**不是**削弱——它把 Devign 的"模型族依赖"结论延伸到补丁判定任务，形成一致的诚实叙事：**"LLM 补丁理解能力高度依赖模型族与任务格式，不能跨族泛化"**。
- 弃权样本（42/45）单列，不与有效 n 混算；论文 Threat 里明确"跨族外推受限"。
