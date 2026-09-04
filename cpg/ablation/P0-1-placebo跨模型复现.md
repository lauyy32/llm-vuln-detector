# P0-1 · placebo 跨模型复现报告（2026-09-04）

> 目的：把全篇唯一 p<0.01 的正面发现（placebo 三臂）从"单模型 n=15 的 case study"升为"跨模型复现"。
> 协议：`patch_verify_control.py --dataset cpg/dataset_d1.jsonl`，CPG 双标记子集（理论 17，有效 n=15，2 个 fixed 源缺失），real/placebo/shuffled 三臂，本地 Ollama temp=0。
> 产物：`patch_verify_control_p0_2_full_{7b,14b,codellama-instruct}.json` + 对应 raw。

## 1. 结果（三模型对照）

| 模型 | real (benign) | placebo (benign) | shuffled (benign) | real−placebo 单侧精确 p |
|---|---|---|---|---|
| qwen2.5-coder:7b（B4 原） | 8/15 (0.533) | 0/15 (0.000) | 3/15 (0.200) | **0.0039** |
| qwen2.5-coder:14b | 8/15 (0.533) | 0/15 (0.000) | **0/15 (0.000)** | **0.0039** |
| codellama:7b-instruct | （跑批中） | — | — | — |

## 2. 结论

1. **placebo 正面发现跨规模复现**：7B→14B 下 placebo 0/15、real 8/15、p=0.0039 **逐字一致** —— 满足评审"跨模型复现"的核心要求（至少跨规模）。
2. **shuffled 在 14B 更干净**（0/15 vs 7B 3/15）——"无关但结构相似补丁"的误判在更大模型反而更少，方向有利。
3. **跨族（CodeLlama）需 instruct 变体**：`codellama:7b`（base）对结构化 prompt **解释 JSON schema 而不作答**（verdict="?"），600s 超时——这是 base 模型不遵指令的工具性问题，非结果；已拉取 `codellama:7b-instruct` 重跑。

## 3. 对论文的意义

- placebo 结果从"单模型"升为"跨规模复现"（7B/14B 一致），正面牌的稳健性成立。
- 若 codellama-instruct 复现成立 → 进一步跨模型族；若 codellama-instruct 出现 1–2 例 placebo 误判（p 掉出 0.01），则如实写"qwen 家族内稳健、跨族待观察"。
- 弃权/失败样本单列，不与有效 n=15 混算。
