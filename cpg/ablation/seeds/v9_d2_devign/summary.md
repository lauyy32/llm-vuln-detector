# D2 Devign 外部效度（LocalLLMScorer qwen2.5-coder:7b）

- 生成时间：2026-09-03T05:07:40.728477+00:00
- 样本：决定集 n=88 / abstain=412 / 总=500（平衡采样，每类 250）
- 覆盖率（非 abstain）：0.176

## 独立样本指标（McNemar 不适用）

| 指标 | 值 |
| --- | --- |
| 灵敏度 Sensitivity | 0.436 |
| 特异度 Specificity | 0.510 |
| **平衡准确率 BA** | **0.473** |
| 精确率 Precision | 0.415 |
| 召回率 Recall | 0.436 |
| **F1** | **0.425** |
| **MCC** | **-0.054** |

## 平凡基线对照（暴露 F1 陷阱）

- 平衡样本下「全判 vulnerable」：F1=**0.667**、BA=0.500、MCC=+0.000
- **判定器 F1=0.425 <= 平凡基线 0.667**（与 D1 同一口径：F1 在 50% 正类语料失效）
- **判定器 MCC=-0.054** 接【随机】(0) → 结论：外部基准上 LLM 打分器判别力接近随机。

## 与课题核心 claim 的关系

- 本结果仅回答「LLM 打分器在通用函数级 vuln 检测上的独立判别力」，
  与 D1「补丁边界判别」是**不同 claim**，不可混用为「CPG 互补/必要」证据。
- C/C++ CPG Scorer 出范围（CodeQL-python 仅覆盖 Python）；PublishedLLMBaseline 需 API Key，依规递延。