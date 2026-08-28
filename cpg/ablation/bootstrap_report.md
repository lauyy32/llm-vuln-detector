# Bootstrap 置信区间（P0-2）

> 36 版本 × 2000 次按 CVE 配对重采样（seed=42）

| scorer | F1(原) | mean | 95% CI |
| --- | --- | --- | --- |
| LocalLLMScorer | 0.400~ | — | [0.400, 0.625] |
| CPGEvidenceScorer | 0.270~ | — | [0.270, 0.538] |
| StructuralHeuristicScorer | 0.069~ | — | [0.069, 0.400] |
| CodeQLBaselineScorer | 0.000~ | — | [0.000, 0.182] |
| ConfigSigScorer | 0.000~ | — | [0.000, 0.000] |

**LLM − CPGEvidence 差值 CI: [0.023, 0.221]；LLM 高于 CPG 的比例 99.7%**