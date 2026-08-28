# Bootstrap 置信区间（P0-2）

> 36 版本 × 2000 次按 CVE 配对重采样（seed=42）

| scorer | F1(原) | mean | 95% CI |
| --- | --- | --- | --- |
| LocalLLMScorer | 0.364~ | — | [0.364, 0.643] |
| CPGEvidenceScorer | 0.250~ | — | [0.250, 0.579] |
| StructuralHeuristicScorer | 0.100~ | — | [0.100, 0.471] |
| CodeQLBaselineScorer | 0.000~ | — | [0.000, 0.250] |
| ConfigSigScorer | 0.000~ | — | [0.000, 0.000] |

**LLM − CPGEvidence 差值 CI: [-0.015, 0.230]；LLM 高于 CPG 的比例 91.6%**