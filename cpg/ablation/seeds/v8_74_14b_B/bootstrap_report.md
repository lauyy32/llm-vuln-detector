# Bootstrap 置信区间（P0-2）

> 148 版本（74 CVE）× 2000 次按 CVE 配对重采样（seed=42）

| scorer | F1(原) | mean | 95% CI |
| --- | --- | --- | --- |
| LocalLLMScorer | 0.073 | — | [0.000, 0.156] |
| CPGEvidenceScorer | 0.000 | — | [0.000, 0.000] |
| StructuralHeuristicScorer | 0.000 | — | [0.000, 0.000] |
| CodeQLBaselineScorer | 0.051 | — | [0.000, 0.119] |
| ConfigSigScorer | 0.000 | — | [0.000, 0.000] |

**LLM − CPGEvidence 差值 CI: [0.000, 0.156]；LLM 高于 CPG 的比例 95.6%**