# Bootstrap 置信区间（P0-2）

> 148 版本（74 CVE）× 2000 次按 CVE 配对重采样（seed=42）

| scorer | F1(原) | mean | 95% CI |
| --- | --- | --- | --- |
| LocalLLMScorer | 0.321 | — | [0.215, 0.410] |
| CPGEvidenceScorer | 0.330 | — | [0.229, 0.416] |
| StructuralHeuristicScorer | 0.196 | — | [0.098, 0.288] |
| CodeQLBaselineScorer | 0.051 | — | [0.000, 0.119] |
| ConfigSigScorer | 0.000 | — | [0.000, 0.000] |

**LLM − CPGEvidence 差值 CI: [-0.041, 0.008]；LLM 高于 CPG 的比例 24.2%**