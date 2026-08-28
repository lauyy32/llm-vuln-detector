# 上下文消融实验 - 结果汇总

- 生成时间: 2026-08-28 13:07 UTC
- 数据来源: dataset.jsonl (真实 CVE)
- 样本版本数: 54  (vuln=正例 / fixed=负例)
- 模式: code
- 公告摘要注入: False（主结果默认关闭，避免标签泄漏）
- 跳过基线: False
- CodeQL: 2.26.2  python Security/CWE 定向查询（覆盖数据集 CWE-022/918/020/295）
- ConfigSig: 结构型/配置签名基线（CWE-295/059/200 精确签名；020/400/444/639/862/863 显式 abstain）
- CPGEvidence: 直接解析 CPG 污点切片文本做确定性判定（为 LocalLLMScorer 提供同吃切片文本的对照基线）

## 全局指标（正类=vulnerable；abstain 计为未判 vulnerable → 正例召回 0）

| scorer | mode | P | R | F1 | support | TP | FP | TN | FN |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| StructuralHeuristicScorer | code | 0.500 | 0.185 | 0.270 | 54 | 5 | 5 | 22 | 22 |
| CodeQLBaselineScorer | code | 0.500 | 0.037 | 0.069 | 54 | 1 | 1 | 26 | 26 |
| ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 54 | 0 | 0 | 27 | 27 |
| CPGEvidenceScorer | code | 0.526 | 0.370 | 0.435 | 54 | 10 | 9 | 18 | 17 |
| LocalLLMScorer | code | 0.529 | 0.333 | 0.409 | 54 | 9 | 8 | 19 | 18 |

## 分组指标（可污点类 vs 逻辑类）

| group | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| taint | StructuralHeuristicScorer | code | 0.500 | 0.833 | 0.625 | 12 |
| taint | CodeQLBaselineScorer | code | 0.500 | 0.167 | 0.250 | 12 |
| taint | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 12 |
| taint | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 12 |
| taint | LocalLLMScorer | code | 0.500 | 1.000 | 0.667 | 12 |
| logic | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | CodeQLBaselineScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 42 |
| logic | CPGEvidenceScorer | code | 0.571 | 0.190 | 0.286 | 42 |
| logic | LocalLLMScorer | code | 0.600 | 0.143 | 0.231 | 42 |

## 每 CWE 指标（StructuralHeuristic / ConfigSig / CPGEvidence）

| cwe | scorer | mode | P | R | F1 | support |
| --- | --- | --- | --- | --- | --- | --- |
| CWE-020 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | StructuralHeuristicScorer | code | 0.500 | 1.000 | 0.667 | 6 |
| CWE-059 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-295 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | StructuralHeuristicScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | StructuralHeuristicScorer | code | 0.500 | 0.667 | 0.571 | 6 |
| CWE-020 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-059 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-095 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-295 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-918 | ConfigSigScorer | code | 0.000 | 0.000 | 0.000 | 6 |
| CWE-020 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-022 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 6 |
| CWE-059 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-095 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-1333 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-200 | CPGEvidenceScorer | code | 0.667 | 0.500 | 0.571 | 8 |
| CWE-295 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-400 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 8 |
| CWE-444 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-601 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-639 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-770 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 2 |
| CWE-862 | CPGEvidenceScorer | code | 0.000 | 0.000 | 0.000 | 4 |
| CWE-863 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 2 |
| CWE-918 | CPGEvidenceScorer | code | 0.500 | 1.000 | 0.667 | 6 |

## 混淆矩阵（全局，行=预测 / 列=真值）

### StructuralHeuristicScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 5 | 5 | 0 | 0 |
| benign | 22 | 22 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CodeQLBaselineScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 1 | 1 | 0 | 0 |
| benign | 26 | 26 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### ConfigSigScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 0 | 0 | 0 | 0 |
| benign | 16 | 16 | 0 | 0 |
| abstain | 11 | 11 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### CPGEvidenceScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 10 | 9 | 0 | 0 |
| benign | 17 | 18 | 0 | 0 |
| abstain | 0 | 0 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

### LocalLLMScorer
| predicted \ truth | vulnerable | benign | abstain | error |
| --- | --- | --- | --- | --- |
| vulnerable | 9 | 8 | 0 | 0 |
| benign | 14 | 16 | 0 | 0 |
| abstain | 4 | 3 | 0 | 0 |
| error | 0 | 0 | 0 | 0 |

---

## 补充实验索引（头条 0.409 为 7B 无摘要单次运行）

本表为 54 版本（27 CVE 配对）下 `LocalLLMScorer` 以 **qwen2.5-coder-7B、
无公告摘要主协议** 的权威全局结果。下列扩展实验不重复计入本表，详见对应文件：

| 实验 | 关键结果 | 数据文件 / 报告 |
|------|----------|----------------|
| 摘要隔离（标签泄漏量化） | 带摘要 0.449 → 无摘要 0.409（−0.040）；B 组 0.316→0.000；CPGEvidence 不变 0.435 | `B3-消融与互补性报告.md` §6.6 |
| 模型规模消融（14B） | 14B 全局 F1=0.531（逻辑域 0.364→0.545；带摘要对照运行），CPG 增益缩至 +0.033 | `results_14b.csv`；`B3-消融与互补性报告.md` §6.4 |
| 多 seed 方差（3 seed） | 2×2 隔离消融 28/38/54 版本均 **零方差**；头条 0.409 为 7B 单 seed | `seeds/`；`B3-消融与互补性报告.md` §1/§5/§6 |
| 上下文形式消融 | CPG 切片 0.424 vs 行号列表 0.412（几乎持平） | `B3-消融与互补性报告.md` §6.5 |
| 统计显著性（bootstrap） | LLM vs CPGEvidence 差值 CI [-0.091, 0.000]、LLM 高于 CPG 比例 0.0%（未优于；带摘要"99.7% 显著"来自泄漏已撤销） | `bootstrap_report.md` |
| 业界工具对比（Bandit） | Bandit F1=0.182 vs 本系统 0.409（2.2×） | `bandit_report.md`；`B3-消融与互补性报告.md` §6.7 |
| 补丁验证（第二研究问题） | diff 注入修复 7/8 误报 | `patch_verify_report.md` |

> 注：逻辑子集样本量偏小（54 版本 logic 子集 n=42，常是 1–2 样本差异）；
> 无摘要下 LLM 未优于确定性解析器（bootstrap 差值 CI 含 0），LLM 独有贡献
> 需在逻辑域与 B-2 基准中另行论证；扩充至 50+ 真实 CVE 后结论将更稳健。
