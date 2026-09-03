# B6 弃权（Abstention）分析（P1-2）

> 关联任务：P1-2 弃权 / abstention 分析
> 数据源：`cpg/ablation/seeds/v8_d1_final/results.csv`（85 对 / 170 版本 / 4 scorer / code 模式）

## 1. 编码约定

`predicted ∈ {vulnerable, benign, abstain}`。abstain 在配对指标中计为「未判 vulnerable」
（→ 若 truth=vulnerable 则记 FN，若 truth=benign 则记 TN）。

## 2. 各 Scorer 弃权率（code 模式）

| Scorer | abstain / total | 弃权率 |
|--------|-----------------|--------|
| StructuralHeuristicScorer | 0 / 170 | 0.0% |
| CPGEvidenceScorer | 15 / 170 | 8.8% |
| LocalLLMScorer | 20 / 170 | 11.8% |
| ConfigSigScorer | 51 / 170 | **30.0%** |

按样本聚合（170 个版本）：

- 四 scorer 全部 abstain：0 / 170（0.0%）
- 至少一个 scorer abstain：**79 / 170（46.5%）**

即近半数样本存在「至少一方弃权」，集成层的弃权天花板不可忽略。

## 3. 弃权率的组间差异（taint vs logic）

| Scorer | taint 弃权率 | logic 弃权率 |
|--------|--------------|--------------|
| CPGEvidenceScorer | 4.5%（2/44） | 10.3%（13/126） |
| ConfigSigScorer | 2.3%（1/44） | 39.7%（50/126） |
| LocalLLMScorer | 9.1%（4/44） | 12.7%（16/126） |

规律：**logic（纯逻辑/状态类）CWE 的弃权率系统性高于 taint 类**——这类 CVE 无污点流
证据，CPG 类 scorer 与签名法缺乏可判定信号，倾向弃权。

## 4. ConfigSig 的「设计性弃权」

ConfigSigScorer 对 6 个 CWE **100% 弃权**（签名法无法证明「某处缺少某检查」）：

| CWE | 弃权率 | n |
|-----|--------|---|
| CWE-400 | 100% | 22 |
| CWE-639 | 100% | 8 |
| CWE-020 | 100% | 6 |
| CWE-862 | 100% | 6 |
| CWE-444 | 100% | 4 |
| CWE-863 | 100% | 2 |

对其余（taint / 结构型）CWE 弃权率为 0。这是**按目标 CWE 的显式弃权门禁**，非失效。

## 5. request 模式的系统性弃权（请求侧分析上限）

按 `SPEC §8` 与 `scorers.py` 实现：request 模式 `ctx.cpg_slices is None`
（无代码上下文）→ 所有依赖 CPG/源码的 scorer **显式 abstain**。即请求侧（仅 HTTP payload）
在本课题 code-level 判别框架下**覆盖率为 0**——这正式界定了「请求侧分析上限」，
也是立论收敛为「补丁边界判别力研究（code-level）」、而非「请求侧 payload 分类器」的依据。

## 6. 结论

- 弃权是**设计性 + 信号性**双重现象：ConfigSig 按 CWE 门禁弃权（确定、可复现），
  CPG/LLM 在 logic 类高弃权反映「无污点证据即无判别信号」；
- 46.5% 样本存在至少一方弃权 → 任何「全判 vulnerable/benign」的平凡基线都未计入弃权，
  而真实 scorer 的弃权应作为「信息不足」单独报告，不得与 FN 混算掩盖；
- 论文须在指标表中单列各 scorer 弃权率（本表即为候选内容），并说明 request 模式弃权即
  请求侧分析的上限。
