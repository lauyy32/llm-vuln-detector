# PA1 · pair-aware 判别门禁实测报告（第一步 ①，2026-09-04）

> 配套代码：`cpg/ablation/pair_aware_gate.py`（复用 d5_flowcut_baserate 流集装载，确定性，无需 Ollama）
> 数据产物：`.work/pair_aware_gate.json`（.work 并集源）、`.work/pair_aware_gate_d5a.json`（d5a 单源）
> 前置：终版计划第①步预期"纯增益 n_disc +2 → p 0.0625→0.031"（源于 D5-B cut=5 与 D5 文档"53502/54785 可借流集差异判别"）
> 结论先行：**pair-aware 门禁增益 = 0，计划假设被测量证伪**。9 个双标 CVE 的 fixed 侧 target-CWE 流**全部保留**（部分甚至增多），
> 全 74 集无任何一例"vuln 有 target 流 ∧ fixed 被切断"→ 流存在性层面的 pair-aware 判别力为零。

## 1. 方法与规则

pair-aware 门禁（PA）：对每个 CVE 比较 vuln/fixed 两侧的 **target-CWE 语义流集**（(cwe,file,sourceNode,sinkNode)）：

| 规则 | 条件 | 判定 | 含义 |
|---|---|---|---|
| rule1 | vuln 有 target 流 ∧ fixed 无 | (vulnerable, benign) | 补丁切断 target 流 → **判别成功** |
| rule2 | vuln ∧ fixed 均有 target 流 | (abstain, abstain) | fixed 仍有 target 流 → 无法确证已修（v9 无假良性纪律） |
| rule3 | vuln 无 target 流 | (abstain, abstain) | 无法断言 vuln（含 fixed-only 情形，不判反向） |

rule3 保证 inverted=0，n_disc = #rule1，p = 0.5^n_disc（单侧精确二项）。

## 2. 结果（74 CVE，两个数据源均复验）

| 数据源 | rule1 判别成功 | rule2 双标→双abstain | rule3 | n_disc | p |
|---|---|---|---|---|---|
| `.work`（v9+d5a 并集） | **0** | 9 | 65 | 0 | 1.0000 |
| `.work/d5a`（isSanitizer 单源） | **0** | 9 | 65 | 0 | 1.0000 |

rule2 消除的 9 个双标：12482 / 50181 / 50558 / 53502 / 53598 / 54785 / 67424 / 67428 / 73498。

## 3. 为什么是零：靶向诊断（关键证据）

对 D5-B 标记的 cut CVE 逐一比较 target-CWE 流集，方向**几乎全是反的**：

| CVE | target | vuln target 流 | fixed target 流 | 差异方向 |
|---|---|---|---|---|
| 53502 | CWE-022 | 1 | **2** | fixed **增多**（新增 file_path→literal_path sink） |
| 53598 | CWE-022 | 2 | 2 | 相等（语义级无 cut；D5-B 的 cut 来自他类流） |
| 67424 | CWE-918 | 2 | **3** | fixed **增多**（新增 utils.py 流） |
| 67428 | CWE-918 | 2 | **3** | fixed **增多**（同 67424） |
| 67435 | CWE-200 | 0（仅 CWE-918 流） | 0 | target 错配 + 双侧无 target 流 |

**没有任何 CVE 满足 rule1 的"补丁切断了 target 流"**。fixed 版本在 CodeQL 模型里普遍**保留甚至新增** target-CWE 流——
根因：这些 Python 补丁插入的净化器/守卫（safe_resolve_path / enforce_outbound_url / validate_safe_path 等，GT0 已逐一确认 17/17 真修复）
**不在 CodeQL 源→sink 模型的净化器集合内** → 污点流"穿过"净化器继续存在，甚至因新增代码产生新的建模路径。

## 4. 结论

1. **pair-aware 假设证伪**：计划预期的"流集差异 +2/74 → p 0.031"不成立——那 5 个 D5-B cut 的差异来自非 target 流或 fixed 侧**增多**，
   在 target-CWE 对齐的判定纪律下无一可用。
2. **净化器盲区下沉到证据层（pair 级坐实）**：不只是 CPGEvidence 判不准，而是**底层污点证据对全部 74 个 CVE 都不存在"fixed 侧 target 流被切断"这一事件**。
   这解释了为何 CPG-alone BA=0.500/MCC=0.000 且任何评分器设计（pair-aware、CWE 门禁、isSanitizer）都无法突破。
3. **瓶颈归因收口**：CPG 侧判别力瓶颈 = 证据层（净化器建模 + 提取覆盖），**不是模型容量，也不是评分器是否 pair-aware**。
   D5-A（stdlib isSanitizer）只切了 12 条无关流；残流全是**项目自定义净化器**所致。
4. **唯一杠杆转移至 ②**（修复 10+5 提取覆盖缺口 + 上游净化器建模）：只有当重建后的 taint 查询能识别项目自定义净化器，
   或覆盖缺口补齐露出新的 cut 事件，"流切断"判别信号才可能出现。若 ② 后仍无 → CPG-alone 维持随机 → 论文走负面结果方法论分支（已在计划中预写）。

## 5. 对 D5 文档的更正

D5-isSanitizer-flowcut.md §2 的表述"53502/54785 可借流集差异判别 2 例（pair-aware 门禁 OPEN）"**已被本实测否定**：
流集差异确实存在，但属 non-target / fixed-侧增多，target-CWE 纪律下不可判别。该"2/74"预期撤回。
（GT0 亦确认 53502/54785 的 fixed 版本**确实修复**——流仍在 = 净化器盲区，不 = 未修复。）

## 6. 复现

```bash
cd cpg/ablation
python pair_aware_gate.py --taint-dir .work     --dataset ../dataset.jsonl --out .work/pair_aware_gate.json
python pair_aware_gate.py --taint-dir .work/d5a --dataset ../dataset.jsonl --out .work/pair_aware_gate_d5a.json
```
