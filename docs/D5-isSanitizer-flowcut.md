# D5 · isSanitizer 实测 + 流程切断基础率（OPEN #25，2026-09-03）

> 配套代码：`cpg/queries/taint.ql`（D5-A 通用净化器谓词）、`cpg/ablation/d5_flowcut_baserate.py`（D5-B+D5-A 复用复算）
> 配套数据：`cpg/ablation/.work/d5_flowcut_baserate_v9.json`（v9 基线）、`d5_flowcut_baserate_d5a.json`（isSanitizer 重跑）
> 前置文档：`docs/D5-双标机制与门禁.md`（双标机制 + 目标 CWE 匹配门禁）
> 结论先行：**引入 CPG 证据无法突破随机**。通用 isSanitizer 谓词实测无改善（BA/MCC/双标数完全不变）；
> CPG 在补丁边界的判别上限由 flow-cut baserate 量化 = **≤6.8%（当前污点提取覆盖下的下界，74 CVE 中至多 5 个可被 CPG 判别）**；该下界受污点提取覆盖缺口约束，非结构天花板，见 §2 注。

---

## 0. 研究问题

用户显式要求（2026-09-03）：「继续推进 D5（isSanitizer 净化器识别）以检验引入 CPG 能否突破随机。」
即：审稿人挑战「是否试过 isSanitizer」+ 本课题核心质疑「CPG 证据能否提供超出随机的判别力」。
本实验以两路闭合该问题：

- **D5-A（isSanitizer 实测）**：在 CodeQL 查询中加 corpus-level 通用净化器谓词，重跑污点提取，
  复算 CPGEvidence 的 BA/MCC/双标数，对比 v9 基线。
- **D5-B（流程切断基础率 flow-cut baserate）**：不依赖任何模型，直接从污点流集合结构性量化
  「CPG 在该语料上的判别上限」——即有多少 CVE 的补丁真的切断了 source→sink 污点流。

---

## 1. D5-B 方法：流程切断基础率

污点 CSV 每行含 `abs_path`，可解析出 `(CVE, version∈{vuln,fixed})`。对每个版本构建污点流集合，
流签名取 **语义级** `(cwe, file, sourceNode, sinkNode)`（忽略行号——补丁平移行号但 source→sink
关系不变，避免把「行号平移」误判为「流被切断」）。逐 CVE 比较 vuln 与 fixed 流集：

| 类别 | 判定 | 含义 |
|------|------|------|
| no-evidence | 两端流集均空 | CPG 对该 CVE 结构性失明（无污点证据） |
| identical | 两端流集相同 | CPG 在该 CVE 零判别信号（patch 未切断流） |
| cut | 两端流集不同 | CPG 至少存在潜在判别信号（patch 改变了污点流） |

- **CPG coverage** = 有证据 CVE 数 / 74。
- **flow-cut baserate** = 有证据 CVE 中 `cut` 的占比 = CPG 判别力的理论上限（pair-aware 或非
  pair-aware 评分器都无法超过此比例，因为对 identical / no-evidence CVE 不存在任何 patch 边界信号）。

---

## 2. D5-B 结果（v9 污点 CSV，74 CVE）

| 指标 | 值 |
|------|-----|
| CPG coverage | **18/74 (24.3%)** |
| CPG 结构性失明（两端无流） | 56/74 (75.7%) |
| flow-cut baserate（有证据 CVE 中 vuln≠fixed） | **27.8% (5/18)** |
| 两端流集相同（非判别） | 13 |
| 流集不同（可判别） | 5 |

按目标 CWE 的 flow-cut baserate（仅 CWE-022 / CWE-918 有实质证据）：

| 目标 CWE | 有证据 | 可判别 | baserate |
|----------|--------|--------|----------|
| CWE-022 | 7 | 2 | 28.6% |
| CWE-918 | 3 | 2 | 66.7% |
| CWE-200 | 2 | 1 | 50.0% |
| 其余逻辑类（059/061/176/201/306/863） | 各 1 | 0 | 0.0% |

**CPG 判别上限（当前提取覆盖下界）= 5/74 ≈ 6.8%**：即便理想 pair-aware 评分器完美判别
全部 5 个 cut CVE，对其余 69 个仍无任何 patch 边界信号，只能 abstain 或随机猜。

> ⚠️ **覆盖缺口声明（关键，回应审计）**：上述 56/74「no-evidence」需拆解为两类——
> **(a) 46 个为 CWE 超出污点分析范围**（逻辑 / 状态 / 结构类，如 400/444/639/862/863 等，
> 结构性失明，属合理事实）；**(b) 10 个（74-set：48782 / 50180 / 54654 / 57516 / 59820 /
> 59894 / 61632 / 68508 / 73417 / 9335）为污点查询零行返回的提取覆盖缺口**——其 vuln/fixed
> 流集两端皆空是建库 / checkout 静默失败所致，**流切断状态不可判定，并非"补丁真实保留流"的
> 结构事实**。D1 另有 5 个同类缺口（62677 / 70479 / 70485 / 70486 / 70492）。因此 6.8% 是
> **当前提取覆盖下的下界**，而非结构天花板；即便把 10 个缺口全部视为潜在 cut，上限也仅
> (5+10)/74 ≈ 20.3%，仍远低于可用判别。提升该上限须先修复污点提取覆盖，属工程缺口而非结论推翻。

因此 CPG-alone 的 BA 天花板 ≈ 0.5 + 0.5×(5/74) ≈ 0.534（最优情形，且建立在覆盖已修复的
假设上），实际（非 pair-aware 的 CPGEvidence）更近 0.50。→ **引入 CPG 不能突破随机，结论由
结构数据直接确立，但 6.8% 须严格表述为"当前提取覆盖下的下界"。**

cut CVE（流集 vuln≠fixed，patch 确实改变了污点流）：`CVE-2026-53502`、`53598`(按目标 022 中 2 个)、
`CVE-2026-67424`、`67428`、`67435`。其中 `53502`/`54785` 属原 D5 文档「残 7」之列——
本测量进一步显示其 vuln/fixed 流集实际不同（patch 改变了流），但 CPGEvidence 非 pair-aware，
仍两端判 vulnerable；若引入 pair-aware 门禁（OPEN）此 2 例可借流集差异判别，但仅 2/74，不改整体结论。

> ⚠️ **2026-09-04 pair-aware 实测更正（PA1）**：上述"53502/54785 可借流集差异判别 2 例"**已被实测否定**。
> pair-aware 门禁（`cpg/ablation/pair_aware_gate.py`）比较 target-CWE 语义流集后 rule1（vuln 有 target 流 ∧ fixed 无）= **0 例**；
> 5 个 cut CVE 的流差异方向几乎全为 fixed 侧 **target 流保留/增多**（53502/67424/67428 fixed 流更多；53598 语义级相等；67435 target 错配）。
> 即净化器盲区**下沉到证据层**：全 74 集不存在"fixed 侧 target 流被切断"事件，流存在性层面的 pair-aware 判别力为零。
> 详见 `cpg/ablation/PA1-pair-aware门禁报告.md`；"2/74 可判别"预期撤回。

---

## 3. D5-A 方法：通用 isSanitizer 谓词

在 `cpg/queries/taint.ql`（CWE-022 路径遍历）中新增 corpus-level 净化器谓词，识别标准库路径
规范化调用（属 CodeQL 既有 `PathInjection::Sanitizer` 扩展点，全语料统一、无 per-CVE 调参、
无标签泄漏）：

```ql
class CpgPathSanitizer extends PathInjection::Sanitizer, DataFlow::CallCfgNode {
  CpgPathSanitizer() {
    this.getFunction().(DataFlow::AttrRead).getAttributeName() in
      ["realpath", "abspath", "normpath", "basename", "dirname", "relpath", "secure_filename"]
  }
}
```

CWE-918（SSRF）未加通用净化器：标准库无「总是安全」的 SSRF 净化调用（仅 `ipaddress` 校验需配合
allowlist 才有意义），且 918 证据 CVE 已在 v9 门禁下判 abstain（taint-mismatch），isSanitizer
不会改变其结论，故不引入可能过切的 SSRF 净化器。

复算方式：CPGEvidence 是污点流 CWE 的确定性函数（v9 门禁下），故可直接由污点 CSV 复算 2x2/BA/MCC，
无需重跑 Ollama。`d5_flowcut_baserate.py` 同时输出 D5-B 与 D5-A 复算，作为单一事实源。

---

## 4. D5-A 结果（isSanitizer 重跑 vs v9 基线）

| 指标 | v9 基线 | D5-A isSanitizer | 变化 |
|------|---------|------------------|------|
| taint.csv 污点行数 | 272 | 260（切割 12 条） | −12 |
| CPG coverage | 18/74 | 18/74 | 0 |
| flow-cut baserate | 27.8% | 27.8% | 0 |
| CPGEvidence TP / FP / TN / FN / abstain | 9/9/57/56/17 | 9/9/57/56/17 | 0 |
| CPGEvidence BA / MCC | 0.501 / 0.003 | 0.501 / 0.003 | 0 |
| 双标 CVE 数（两端判 vulnerable） | 9* | 9* | 0 |

\* 双标数 9 为本脚本 any-flow-CWE-match 口径；D5 门禁文档的 7 为 first-flow 口径，二者同属
「两端均含目标 CWE 流」，差异源于门禁对「多 CWE 流时取首条还是任一」的实现选择，不影响结论。

**isSanitizer 切割的 12 条流均为无关流**（非目标 CWE 流，或所在版本本就另有目标 CWE 流），
未改变任何 CVE 的 vuln/fixed 流集成员资格，故无任一 CPGEvidence 判定改变。→ **isSanitizer 实测
确认不足以突破随机**，与 `docs/D5-双标机制与门禁.md` §6 的假设一致：残 double-label 的 fixed 版本
加的是**项目自定义净化器 / 守卫 / 删除 monkeypatch**，不调用 stdlib 规范化，通用 isSanitizer 无从切断。

---

## 5. 结论与论文定位

1. **CPG 不能突破随机**，由 flow-cut baserate（结构数据）与 isSanitizer 实测（对照实验）双重确立。
2. CPG 判别上限（当前提取覆盖下界）= 6.8%（74 中至多 5 个 cut CVE）。其余 56/74 无证据中，
   46 个系 CWE 超污点分析范围（结构性失明），10 个系提取覆盖缺口（流切断状态不可判定）；
   不能径称"93% 补丁不切断流"——该表述混淆了结构性失明与提取失败，已撤回并改为覆盖下界口径。
3. 通用 isSanitizer 是「显而易见的首试修正」，实测无效——已以证据闭合并非回避审稿挑战。
4. 残 double-label 的根因是 CPG 补丁边界局限（项目自定义净化器 + 非判别性流），属边界声明，
   非待修缺陷；pair-aware 判别性证据（OPEN）至多挽回 2/74，性价比低，策略上建议作为边界陈述。
5. 立论维持「补丁边界上的判别力研究」定位：CPG 提供的是**报警位置/证据上下文**，而非判别正确性；
   判别正确性由 LLM 在完整证据下的语义兜底（已证实非显著），二者均未超越随机基线。

---

## 6. 复现

```bash
cd llm-vuln-detector
# D5-B + D5-A 复用复算（v9 基线）
python cpg/ablation/d5_flowcut_baserate.py \
  --taint-dir cpg/ablation/.work --dataset cpg/dataset.jsonl \
  --out cpg/ablation/.work/d5_flowcut_baserate_v9.json

# D5-A：在 taint.ql 加 isSanitizer 后重跑污点提取
cpg/codeql/codeql.exe query run cpg/queries/taint.ql \
  --database=C:/Users/lenovo/cpg_db/corpus_db \
  --search-path=cpg/codeql-queries --output=cpg/ablation/.work/d5a_taint.bqrs --ram=3000 --threads=8
cpg/codeql/codeql.exe bqrs decode --format=csv \
  cpg/ablation/.work/d5a_taint.bqrs --output=cpg/ablation/.work/d5a/taint.csv
# （cwe-918.csv 等未变，复制入 d5a/ 后）
python cpg/ablation/d5_flowcut_baserate.py \
  --taint-dir cpg/ablation/.work/d5a --dataset cpg/dataset.jsonl \
  --out cpg/ablation/.work/d5_flowcut_baserate_d5a.json
# 对比两 JSON：BA/MCC/双标数/flow-cut baserate 应完全一致
```
