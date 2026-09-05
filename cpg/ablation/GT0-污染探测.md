# 污染探测报告（第 0 步 B，2026-09-04）

> 目的：检验目标 API 模型是否"记忆化"了 GitHub Advisory 2026 段的 CVE 细节（标签泄漏的记忆化通道）。
> 若 DeepSeek-V4（2026 模型）能凭 CVE 编号说出**具体准确**的漏洞位置/成因 → 污染实锤 → API 臂须剔除污染 CVE 或换 2024-cutoff 兜底模型。
> qwen2.5-coder（2024 截止）为阴性对照，同时实证本课题"无 API 漂移 + 无标签记忆"的护城河。
> 脚本：`cpg/ablation/pollution_probe.py`（纯标准库，可复现）；产物 `.work/pollution_{qwen7b,deepseek}.jsonl`（各 15 行 raw）。

## 1. 方法

- 同 seed（20260904）从 74-CVE 语料抽 **15 个相同 CVE**，qwen 与 DeepSeek 完全匹配对比。
- Prompt **只给 `CVE: CVE-2026-XXXXX`**，不给任何代码/摘要/仓库名；指示：无记忆则回答 UNKNOWN，有记忆则陈述漏洞类别/影响组件/根因/修复。
- qwen2.5-coder:7b 走本地 Ollama（temperature=0）；DeepSeek v4-flash 走 api.deepseek.com/v1（temperature=0）。

## 2. 结果

| 模型 | 训练截止（预期） | 判定 | n=15 中 UNKNOWN | 具体描述 |
|---|---|---|---|---|
| qwen2.5-coder:7b（阴性对照） | 2024 | 无记忆 | **15/15** | 0 |
| DeepSeek v4-flash（目标） | 2026（待核） | **未检出污染** | **15/15** | 0 |

raw 响应逐条落盘（全部非空 "UNKNOWN"，非空响应/空响应/超时均可复验）。

## 3. 解读

1. **探测方法有效**：qwen 在无记忆时如实输出 UNKNOWN（不胡编），证明"UNKNOWN 引导"能区分"无记忆"与"会编造"；而指令明确"有记忆则描述"，故 UNKNOWN 应解读为**无检索性记忆**（而非指令服从掩盖）。
2. **qwen 护城河实证**：2024 截止模型对 CVE-2026-* 零记忆——本课题当前全部数字不受记忆化泄漏影响。
3. **DeepSeek v4-flash 未检出污染**（15 样本）：第 4 步"规模上界探测臂"**可行**，无需因污染弃用或剔除。
4. **局限与正式跑批前动作**：探测仅 15/74 样本，属抽样；正式 148 次×3 seed 跑批前，建议将探测**扩至全 74（+85）CVE**（成本 <2 分钟/模型）并随论文申报，作为对效度的完整声明。

## 4. 复现

```bash
cd cpg/ablation
python pollution_probe.py --backend ollama --model qwen2.5-coder:7b --dataset ../dataset.jsonl --out .work/pollution_qwen7b.jsonl --n 15
DEEPSEEK_API_KEY=xxx python pollution_probe.py --backend openai --model deepseek-v4-flash \
    --base-url https://api.deepseek.com/v1 --dataset ../dataset.jsonl --out .work/pollution_deepseek.jsonl --n 15
```

---

## 5. P1-7 阳性对照（2026-09-05）——探测**灵敏度不足**，阴性结果需降级解读

### 5.1 为什么要做
阴性对照（对 CVE-2026 说 UNKNOWN）是**预期结果**：2024-cutoff 模型本就不可能记住 2026 的公告；
只有阳性对照能证明探测"**该说的时候说得出来**"，否则"全 UNKNOWN"与"探测恒返回 UNKNOWN"不可区分。

### 5.2 结果

用同一 prompt 对 5 个**训练截止前、极著名**的 CVE 提问（脚本已加 `--cves` 支持显式列表）：

| 目标 CVE | 知名度 | qwen2.5-coder:7b 输出 |
|---|---|---|
| CVE-2014-0160（Heartbleed） | 极高 | **UNKNOWN** |
| CVE-2021-44228（Log4Shell） | 极高 | **UNKNOWN** |
| CVE-2017-0144（EternalBlue） | 极高 | **UNKNOWN** |
| CVE-2014-6271（Shellshock） | 极高 | **UNKNOWN** |
| CVE-2022-22965（Spring4Shell） | 极高 | **UNKNOWN** |

**5/5 全部 UNKNOWN → 阳性对照失败。**

### 5.3 结论（诚实降级）

1. **探测灵敏度未获证明**：qwen2.5-coder:7b 对**任何** CVE 编号（2026 与著名历史 CVE  alike）一律输出 UNKNOWN。因此 §2 的"15/15 UNKNOWN"**不能**作为"无记忆化泄漏"的独立实证——它与"探测不灵敏"同样自洽。
2. **护城河仍成立，但依据是时序论证而非探测**：qwen2.5-coder 训练截止 ~2024、语料为 CVE-2026，**时序上不可能被记忆化**——这是逻辑/设计保证（模型不可能见过尚未发布的公告），不依赖探测。
3. **论文措辞必须改**：不得写"我们通过探测实证了无污染"，应写：
   > "泄漏风险由训练截止与语料时间的时序关系排除（2024 cutoff vs CVE-2026）。我们另做的记忆化探测对该模型不具备灵敏度（对训练截止前的知名 CVE 亦返回 UNKNOWN，阳性对照失败），故其全 UNKNOWN 结果**不作为独立证据**，仅作辅助观察。"
4. **待办**：DeepSeek-V4（2026 模型）的阳性对照**未完成**（执行被敏感内容守卫拦截，命令含 API key），故 DeepSeek 侧"未检出污染"同样待灵敏度验证。完成后才能判断探测是否可用于 API 臂的污染筛查。
5. **副产品（正面）**：qwen 连 Heartbleed/Log4Shell 都答不出，进一步说明它不会以 CVE 编号为索引回忆漏洞细节——这本身对"本地小规模代码模型不具备 CVE 记忆检索能力"是一个可报告的行为观察。
