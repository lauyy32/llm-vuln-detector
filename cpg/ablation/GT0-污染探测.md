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

### 5.3 探测灵敏度验证（DeepSeek-V4，2026-09-05 完成）

用**同一 prompt、同一探测脚本**在 DeepSeek-V4（2026 模型，应当认识这些 CVE）上跑阳性对照：

| 目标 CVE | DeepSeek-v4-flash 输出 |
|---|---|
| CVE-2014-0160（Heartbleed） | ✅ 具体描述：信息泄露/缓冲区越读，OpenSSL 心跳扩展（`ssl/d1_both.c` 等），payload 长度未做边界检查 |
| CVE-2021-44228（Log4Shell） | ✅ 具体描述：JNDI/LDAP 注入致 RCE，log4j-core 的 `JndiLookup` 查找机制 |
| CVE-2017-0144（EternalBlue） | ⚠️ **空响应**（未产出内容，记为探测个案限制/可能的内容过滤） |
| CVE-2014-6271（Shellshock） | ✅ 具体描述：经环境变量的命令注入，bash `variables.c` / `parse_and_execute` 函数导入机制 |
| CVE-2022-22965（Spring4Shell） | ✅ 具体描述：经 `WebDataBinder`/`BeanWrapper` 的不安全数据绑定致 RCE |

**→ 4/5 给出具体且准确的描述 ⇒ 探测工具本身具备灵敏度**（能区分"记得"与"不记得"）。

### 5.4 配对验证（同一模型：阳性 4/5 描述 vs 阴性 15/15 UNKNOWN）

在 DeepSeek-v4-flash 上以 GT0 同 seed（20260904）复跑 15 个 CVE-2026 阴性对照：**15/15 全部 UNKNOWN**（与 GT0 一致，复现成功）。

**同一模型下"能详述著名 CVE、却对 CVE-2026 全 UNKNOWN"** ⇒ 该结果不再是"探测恒返回 UNKNOWN"的伪影，而是**有意义的未记忆化证据**。

### 5.5 最终结论（两模型分别表述，均不可过头）

| 模型 | 阳性对照 | 阴性（CVE-2026） | 结论与依据 |
|---|---|---|---|
| **DeepSeek-v4-flash** | 4/5 具体描述 | 15/15 UNKNOWN | **未检出污染**，且探测灵敏度已验证 → **API 臂（规模上界探测）可行**；正式跑批前按计划扩至全 74/85 CVE 申报 |
| **qwen2.5-coder:7b** | 5/5 UNKNOWN（无 CVE 回忆能力） | 15/15 UNKNOWN | 泄漏风险由**时序论证**排除（2024 cutoff vs CVE-2026，模型不可能见过未发布公告）；探测补充观察：**该模型对任何 CVE 编号均无细节回忆**（连 Heartbleed/Log4Shell 也答不出），故不存在可用的记忆化泄漏通道。**不得**写成"探测实证了 qwen 无 2026 记忆"——它证明的是"qwen 根本没有 CVE 回忆能力" |

**论文措辞模板**：
> "为排查记忆化标签泄漏，我们用同一提示词对模型做 CVE 记忆化探测：阳性对照（5 个训练截止前的著名 CVE）在 DeepSeek-V4 上 4/5 返回具体准确的漏洞描述，证明该探测具备灵敏度；同一模型对本研究语料的 15 个 CVE-2026 全部返回 UNKNOWN。因此 API 臂未检出污染。对本地 qwen2.5-coder，探测显示其对任何 CVE 编号（含著名历史 CVE）均无细节回忆，泄漏通道不存在；本地模型侧的泄漏排除另由训练截止（~2024）与语料时间（CVE-2026）的时序关系保证。"
>
> 局限：阳性对照中 CVE-2017-0144 返回空响应（1/5），为探测的个案限制，如实报告。

### 5.6 全集扩展：DeepSeek 阴性对照 n=85（D1 全量，2026-09-05）

按计划将 API 臂阴性对照从 15 扩至 **D1 全集 85 个 CVE**：

- **结果：85/85 全部 UNKNOWN**（`pollution_deepseek_negcontrol_d1_n85.jsonl`）。结合 §5.3 灵敏度验证（阳性 4/5 具体描述），构成"灵敏度已证 + 全集未检出"的完整证据链——**API 臂在全部 85 个语料 CVE 上未检出记忆化污染**。
- **数据卫生记录（中断恢复）**：本次跑批首次在 28/85 处因网络中断（VPN 502），重跑后产物出现 28 条重复行（113 行/85 唯一 CVE，根因是脚本以追加模式写出、天然可续跑）。经逐条校验，**全部重复行的 raw 完全一致**（均为 UNKNOWN），已做无损去重（113→85 行），85 个 CVE 全覆盖、零缺失、零集外。该过程如实记录，产物以去重后版本入库。
- **口径限定（写作纪律）**：85/85 是**退化型结果**（全 UNKNOWN，对温度不敏感），它证明的是"未检出污染"，**不能**外推为"API 臂零漂移"。"温度 0 确定性"这顶帽子只配给本地 Ollama 实验；论文中凡涉 API 臂，须删除"零漂移"表述或限定为"探测臂结果为温度平凡型"。若将来真跑 API 模型判别实验，须多 seed + 漂移披露。
