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
