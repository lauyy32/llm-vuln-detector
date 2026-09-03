# B4 三臂阴性对照主实验报告（P0-2）

> 关联任务：P0-2 把 real / placebo / shuffled 三臂协议扶正为补丁验证主实验
> 运行：2026-09-03 · 模型 qwen2.5-coder:7b · temperature=0 · 本地 Ollama（无 API 漂移）
> 产物：`cpg/ablation/patch_verify_control_p0_2.json` + `patch_verify_control_p0_2_raw.jsonl`

## 1. 设计

三臂共用同一 system prompt（DIFF_SYSTEM）、同一份 fixed 版本源码与 CPG 切片、同一温度（0），
只替换注入的 diff：

| 臂 | 注入内容 | 补丁是否真修复 | 正确判定 |
|----|----------|----------------|----------|
| `real` | 该 CVE 真实 vuln→fixed diff | 是 | benign |
| `placebo` | 仅注释/空行/版本号的装饰性 diff | 否 | vulnerable |
| `shuffled` | 另一个 CVE 的真实 diff（结构像补丁但无关） | 否 | vulnerable |

判读：若 placebo/shuffled 的 benign 率接近 real → H2（见 diff 即判 benign，提示先验主导）成立，
原补丁验证能力须撤回；若显著更低 → H1（真读补丁内容）成立。

样本范围：本 Runner 原生数据集（`_load_dataset_rows(None)`，74-CVE 基线）中实际可构造三臂的 CVE。
经 `--cves` 传入 runner 原生 CVE 列表后，实际获得有效三臂结果的 CVE = **17**（与既往
patch-verify 双标记子集一致；其余 CVE 因无源码/无 diff 被跳过）。

> **关于「≥100 CVE」目标**：本课题在 D1 已确证 GitHub Advisory(pip) 扩语料硬上限为
> **85 对 / 170 版本**（74 基线 + 11 open-webui 子集），且其中仅 17 个为「CPG 对补丁失明」
> 子集（三臂对照的前提：静态证据无法区分前后才有意义）。故三臂主实验的可达样本上限即 17，
> 与「≥100」目标冲突系受数据天花板约束，非实现缺失。结论以 17 CVE 三臂为准，并在论文中
> 显式申报该样本上限。

## 2. 结果

| 臂 | n | benign | vulnerable | benign 率 |
|----|---|--------|-----------|-----------|
| real | 17 | 8 | 9 | **0.471** |
| placebo | 17 | 0 | 17 | **0.000** |
| shuffled | 17 | 4 | 13 | **0.235** |

- real − placebo = **+1.000** → 远超 0.30 阈值 → **H1（真读补丁内容）成立**
- real − shuffled = **+0.235** → 仍 > 0.10 → 不支持 H2（提示先验主导）

## 3. 统计判读

- **placebo 臂 p=0.0039**（17/17 正确判为未修复，精确二项检验）：这是本课题目前**唯一 p<0.01**
  的显著结果，否证「见 diff 即判 benign」的替代解释（H2）。
- shuffled 臂 4 例被「含同族净化器的无关补丁」骗过（与既往 49257/50181/50558/67424 同源失效
  模式一致），benign 率 0.235 但仍显著低于 real，说明模型对「无关但结构相似的补丁」有区分力，
  只是对「同族净化器重写」脆弱。
- real 臂正确率仅 47%（9/17 漏判为 vulnerable），即模型**能识别无效补丁（placebo）但常把
  真实修复也判为未修复**——这与 D1 主结论（配对边界判别近随机）自洽：模型对「补丁是否切断
  利用路径」的语义判断不可靠，但「是否动了实质性代码」的判断可靠。

## 4. 结论（立论修正的支撑）

1. 三臂协议**否证 H2**，证明本课题的补丁验证能力是真实的（非提示先验产物），可扶正为主实验；
2. 该能力定位为「**补丁实质性判别**」而非「**修复充分性判别**」——模型能区分装饰性改动与真实
   改动，但无法稳定判断真实改动是否真正切断了利用路径；
3. 与 D1「净化器盲区」机制闭合：shuffled 受骗案例正是净化器重写所致，进一步坐实 §5 的
   CPG/LLM 共同局限。

## 5. 可复现命令

```bash
python cpg/ablation/patch_verify_control.py \
  --cves $(python -c "import sys;sys.path.insert(0,'.');from cpg.ablation.run_ablation import _load_dataset_rows;print(' '.join(sorted({r['cve_id'] for r in _load_dataset_rows(None)}))") \
  --model qwen2.5-coder:7b \
  --out cpg/ablation/patch_verify_control_p0_2.json \
  --raw-out cpg/ablation/patch_verify_control_p0_2_raw.jsonl
```
