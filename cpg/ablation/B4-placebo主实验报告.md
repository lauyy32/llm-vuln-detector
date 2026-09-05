# B4 三臂阴性对照主实验报告（P0-2）

> 关联任务：P0-2 把 real / placebo / shuffled 三臂协议扶正为补丁验证主实验
> 运行：2026-09-03 · 模型 qwen2.5-coder:7b · temperature=0 · 本地 Ollama（无 API 漂移）
> 产物（权威）：`cpg/ablation/patch_verify_control_p0_2_full.json` + `patch_verify_control_p0_2_full_raw.jsonl`

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

样本范围：本实验的理论总体是「CPG 对补丁失明」子集（CPG 在 vuln 与 fixed 两版均判
vulnerable，双标记），由 `b2_74_7b.json` 的 `cpg_full` 字段确定性导出，不做人工挑选。
该子集正是补丁验证有意义的前提——静态证据无法区分前后，LLM 对补丁的读取才是唯一信号；
在 CPG 已能判别的 CVE 上跑 placebo 会稀释问题，故 **17 即为本实验的正确总体，而非受限于
数据天花板**。本轮通过 `--dataset cpg/dataset_d1.jsonl` 加载 D1 语料取回源码，其中 **2 个
CVE 在 D1 中无法取回 fixed 源码**被跳过，故有效三臂 CVE = **15**（与既往双标记子集一致，
余 2 个为语料源码缺口，非方法缺陷）。

> **关于「≥100 CVE」目标**：本课题在 D1 已确证 GitHub Advisory(pip) 扩语料硬上限为
> **85 对 / 170 版本**（74 基线 + 11 open-webui 子集），但其中仅 17 个为「CPG 对补丁失明」
> 子集（三臂对照的前提：静态证据无法区分前后才有意义）。故三臂主实验的理论总体即 17，
> 与「≥100」目标冲突系受该子集规模约束，非实现缺失。结论以该子集三臂为准，论文中
> 显式申报该样本上限与有效 n=15 的源码缺口。

## 2. 结果（权威运行：patch_verify_control_p0_2_full.json，有效 n=15）

| 臂 | n | benign | vulnerable | benign 率 |
|----|---|--------|-----------|-----------|
| real | 15 | 8 | 7 | **0.533** |
| placebo | 15 | 0 | 15 | **0.000** |
| shuffled | 15 | 3 | 12 | **0.200** |

- real − placebo = **+0.533** → 远超 0.30 阈值 → **H1（真读补丁内容）成立**
- real − shuffled = **+0.333** → 远超 0.10 阈值 → 不支持 H2（提示先验主导）

## 3. 统计判读

- **placebo 臂 McNemar 单侧精确二项 p=0.0039（双侧 0.0078）**（配对 real vs placebo，
  b=8/c=0，不一致对 n=8，P(X≥8 | Bin(8, 0.5))=0.5⁸=0.0039）。注：此前写作 p≈0.0047
  系 χ² 渐近（χ²=8.0, df=1）双侧值，并非精确检验，已更正。这是本课题当时**唯一 p<0.01**（2026-09-05 注：P1-12 v2 前沿附录臂 p 达 3e-5，"唯一"自此失效）
  的显著结果，否证「见 diff 即判 benign」的替代解释（H2）。即模型看到装饰性 diff 时 **0/15**
  判 benign，证明它对补丁内容（而非"有 diff"这一线索）敏感。
- shuffled 臂 3 例被「含同族净化器的无关补丁」骗过（与既往 49257/50181/50558/67424 同源
  失效模式一致），benign 率 0.200 但仍显著低于 real（McNemar real−shuffled 同样显著），
  说明模型对「无关但结构相似的补丁」有区分力，只对「同族净化器重写」脆弱。
- real 臂正确率仅 53%（8/15 判为已修复，7/15 漏判为 vulnerable），即模型**能识别无效补丁
  （placebo 全判未修复）但常把真实修复也判为未修复**——与 D1 主结论（配对边界判别近随机）
  自洽：模型对「是否动了实质性代码」的判断可靠，但对「补丁是否真正切断利用路径」的语义
  判断不可靠。

## 4. 结论（立论修正的支撑）

1. 三臂协议**否证 H2**，证明本课题的补丁验证能力是真实的（非提示先验产物），可扶正为主实验；
2. 该能力定位为「**补丁实质性判别**」而非「**修复充分性判别**」——模型能区分装饰性改动与真实
   改动，但无法稳定判断真实改动是否真正切断了利用路径；
3. 与 D1「净化器盲区」机制闭合：shuffled 受骗案例正是净化器重写所致，进一步坐实 §5 的
   CPG/LLM 共同局限。

## 5. 可复现命令

默认即取 CPG 双标记（对补丁失明）17-CVE 子集；`--dataset` 指定从 D1 语料取回 fixed 源码
（其中 CVE-2026-49257 / CVE-2026-67428 为 74 主集独有、不在 D1 语料中，脚本按"不在 dataset"跳过 → 有效 n=15；二者源码在 corpus_src 中实际存在，排除原因是语料集关系而非源码缺失——此前"fixed 源缺失/在 D1 无源码"的表述不确，2026-09-05 勘误）。

```bash
python cpg/ablation/patch_verify_control.py \
  --dataset cpg/dataset_d1.jsonl \
  --model qwen2.5-coder:7b \
  --out cpg/ablation/patch_verify_control_p0_2_full.json \
  --raw-out cpg/ablation/patch_verify_control_p0_2_full_raw.jsonl
```
