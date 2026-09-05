# P1-12：placebo 三臂的前沿模型 spot-check（DeepSeek-v4-flash，2026-09-05）

> 目的：主协议锁定本地 2024-cutoff 模型（qwen2.5-coder 7B/14B，时序隔离记忆化污染）。
> 评审风险点是"结论是否 2024 小模型特异"。本实验把**本地协议中唯一 p<0.01 的阳性锚点**
> （placebo 三臂）在前沿 API 模型上做一次**加法式**抽查——不动任何冻结数字，
> 结果只进附录小节。
>
> 解释分支（先于跑批确定，非时间戳工件）：① placebo 拒绝率复现 → 阳性锚点升为跨世代证据；② placebo 翻车 →
> "读补丁"能力为世代特异，结论收窄；③ real 臂 benign 率远高于 53% → "漏判真实修复"
> 边界移动，须改写叙事。

## 1. 协议

- 脚本：`patch_verify_control.py --backend openai`（本次新增 OpenAI 兼容后端；
  与 Ollama 臂**同 system prompt、同源码、同 taint 切片、同 temperature=0**）。
- 模型：deepseek-v4-flash（API，2026 世代）；`--dataset cpg/dataset_d1.jsonl`，
  CPG 双标记子集有效 n=15（49257/67428 不在 D1，与主协议口径一致）。
- 规模：15 CVE × 3 臂 × 3 轮 = 135 次调用；raw 全量落盘。
- 复现：`python cpg/ablation/patch_verify_control.py --backend openai --model deepseek-v4-flash --dataset cpg/dataset_d1.jsonl --max-tokens 8192 --out <out>.json --raw-out <raw>.jsonl`（key 走环境变量 DEEPSEEK_API_KEY；须绕过本机代理）。
- 污染前提：该模型已通过灵敏度验证的记忆化探测（GT0 §5：阳性 4/5，阴性 85/85
  UNKNOWN），且 placebo/shuffled 臂的 diff 为合成/移植，记忆化通道天然微弱。

## 2. 版本史（含一次仪表 bug 的诚实记录）

- **v1（max_tokens=1024，已废弃）**：37/135 次返回空响应。初判"疑服务端安全过滤"，
  **经直查响应结构证伪**：`finish_reason=length` 且 `reasoning_content` 已耗 844+
  tokens——deepseek-v4-flash 是 reasoning 模型，1024 预算被思维链烧光导致
  content 为空。空响应集中在 real 臂（该臂 diff 最长、推理量最大），与内容过滤无关。
  v1 产物保留在 `.work/patch_verify_control_deepseek_r{1,2,3}.*` 备查，不用于结论。
- **v2（max_tokens=8192，权威）**：脚本新增 `--max-tokens` 参数后全量复跑，
  空响应降至 4/135（3%）。

## 3. v2 结果（权威）

| 轮次 | real benign | placebo benign | shuffled benign | McNemar（b/c，单侧精确 p） |
|---|---|---|---|---|
| r1 | 12/15 | **0/15** | 0/15 | 12/0，p=0.00024 |
| r2 | 13/15 | **0/15** | 0/15 | 13/0，p=0.00012 |
| r3 | 15/15 | **0/15** | 0/15 | 15/0，p=0.00003 |
| 池化 | **40/45（89%）** | **0/45** | **0/45** | （逐轮报，不池化 p） |

对照（本地，n=15，temp=0 确定性）：7B real 8/15 / placebo 0/15 / shuffled 3/15；
14B real 8/15 / placebo 0/15 / shuffled 0/15。

产物：`.work/patch_verify_control_deepseek_v2_r{1,2,3}.json` +
`_v2_raw_r{1,2,3}.jsonl`（135 条 raw 全量落盘入库；其中 4 条空响应按独立类别申报，不计被骗）。

## 4. 发现

1. **阳性锚点跨世代复现成立且更强（分支①）**：placebo 臂 45/45 全拒；v1 曾出现 1 次滑点
   （53502，raw 完整未截断、150 字符、JSON 闭合——该次 rationale 显示模型凭模式而非
   diff 内容作答，属真实误判），v2 三轮未复现 → 归因为 temp=0 下 API 非确定性
   漂移，**非**截断伪影（2026-09-05 晚勘误：本报告初版"截断伪影"表述有误，
   以 v1 raw 为证）；shuffled 0/45 被骗。逐轮 McNemar
   p∈[3e-5, 2.4e-4]，强于本地（b=8/c=0, p=0.0039）——因为前沿模型 real 臂更敢判
   benign 而 placebo 臂仍全拒，real−placebo 差拉大到 +0.80~+1.00。
2. **real 臂边界移动（分支③部分命中，须收窄措辞）**：前沿模型识别真实修复
   40/45（89%），显著高于本地 7B/14B 的 53%。"LLM 漏判约一半真实修复"**仅是
   本地小模型现象**，不得外推至前沿模型；论文相关表述统一收窄为
   "本地 7B/14B + CPG 证据链上"。
3. **实例关系为超集而非错位**：v2 三轮中 7B 的 8 个 real-benign 全部落入
   DeepSeek 的 real-benign 集合（DS ⊇ 7B，三轮均成立）。v1 报告的"5/8 重合"
   系空响应污染，已作废。
4. **仪表教训**：reasoning 模型的 max_tokens 须覆盖思维链；空响应排查先看
   `finish_reason`，再谈内容过滤。

## 5. 局限

- API 残余非确定性：temp=0 下 real 臂三轮仍漂移（12/13/15），漂移本身即数据；
  "温度 0 确定性"表述仅属本地臂（GT0 §5.6 口径）。
- 单一 API 模型、单 prompt 形态、子集 n=15；spot-check 级证据，只用于回应
  "模型代表性"质疑，不外推为前沿模型全量结论。
- 网络中断 4 次（VPN 502/超时），幂等重跑补齐；中断与修复过程如实记录。

## 6. 对论文的影响

- 主协议数字**零改动**；本结果进附录小节 "frontier spot-check"。
- 摘要/正文可加一句：placebo 协议在 2026 世代 API 模型上复现（45/45 拒绝），
  且前沿模型对真实修复的识别率（89%）高于本地小模型（53%）——主负面结果
  （82 对补丁边界判别近随机）仍为本地模型 + CPG 证据链的主张，前沿判别力
  不在本研究宣称范围内。
