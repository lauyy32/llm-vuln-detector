# P1-15：placebo v3 重构 + hard-negative partial 臂（2026-09-06 预注册）

> 起因：外部代码级评审指出 placebo 三臂存在三个设计混淆（全部属实）：
> ① 三臂共用 fixed 版源码（`patch_verify_control.py` L249），placebo/shuffled 的
> "源码状态 × 注入 diff × 期望标签"语义不自洽；
> ② placebo diff 内嵌"无功能变更"自述（`COSMETIC_HEADER`），模型读字面即可拒答；
> ③ 系统提示直接教学判据（`patch_verify.py` L34"只改文档/版本号→vulnerable"）。
> 结论：旧 placebo 是"送分题"，证据等级须降；且拟定题目含 "Placebo-Controlled"，
> placebo 臂是承重墙，必须重构。
>
> **解释分支（先于跑批确定，2026-09-06）**：
> - **A. v3 三臂保持旧结果形态**（real 高良性率、placebo/shuffled 高拒绝）→
>   "读内容"结论在语义自洽协议下成立，placebo 臂从 pilot 升回主证据；
> - **B. v3 三臂塌缩**（real 臂良性率大跌或 placebo 拒绝率大跌）→
>   旧 15/15 部分归因于设计混淆，结论降级为"旧协议下的操纵检验"，
>   论文相关表述收窄并以 v3 数字为准；
> - **partial 臂（独立判读）**：若模型对"看似修复但不充分"的 partial 补丁
>   大量判 benign（≥50%）→ "Reading ≠ Judging"获得**直接**证据（标题命题成立）；
>   若大量判 vulnerable → 模型的充分性判断比预期强，标题命题需收窄。
>
> 旧 fixed 基线结果（P0-2 三臂/P1-12 v2）降级为 **flawed pilot**，留档不池化；
> 本修正本身作为"发现并修复自身混淆变量"的自我纠错叙事写入论文（RENE 取向）。

## 1. v3 协议变更（对旧三臂逐项对齐）

| 项 | 旧（flawed pilot） | v3 |
|---|---|---|
| 基线源码 | **fixed 版**（L249） | **vuln 版**（prefix/version/truth 同步改） |
| 任务语义 | 混（已修代码+补丁？） | **自洽**：给漏洞代码+候选补丁，问"此补丁能否修好它" |
| placebo 自述 | "无功能变更"marker | 删除自述；装饰 diff 只保留客观变更（注释/版本号），不自我声明 |
| 系统提示 | 教学例"只改文档/版本号→vulnerable" | 删除该教学例（保留中性判据："漏洞路径仍可被利用或补丁与漏洞无关→vulnerable"） |
| 子集 | CPG 双标 15（D1） | 同（不变，保持可比） |
| 模型 | 7B/14B 本地 temp=0 | 同（先本地确定性复跑；前沿 API 臂视 v3 本地结果再定） |
| 旧结果地位 | 主证据 | **flawed pilot，降级留档** |

## 2. partial 臂构造规则（先于构造确定）

1. 从 15 个 CPG 双标 CVE 的真实修复 diff 中，识别**安全关键 hunk**
   （直接切断 source→sink 或引入守卫的 hunk；识别依据逐 CVE 写入
   `partial_arm_construction.md`，含 hunk 定位与理由）；
2. partial 补丁 = 真实修复 **删除该 hunk**（保留其余 hunks）——
   "不充分"由构造保证，不凭直觉声明；
3. 期望判定 = vulnerable（补丁仍不充分）；
4. 无法确定安全关键 hunk 的 CVE 不纳入（宁缺毋滥），目标 10-15 例；
5. partial 臂与 v3 三臂同 prompt/源码/温度注入，作为**第四臂**。

## 3. 标注协议（双人独立标注 + 仲裁）

- **构造者（我）**：按 §2 规则构造，输出构造文档；构造者标签由构造保证，
  不作为标注输入；
- **独立标注者（安全/代码分析背景的师兄）**：对**全部四臂混合打乱**的补丁
  独立盲标（sufficient / insufficient / unclear），不知臂属、不知构造标签、
  不知模型结果；给出每条的判断依据一句话；
- **仲裁（导师）**：协议把关 + 分歧仲裁；盲标完成前不看构造文档；
- **指标**：Cohen's κ + 原始一致率双报（n=10-15 时 κ 不稳，双指标并呈）；
  分歧条目的仲裁结果与理由入附录；
- **盲标产物**：`partial_arm_annotation.jsonl`（含 annotator 版本但不含构造标签）。

## 4. 统计与口径

- 全 strict 弃权口径（P1-14 勘正后唯一口径）；abstain 独立申报；
- v3 三臂主检验：real−placebo benign 率差（H1 阈值 0.30）、
  real vs placebo 单侧精确 McNemar（与旧口径一致）；
- partial 臂：benign 率（被判"充分"的比率）+ 双侧 95% CP-CI；
- 聚类敏感性（P1）：leave-one-repo-out 重算主判别数字（仓库聚集：
  open-webui/thumbor/flyto-core 多条 + 67424/67428 同 fix commit）；
- "确定性算法无需 CI"限定：CPG-alone 结论仅陈述本语料，
  不做未来 CVE 总体外推（effect_size.md 已加限定）。

## 5. 产物规划

- harness v3：`patch_verify_control.py`（v3 协议，旧版由 git 历史留档）；
- v3 结果：`patch_verify_control_v3_{7b,14b}.json` + raw jsonl；
- partial 构造文档：`partial_arm_construction.md`；
- 分析报告：本文件 §6（跑批后填）；
- 论文：旧 placebo 降级说明 + v3 结果 + partial 臂 + 自我纠错叙事段。

## 6. 结果（跑批后填写）

（待填）
