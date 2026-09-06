# 实验冻结包清单（2026-09-06 定稿，封口后不再扩建）

> 目标：在正式 v4 跑批前，把实验基础一次性收齐到"可审计、可复算、可验收"。
> **勾选纪律（2026-09-06 反向审计后加入）**：[x] 必须与 git 实际文件/测试状态一致——勾选前跑存在性/可运行性检查；清单与代码状态漂移属违例（台账已记）。
> **封口条款（与外部验收共识）**：本清单全部通过后，下一次验收即
> "实验前最终验收"——通过后立即跑批。**冻结的是范围不是事实**：
> 此后不再新增研究问题、实验臂与非必要工程功能；但任何影响标签真实性、
> 样本完整性、统计正确性、身份泄露或数据安全的 P0 问题，仍须停止跑批并修复。
> 死线双轨：摘要 **10-19**（强制）/ 全文 **10-23**（AoE）。
> 进度：[ ] 未开始 / [~] 进行中 / [x] 完成

## 0. 倒排（终点即承诺）

| 日期 | 里程碑 |
|---|---|
| 09-07 | §1 复算链 + §4 决策（API 臂）完成 |
| 09-07~08 | §2 v4 候选包（real/placebo）+ §3 门禁测试全绿 |
| 09-08 | **师兄盲标包发出（关键路径，先行）** |
| 09-09 | **Gate A 验收**（外部：G0-G4 对三臂全绿 + 协议冻结 + smoke；通过后仅跑 real/placebo/shuffled） |
| 09-09~12 | 标注窗口期：跑 real/placebo/shuffled 三臂（与 partial 标签无涉） |
| 标注完成+仲裁+纳入名单冻结后 | **partial 臂才跑批**（构造者/仲裁者此前不见模型结果） |
| 09-13~14 | v4 分析 + 聚类敏感性 + P1-16 §6 成稿 |
| 09-15~ | 论文正文冲刺（§2/§3/§4；骨架在私有仓） |
| 10-12 | 匿名工件 + 数据可用性材料就位 |
| **10-19** | **摘要提交（强制）** |
| **10-23** | **全文提交（AoE）** |

## 1. 复算与声明链（大部分已建）

- [x] `_abst` 硬编码改数据计算 + fail-closed
- [x] claims.json 补全 data_files、unknown claim→fail、行级唯一键断言
- [x] **三类负向测试**（verify_claims --self-test，T1/T2/T3 实测全 PASS，2026-09-06）：
  ①篡改 expect→FAIL；②删/复制原始记录→FAIL；③篡改一行预测→相应统计值变化
- [x] 干净克隆一条命令复算（2026-09-06 codex 在全新克隆 HEAD fe20a38 上独立执行验证：local 7B 2/82、14B 0/74、r1/r2 7/82、b=6/c=1 p=0.0625、方向 0.089844/0.171875、abstain 148/159、VERIFY_CLAIMS: PASS）
- 复现命令：`git clone <url> && cd <dir> && python cpg/ablation/.work/verify_claims.py`（须已装 Python ≥3.9；统计脚本纯标准库，无第三方依赖）

## 2. v4 实验对象真实性（G0-G4 实现）

- [~] real diff 完整性（语料树等价 15/15 G1_G2_STRUCTURAL_PASS：canonical diff 应用后与 fixed 树双向集合+字节+类型一致；报告 .work/v4_gates_report.json）。**P0-3 已定（2026-09-06 第六轮）**：real 主臂 = 上游 `fix_commit^..fix_commit` 的**机械化 Python 投影**（按预注册语言/扩展名客观提取，禁人工挑 hunk）；corpus-complete 降为一致性/敏感性分析。命名 "*upstream fix-commit derived Python projection*"，不得称"完整真实补丁"，不得称"CPG 收窄补丁"。⚠️ 已知 45019 语料 10 文件 vs 上游 ~23 文件，须标 `composite_fix_commit=true` 并从长度匹配子集（主分析）排除。
  **⚠️ 第七轮更正**：上述 15/15 报告验证的是 corpus 快照生成器，**非新 real 臂**——已降级命名
  "corpus-snapshot structural validation"，不得作为新 real 臂 Gate A 证据。新 real 的结构门禁
  G1 已重定义为"对上游树的判定"（投影应用到 parent 的 Python 文件 == fix commit 的 Python 文件，
  apply-clean），产出独立报告 `v4_upstream_real_report.json`（详见"manifest 协议冻结"节）。
  **应用后与 fixed 快照逐文件哈希一致**（或显式标记不等价原因）；
  禁字典序子集/禁中间截断
- [~] placebo：结构门禁 15/15 apply-clean+AST 等价；**锚点字节偏移/死分支/统一模板/shebang 位移四处已修（2026-09-06 v2.2）**；token 比未达 [0.8,1.25] 带（proxy 值随实现变动，不固化具体范围）；注释自然度天花板=自动化不可达"第二标注者看不出自动生成"，最终由构造者撰写+盲标仲裁——**此项验收前置于 Gate A**（real/placebo/shuffled 跑批前必须完成，不能等 partial 的 Gate B）。
  **残余漏洞 oracle 分层（修正"机器 oracle 原理上不可用"的过宽推论——
  实际只是 CodeQL 对本子集不可用，其它层存在）**：
  T1 可执行 oracle（上游修复自带安全回归测试且环境可跑：12482/53502/50181
  约 3 例——partial 应用后该测试必须失败，机器可证）；
  T2 确定性语义断言（路径/权限/返回字段等领域检查可脚本化者）；
  T3 均不可行 → 冻结的书面残余利用路径 + 双人独立确认。
  三类数量分别报告，不混为同一证据等级。
- [ ] partial：**主对照**（real–partial 为 Judging 主比较）——基于上游投影 real 删除**双人确认**的关键安全 hunk（14 例构造表已定）；**与 G0/G3/G4 并行启动构造+双标**（勿串行，是 10-19 前最长的杆）；预注册标注滑期的 fallback（placebo 操纵检验 + corpus-complete，claim 显式收窄为"外观敏感性"）。效度押在"删对 hunk"上：双人独立识别+仲裁+报 κ，删错则 partial 仍充分、对比作废。
- [~] token 比门禁硬执行（目标 [0.8,1.25] 在**四臂作用域定下后基于新数据重设并预注册**，不得以"删范围"变相放宽；按最终送入模型的 diff token 数计；冒烟三例未过，扩容/子集策略见下）
  **长度匹配策略（2026-09-06 冒烟实测后预注册）**：real diff 巨大（≥~25k 字符）的 CVE，
  等长纯装饰 placebo 需注入数万字符注释，不自然且可被当线索——此类 CVE：
  a) 先尝试确定性 cosmetic 扩容（跨多个真实文件锚点注入，目标落带内）；
  b) 仍不可达 → 排除出长度匹配子集，入"全样本 + 匹配子集"敏感性分析（两口径预注册，分别报告）；
  c) 对排除项**不得声称篇幅混淆已排除**（与 G0/G2 报告同列）。
  实测：12482 real 482t/placebo 106t(0.22)、67424 10136t/122t(0.01)、73498 19590t/144t(0.01)。
- [ ] 全输入落盘：完整 prompt/diff/SHA-256/**Ollama 模型 digest**/参数/响应/解析
- [ ] G0 任务契约：四臂"候选补丁"措辞、prompt 快照除 diff 外一致（自动断言）、
  无臂属/来源/期望泄露、无暗示性文字

## 3. partial 臂标签质量

- [x] 构造依据冻结（partial_arm_construction.md，14 例）
- [ ] 盲标包：四臂混合随机编号、无臂属标识
- [ ] 师兄**真正独立**盲标（非挂名）；导师只仲裁分歧，不倒推改独立标签
- [ ] 报原始一致率 + 混淆表；小样本不独赖 κ（κ 仅在外部标注者≥2 时报）
- [ ] "不充分"依据：构造性（删安全关键 hunk）+ 逐例残余路径书面论证

## 4. 预注册决策补全（冻结前必须写死）

- [x] **v4 含前沿 API 臂**（与本地同包同测）。**记录契约（先于调用冻结，codex 验收条款）**：
  - 精确 API 模型名、调用日期窗口、endpoint/provider 写入 manifest；
  - 参数：temperature=0、seed（若支持）、max_tokens=32768；
  - 逐调用捕获服务端返回的 request ID；重试与网络失败规则
    （≤2 次退避重试，失败落盘记 abstain-fault，不静默丢弃）；
  - 每个样本每轮恰一次主调用；原始请求+响应完整落盘（G3 全输入）
  - **外部效度措辞**：API 权重不可冻结（无本地 digest），论文只声称
    "在某时间窗调用的服务版本"，不声称模型权重完全固定。
- [ ] §5 统计冻结：主结果 vs 探索性结果、abstain 处理、逐臂目标标签、
  主检验/方向检验/多重比较策略、两模型分别报告、**聚类敏感性
  （leave-one-repo-out + 仓库聚集处置）**、排除规则、v3↔v4 比较的角色
  （仅协议诊断，不作主结论）
- [ ] v3↔v4 判读：2×2 互斥矩阵按 A4 规则执行

## 5. 可复现运行

- [ ] **最小环境说明**（不强制 Docker，但须可验证）：Python 版本与依赖清单、
  Ollama 版本、模型名+digest、OS/shell 假设、磁盘/内存/预期运行时长、
  API 依赖清单，以及**哪些结果可从已保存响应复算、哪些必须重调模型**
- [ ] 固定依赖与模型版本（Ollama digest 写入 manifest）
- [ ] 测试覆盖：diff 完整性/apply/树哈希/prompt 等价/统计复算
- [ ] 干净工作区小规模端到端 smoke（≤3 CVE 全管线）
- [ ] 失败日志与排除清单随产物保留（不只有成功结果）

## 6. 事实底稿（论文证据层，非正文）

- [x] **数据字典**（dataset_dictionary.md，2026-09-06 已建）：85 对 schema、66/19/8 构成、
  5 个排除 CVE 理由、孪生对（67424/67428 等）处置、seeds 版本谱系
- [x] claim-evidence 表 = claims.json（已建，持续维护）
- [x] 决策日志 = git 史 + P 文档索引（不新建文件）
- [x] threats 清单 = 私有骨架 §5.3 原位维护

## 7. 立即安全门禁（唯一阻塞项）

- [ ] **DeepSeek API key 立即轮换**（已多次明文出现于会话；删文件无法恢复
  已泄露密钥，必须吊销换新——这是唯一阻塞实验的门禁级会务）

## 8. 会务清单（重要但不阻塞实验冻结，独立跟踪）

- [ ] 匿名工件镜像（~9-23 匿名期前；去身份痕迹 + DOI）
- [ ] 导师确认：注册（全价）+ 差旅（里士满 2027-03）+ 学校认定
- [ ] .git.broken 物理删除确认 + 工作区垃圾目录清理

## 决策备忘：real 臂范围【四臂+两表示，CPG 路径裁剪方案出局】（2026-09-06 第六/七轮评审）

**背景**：real 臂（语料全量 vuln→fixed diff）与 placebo（2 文件各 1 条注释）尺寸失配为
数量级（实测 45019=161×、73498=54×、12482=1.3×），15 例 **0 例**落在 [0.8,1.25]。据此
patch size 是**严重且可完全分离配对样本的潜在混淆**（注：这是数据的性质，不等于"模型单样本
识别率 100%"——后者需训练仅用 token 数的分类器做留一交叉验证才可声称，故不写"100%"）。

**CPG 路径裁剪方案已否决（三审一致，用仓库自身证据钉死）**：
1. **循环定义**：研究 CPG 上下文是否帮 LLM 判补丁，却反过来用 CPG 输出决定模型看到哪些补丁
   文件 → 测得"LLM 能否验证 CPG 预裁剪表示"，研究问题被换掉。
2. **机械删新增文件**：73498 的 `ssrf_adapter.py` 为修复**新增**文件（vuln 侧 utils 无、fixed
   侧有），"∩ vuln 侧 CPG 污点路径文件"会删掉这个以漏洞类型命名的核心修复文件。
3. **按错误路径裁焦点案例**：D5:42 明载 45019（目标 CWE-918 SSRF）被 `CpgPathSource` 抓成
   CWE-022 路径遍历流 → 会让 CPG 按错误 CWE 去裁 real。
4. **不能为匹配对照而改处理组定义**：real patch 定义属研究构念，token 长度属混淆控制，二者
   不是"同一个决策"。不能因为 placebo 太短就把 real 裁短——等长是实现了，"真实补丁验证"这个
   研究对象被改掉了。

**终版臂设计（Codex 裁决，三审收敛；2026-09-06 第七轮改"六层"→"四臂+两表示"）**：

> **命名纪律（Codex P0-1）**：不是"六个臂"，而是 **确认性四臂 + 两个敏感性/表示条件**。
> 审稿人会追问"六臂是否共享样本/是否共同进多重比较/哪个是主 estimand"——故须先分清楚。

**确认性四臂**（共享样本、进入主分析）：
1. **real 主臂** = 上游 `fix_commit^..fix_commit` 的**机械化 Python 投影**（按预注册语言/扩展名
   规则客观提取，禁人工挑"安全相关 hunk"）。命名 "*upstream fix-commit derived Python
   projection*"，不得称"完整真实补丁"，也不得称"CPG 收窄补丁"。
2. **partial 主对照** = 从同一 real 投影删除**双人确认**的关键安全 hunk。与 real 天然近等长。
3. **cosmetic placebo** = 仅作操纵检验，证明模型对补丁内容/外观有反应，**不单独支撑**"会判断
   充分性"。
4. **shuffled** = 按 token 数匹配 donor 的无关补丁对照（匹配后须报协变量平衡表/标准化均值差，
   不得只写"已匹配"；n=15 下平衡大概率不理想，诚实披露）。

**敏感性/表示条件**（不进主 estimand、不共享主解释权重）：
5. **corpus-complete** = 语料一致性与敏感性分析（不充当"收窄未丢安全 hunk"的充分性 oracle）。
6. **CPG-path-scoped** = 仅列**探索性消融**（full patch vs CPG-path-scoped representation，
   回答"CPG 裁剪到底帮助还是损害判断"），**不得作为 real 主臂**。

**主 estimand（提前写死）**：
> 在确认性合格样本中，real 与 partial 的**配对判定差异**（paired judgement difference）。
> placebo 与 shuffled 是辅助对照，不与主比较拥有同等解释权重。

**超大/复合提交处置（预注册）**：
- 预注册 token 上限；超限样本进 oversized/composite 分层，**不截断、不按 CPG 路径裁剪**；
- 本地模型装不下则从确认性匹配子集排除；大上下文 API 另做敏感性分析；
- 复合提交（如 45019：上游 24 文件、含两项 CVE 修复）除标 `composite_fix_commit=true` 外，
  **从长度匹配子集（主分析）排除**，仅入全样本并单独报告——只打标签不足以消解"该 CVE 的
  ground-truth 归属被污染"。

**长度修复必须双侧**：不只收窄 real——placebo 必须作用于 real 所改的**同一文件集**并按目标
体量增加 AST 中性编辑；四臂（real/placebo/shuffled/partial）统一作用域，否则指纹转移到
shuffled/partial。token 比目标 [0.8,1.25] 在**四臂作用域定下后基于新数据重设并预注册**，
不得以"删范围"变相放宽。

> 状态：**四臂+两表示设计已固定**；待执行=构建 15 例上游投影 manifest + 测 real–partial/real–placebo
> 真实 token 分布 + 重跑新门禁报告；导师只裁定分层设计与排除阈值（token 上限/文件数规则），
> 不裁定"是否允许 CPG 定义 ground truth"（该条已否决）。

## manifest 协议冻结（2026-09-06 第七轮；real 改上游投影后的操作化规则）

### (A)/(B) 裁定：选 (A)——G1 重定义为"对上游树的判定"

real 主臂改为上游 Python 投影后，原 G1（"canonical diff 应用到 corpus vuln/ == corpus fixed/"）
**失效，15/15 不会自动延续**——上游投影基线是 `parent(fix_commit)`、目标是 `fix_commit`，与
corpus 树非同一对象；投影是 corpus 超集时（45019：语料 10 文件 vs 上游 ~23），G1 双向路径比较
必然 FAIL。

**裁定（选 A，与四臂设计一致）**：
- **新 G1（upstream-real 结构门禁）**：fetch `parent(fix_commit)` 与 `fix_commit` 两棵树，机械
  提取 Python 投影；门禁目标 = "投影应用到 parent 树的 Python 文件 == fix commit 树的 Python
  文件"（双向路径集合 + 逐文件字节/哈希 + apply-clean）。产出独立报告
  `v4_upstream_real_report.json`。
- **原 corpus G1 降级**：作为**一致性层（第⑤层 corpus-complete）**，不再充当 real 主臂的结构
  证据。
- 否决 (B) 的理由：real 主臂已是 upstream projection（Codex 已裁决），(B) 会退回 corpus 作
  real，与"corpus-complete 已降级为一致性检查"自相矛盾，且会复现"名为 real 实为 partial"
  （45019 语料漏了上游安全关键文件）。

### 报告降级

当前 `v4_gates_report.json`（15/15 G1_G2_STRUCTURAL_PASS）验证的是 **corpus 快照生成器**，
非新 real 臂。**命名降级为 "corpus-snapshot structural validation"**，保留不删，但**不得作为
新 real 臂的 Gate A 证据**。新 upstream manifest + 生成器完成后，须重新生成
`v4_upstream_real_report.json`（含上游来源/父提交/Python 投影/apply-clean/树一致性/纳入排除
文件/实际送模 diff SHA/token 统计）。

### manifest schema（填充 15 例前冻结；先提交 schema 再填数据，不得先做数据后补规则）

| 字段 | 类型 | 说明 |
|---|---|---|
| sample_id | str | 唯一键 |
| cve_id | str | |
| repository | str | repo_slug |
| advisory_url | str | 上游 advisory/PR 链接 |
| fix_commit | str | 完整 40 位 hash |
| parent_commits | list[str] | fix_commit 全部父提交 |
| parents_count | int | 父提交数 |
| is_merge | bool | merge/复合提交自动线索（提交信息含 "Merge"） |
| selected_base_commit | str | 实际投影基线（fail-closed 选择，见下） |
| selected_base_reason | str | 选此父提交的理由 |
| upstream_changed_files | list[str] | fix_commit^..fix_commit 改动文件全集 |
| python_included_files | list[str] | 机械 Python 投影 |
| non_python_excluded_files | list[str] | 被排除的非 Python 文件 |
| added/deleted/renamed_files | dict | 三类结构化记录 |
| co_fixed_cves | list[str] | 同提交修复的其它 CVE |
| candidate_patch_base_commit | str | 候选补丁应用的基线 |
| prompt_source_commit | str | 模型看到的 vulnerable 源码来源 |
| cpg_context_source_commit | str | CPG 上下文来源 |
| corpus_vuln_vs_upstream_parent_delta | obj | corpus vuln 与 upstream parent 的差异（双向） |
| relevant_source_files_byte_equivalent | bool | 相关源文件字节等价证明 |
| patch_apply_clean_to_prompt_source | bool | 补丁能否 apply 到 prompt source |
| cpg_rebuild_required | bool | 是否需重建 CPG |
| **composite_fix_commit** | bool | **fail-closed**：`== true` 排除 |
| **security_critical_non_python_change** | bool | **fail-closed**：`== true` 排除 |
| **python_projection_sufficient** | bool | **fail-closed**：`!= true` 排除 |
| token_count | int | 投影后 token 数 |
| context_limit_eligible | bool | 本地模型能否装下 |
| confirmatory_eligible | bool | 推导（三布尔 + token/context + 三源一致，见下） |
| exclusion_reason | str | 排除理由（fail-closed 时必填） |
| reviewer_1 / reviewer_2 | str | 双人核验 |
| adjudication | str | 分歧仲裁 |

**三源一致性纳入条件（P0-2；否则出现"上游补丁 + corpus 源码 + corpus CPG"语义错配）**：

```text
candidate_patch_base_commit == prompt_source_commit
cpg_context_source_commit == prompt_source_commit
```

二者**必须相同**，或提供机器可核验的"相关源文件字节等价"证明（`relevant_source_files_byte_equivalent`）。
具体回答四问：①模型看到的 vulnerable source 是否来自 upstream parent；②旧 corpus CPG 能否继续
用；③corpus vuln 与 upstream parent 不一致时是否重建 CPG（`cpg_rebuild_required`）；④patch 是否
可 apply 到实际 prompt source（`patch_apply_clean_to_prompt_source`）。三源未对齐的样本退出确认性。

**Python 投影规则冻结（Hy4：先冻结再测量，否则 Δ 表作废）**：投影 = 上游 fix_commit 改动文件里
**所有 `.py`（含 tests，含 `.pyi`）**。此规则在测量前写死，不得事后改"排除 tests"或"含/不含 .pyi"
以迁就结果。

**Δ 指标精确定义（P1-1 + 第十轮升级为分层；先定义再判"近似"，禁看完数据再定"差异不算大"）**：

> ⚠️ **第十轮核心教训**：路径级 Δ=0 **只证明"文件路径集合一致"，不证明补丁内容完整**（早期
> "90 行窗口 + [:4000]"同类问题）。实测 45019 路径级 Δ=0，但内容级发现 **fixed 快照缺了
> mcp.py/types.py/test_session.py**——见下"内容级"。故 Δ 分两级，禁混称。

**L1 路径级（path-set）**：
- `delta_paths`：上游 Python 投影文件集 vs corpus `.py` 文件集，双向差集 `|P\C|` / `|C\P|` 分列；
- `delta_change_types`：added/deleted/renamed/status 是否一致。

**L2 内容级（blob，须逐个文件比对上游 parent/fix blob 与 corpus vuln/fixed）**：
- `delta_base_blobs`：corpus vuln 与 upstream parent 对应 blob 字节是否一致；
- `delta_fixed_blobs`：corpus fixed 与 upstream fix 对应 blob 字节是否一致；
- `delta_patch_hunks`：每文件 canonical patch 的 SHA/hunk 集合是否一致；
- `delta_file_modes`：file mode / symlink / 末尾换行是否一致；
- 存在性：`delta_base_presence` / `delta_fixed_presence`（文件在两端是否都存在）。

**字节级 vs 内容级**：corpus 在 Windows checkout 下 LF→CRLF（git autocrlf），属环境行尾差非内容
差；内容级比较按**归一化行尾（CRLF→LF）**，`line_ending_diff` 单独记录原始字节行尾差。

"内容级等价（byte-equivalent）" = L1 + L2 全部通过。**即使路径级 14/15 Δ=0，内容级仍须全量重跑，
不自动继承认证结果。** 权威 diff 来自本地 Git 对象 `git diff --binary --full-index <base> <fix>`，
**不以 API 的 patch 字段为权威**（patch 可能分页/截断）。

**多 parent 选择 fail-closed（P1-2）**：
- 单 parent：暂取唯一 parent，但**仍须确认其含漏洞**（advisory/PR 佐证）；
- 多 parent / merge：**禁默认取 `^1`**；须从 advisory/PR 确认哪个是干净 vulnerable base；
- cherry-pick / 合并 / 复合安全提交：parent 未必是干净 vulnerable base；
- 无法从 advisory/PR 确认 base → `selected_base_commit` 置 `unverifiable`，**退出确认性**。
- ⚠️ **第十轮实测**：`parents_count=1` 对全部 15 例，`is_merge=0`——**`is_merge` 在本语料完全
  不能用作复合信号**（45019 标题 "Merge commit from fork" 是假 merge）。复合判定一律走
  advisory/PR + 第二标注者，不得指望 `is_merge`。

**API 工件复现门禁（Codex）**：GitHub API/raw 结果须保存原始证据或元数据——请求 URL、HTTP 状态、
fetch 时间、commit SHA、parent SHA、原始响应 SHA-256、是否分页。API 的 `files[].patch` 可能分页/
截断/缺失，**不作权威补丁**。

**三个 fail-closed 布尔（三布尔异号，禁自然语言并列；未知值一律不过）**：

```python
confirmatory_eligible = (
    composite_fix_commit is False
    and security_critical_non_python_change is False
    and python_projection_sufficient is True
)
```

1. `composite_fix_commit == true` → **排除**（同提交修了多个 CVE，ground-truth 归属污染）；
2. `security_critical_non_python_change == true` → **排除**（被排除的非 Python 文件含修复该 CVE
   必需的安全行为变更，如依赖版本/配置/模板/路由/YAML 权限/前端或代理层改动）；
3. `python_projection_sufficient != true` → **排除**（即 **=true 才是纳入的必要条件**；投影无法
   自证"补丁充分性"则排除）。

⚠️ 三条极性不同：前两条 `== true` 排除、第三条 `!= true` 排除。代码必须用
`is False / is True` 显式判定，`None`（未知值）一律不通过——**禁把三者写成"任一成立即排除"**。
判定来源 = upstream advisory/PR + 差异审阅 + 第二标注者，**禁 CPG 判断**；无法确认的样本退出
确认性主分析，进敏感性分析。

### shuffled donor 匹配规则（冻结；Codex P0-4）

"token 匹配 donor"不够。另一 CVE 的 diff 常文件名不对应/不可 apply/CWE 完全不同/一眼可判无关。
规则（按优先级）：
1. 优先**同仓库** donor；
2. 相近 CWE/修复类型；
3. token 数、文件数、hunk 数、修改行数匹配；
4. 新增/删除文件**结构**匹配；
5. 明确是否要求 apply-clean（建议要求，否则模型可凭"不可 apply"识破）；
6. **无合适 donor 时排除，不任意抽取**——不得把明显不相关的 patch 伪装成 hard negative，也
   不得强行把不同文件名改成相同文件名伪装。
匹配后报协变量平衡表/标准化均值差，n=15 下不平衡如实披露。

### partial 构造规则（冻结；Codex + ai2）

- 构造依据在模型结果产生前冻结；
- 第二标注者**独立**判断关键 hunk；分歧由导师/第三人仲裁；报 κ；
- partial 必须 apply-clean；必须说明剩余漏洞路径；
- 可执行 PoC 可用时优先验证：vuln→失败、partial→仍触发、real→不触发；
- 无执行 oracle 时明确标"构造性/人工 oracle"；
- 构造者不得看到 partial 臂模型结果后再调整补丁。

### n 下限预注册（go/no-go 阈值；待功效分析确定，暂不冻结具体数字）

总样本量不是 McNemar 检验的有效信息量——有效信息主要来自 **discordant pairs**。`n=8` 即使全部
合格，也可能只有一两对 discordant，撑不起确认性结论。故：

1. 在未知模型结果前，先给出若干预期 discordance 场景；
2. 对 n=8..15 做 **exact McNemar / binomial 功效或可检测效应分析**（纯标准库脚本，可复算）；
3. 再冻结确认性最低 n（当前 `n=8` 仅作占位，**非已注册下限**）；
4. 若最终 n 不足：real–partial 降级为"**探索性补丁充分性研究**"（**非"外观敏感性"**——后者是
   placebo/shuffled 才涉及的概念，不能张冠李戴）。

功效分析在填数据阶段用脚本产出，结果并入 manifest 交付物。第 1 天知道 n 不够可改设计，第 20 天
只能砍 claim。

### 排期（人不可并行，优先锁日历）

- **partial 双标日历今日锁死**（依赖师兄，不可并行不可压缩），优先级高于任何代码；
- 双标**不必等 manifest**：先在 corpus diff + advisory 文本上立即启动关键 hunk 识别，上游投影
  出来后再重新锚定（关键 hunk 大概率本就在 corpus 子集，重锚定成本低）；
- 45019（复合提交）后置——难标注且已排除出确认性分析。

## 完成判据（2026-09-06 拆分 Gate A/B，消除"§3 含 partial 标注 vs 排期先跑三臂"的冲突）

**Gate A（三臂跑批前）** —— 通过后只运行 real/placebo/shuffled：
- **placebo 人工自然度/臂指纹盲验（构造者+第二标注者，在见模型结果前完成）**；
- G0-G4 门禁对三臂候选包全绿（**upstream fix-commit derived Python projection（real）** + apply-clean placebo + 残余漏洞
  分层 oracle + token 比 [0.8,1.25]（四臂作用域定下后重设））；
- prompt/diff/digest/日志与统计协议冻结；端到端 smoke 通过；
- 外部验收通过。

**Gate B（partial 跑批前）** —— 通过后才运行 partial 臂：
- partial 基于**上游投影 real** 重构（删除双人确认关键安全 hunk；14 例构造表 + 45019 从确认性主分析排除、仅入全样本）；
- oracle 分层完成（T1 可执行约 3 例/T2 断言/T3 人工+双人确认）；
- 四臂混合盲标 + 仲裁 + 纳入名单冻结；构造者此前未查看 partial 模型结果；
- partial 的 prompt/token/apply 门禁通过。

**冻结** = Gate A 与 Gate B 各自通过后，相应臂进入跑批；四臂结果（real/placebo/shuffled + partial）+ 分析完成后
进入论文层。此后只许跑批、分析、写论文，门禁层不再新增条目
（新发现的问题进 backlog，投稿后再议）。

> 注：**"干净克隆复算通过"只解锁 G0-G4 实现，不等于可申请最终验收**——
> 验收对象是候选包与门禁结果，不是复算脚本。
