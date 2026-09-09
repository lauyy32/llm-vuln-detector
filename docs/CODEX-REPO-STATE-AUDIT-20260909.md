# CODEX 仓库状态审计（REPO-STATE-AUDIT）

> 来源：外部评审 codex 的只读核验报告，逐字转录（原文审计基线 `origin/main = 644f713`）。
> 本文件为当前阶段的上位执行约束。冲突裁决：**仓库事实以本文件为准**。

---

只读核验完成。结论是：仓库目前并非"只差跑 61539/67435"，而是基础门禁仍有数个 P0；继续单例实验会扩大返工。

仓库状态：

- 本地与远端 HEAD 一致：`644f71310f17c3718de9b94cfdcfeb43da6406ce`
- 工作区干净
- 当前为 detached HEAD

## 已经真实完成

- 五态审计机器结果：93 例中 77 OK、16 `CORPUS_ERROR`、0 unverifiable。
- 14 个 `corpus-v2` 样本已跟踪，样本 ID 与 canonical manifest 一致。
- canonical manifest 已记录：
  - 并集：77 v1 + 14 v2 + 2 排除 = 93
  - 74 集：65 + 9 = 74
  - D1：69 + 14 + 2 = 85，候选分母 83
- 61539 已有无摘要、历史 prompt 字节等价的复验工件，保存了完整模型 digest、请求和原始响应。
- zero-diff 检查已经按"纳入样本与零差异集合的交集"实现。

## 当前 P0

1. **canonical manifest 并不是真正的纳入门禁**：`canonical_manifest.py:64` 只是把旧审计状态机械映射成 v1/v2/eligible；没有执行 freeze 里的复合提交、来源一致性、模型结果继承等规则。干净克隆中还有 12 个被标为 eligible/v1 的样本根本没有公开语料目录。

2. **canonical tree hash 不可跨机器复现**：`canonical_manifest.py:34` 哈希工作区原始字节。受 `core.autocrlf` 影响，干净克隆中的 14 个 v2 hash 全部不同；归一化 CRLF 后才全部一致。

3. **`verify_claims` 会在结果未闭环时返回 PASS**：`verify_claims.py:37` 只检查硬编码计数，未验证路径、hash、逐例重建 manifest 和五态审计；`verify_claims.py:52` 只打印 `result_gate PROVISIONAL`，最终仍可能 PASS。旧 `claims.json` 还冻结着 `2/82`、`7/82`。

4. **多父提交没有 fail-closed**：CVE-2026-53656 的 parent commit 有两个父提交，却仍被 canonical manifest 标为 eligible。`upstream_five_state_audit.py:78` 对多父提交仅将 `parent_sha=None`，仍可能返回 OK；这违反 `EXPERIMENT-FREEZE.md:305` 的规则。

5. **内容审计仍有 fail-open**：`upstream_five_state_audit.py:83` 只有 HTTP 200 且内容不同才记录 mismatch；非 200、超时会被静默绕过。执行分母还会被照常增加，因此"content mismatch=0"尚不能证明所有 blob 都实际核验成功。

6. **`rebuild_pair` 不是原始字节级、批量也不 fail-closed**：`rebuild_pair.py:31` 以 UTF-8 文本方式读取 Git blob，再编码写出，可能改变换行或非 UTF-8 内容；`rebuild_pair.py:225` 批量模式即使个别样本失败，最终仍返回 0。

7. **最新 61539 A5 消融仍无效**：`ablate_61539.py:100` 把 `utils` 块追加到一个已截断、语法未闭合的 v1 prompt（`choices": [# ===== FILE: utils.py...`）；变体未保持原 8000 字符预算；删除块后也没补齐预算。因此 A5 不能支持"上下文不鲁棒"因果结论，协议中还缺 A6 将其正式作废。

8. **V4 Gate A 尚未建立**：freeze 要求的 `v4_upstream_real_report.json` 不存在；`upstream_manifest.json` 的 15 个案例中，复合性、安全关键非 Python 变更、投影充分性、三源 commit、token、双 reviewer、仲裁等关键字段全部未填；旧 `v4_gates_report.json` 只验证损坏的 corpus snapshot，freeze 本身也明确不能把它当新 real 臂证据。

## 当前报告与工件不一致

- `五态审计报告.md:8` 写 79 OK / 14 error；机器 JSON 实际为 77 / 16。
- 同一报告仍把 61539 写成 SSRF，而其真实 CWE 是 CWE-95。
- `docs/D1-语料缺口与可复现性说明.md:52` 仍称"17/85 缺口不存在"。
- `cpg/ablation/raw_prompt审计.md:59` 仍声称 14 例历史结果可直接继承。
- `docs/EXPERIMENT-FREEZE.md:108` 仍称 API key 是"唯一阻塞项"，与实际状态冲突。

## 真正关键路径

1. 立即停止新的单 CVE 试验；追加 A6，正式标记 A5 无效。
2. 修基础工件：Git blob 按 bytes 提取；批量重建原子化且任一失败非零退出；五态审计对非 200/超时/multi-parent fail-closed；解决 CVE-53656 base；让缺失的 12 个语料样本可公开重建或获取；canonical hash 改 Git blob ID 或规范化内容 hash；`verify_claims` 必须逐样本验证，并在 result gate provisional 时非零退出。
3. 将工作拆成三个互不混用的轨道：H（历史 83 对语料和结果重跑）、V（V4 15 例四臂 Gate A/B）、M（上下文鲁棒性探索性实验）。
4. 在复验 67435 或全量模型调用前，先冻结通用 prompt/excerpt 规范：禁手工 prompt；仅完整文件/AST 边界截取，禁止中途截断语句；FULL/PARTIAL/ABSENT 安全 hunk 覆盖；固定字符/token 预算及补位规则；DB source-tree SHA、prompt SHA、完整模型 digest、请求和响应；批次结束前不揭示单例输出。
5. 历史模型没有 digest，无法形式证明继承；稳妥路线是按单一冻结协议重跑 83 对。
6. 并行推进 V4：填满 15 例 upstream manifest；产出新的 upstream G1 报告；完成 G0/G3/G4、真实 tokenizer、shuffled/placebo；Gate A 后再做 partial 双标和 Gate B。

缺失的关键工件包括：

- `v4_upstream_real_report.json`
- `make_partial_diffs.py`
- `partial_diffs.json`
- `prompt_snapshot/`
- `shuffled_manifest.json`

因此，现阶段最有效的指导不是继续"发现一个 bug 修一个 bug"，而是先建立上述三轨结构和逐层 fail-closed 验收链。
