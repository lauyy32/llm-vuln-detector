# OPEN #11 消融报告：切片含 AST vs 不含 AST

- 日期：2026-09-02
- 决策来源：`docs/decisions/OPEN-DECISIONS.md` 第 11 行（CPG 切片设计 / AST 要不要进文本切片）
- 结论：**显式 AST 不提升、反而略损 7B 在配对平衡语料上的判别力，并引入显著判定不稳定性 → 维持「默认不进 AST」并关闭 #11。**

## 1. 动机与假设

决策 #11 的原假设：源码文本已隐式编码 AST，重复塞入只烧 token；但显式 AST 可能帮小模型（7B）做结构推理。 closure 条件即「跑切片含 AST vs 不含 AST 消融」。

此前真实消融 harness（`run_ablation.py → context_build → cpg_eval.build_cpg_slices_text`）只把 **taint 切片**注入 LLM，源码文本（`code_text`，已隐式编码 AST）与 taint 切片分离，AST 从未进入切片文本——故 #11 一直处于 OPEN、未真正跑过。

## 2. 方法

- **接线**（4 文件）：
  - `cpg_eval.py`：新增 `build_ast_section_from_source()`，用 Python 原生 `ast` 物化显式 AST 父子边
    （`L<父行> <父类型> -> L<子行> <子类型>`），best-effort 回退截断片段；`build_cpg_slices_text` 新增
    `ast_text` 参数，非空时追加 `## AST` 段。
  - `context_build.py`：新增 `include_ast`；语料库模式按 `prefix` 读**完整** `.py` 源文件物化 AST
    （避免截断后的 `_load_sample_code` 片段 `ast.parse` 失败——试点曾见 7/12 片段解析失败）。
  - `run_ablation.py`：新增 `--include-ast` 开关。
  - `scorers.py`：把 `cpg_slices` 截断上限 4000→12000，确保大 AST 不被砍掉。
- **AST 来源选择**：采用 Python 原生 `ast` 而非 CodeQL `ast.csv`。二者同为「目标函数 AST 边列表」，
  检验的假设（显式 AST 边 vs 隐式从源码推断）一致；原生 `ast` 逐样本、无跨样本泄漏、无需为每样本重建
  CodeQL 库，更适合受控消融。CodeQL `ast.csv` 会产出等价边列表。
- **实验设置**：`qwen2.5-coder:7b`，`--modes code --seed 0 --skip-baseline`，温度 0（确定性）。
  语料 = 74 CVE × {vuln, fixed} = 148 版本（配对平衡，正类 50%）。
- **对照**：无 AST 基线 = `seeds/v8_74/results.csv`（既有主协议 7b 结果）；含 AST = `seeds/v8_74_ast/results.csv`。
  两条件除「是否含 AST 段」外完全一致（同模型、同 seed、同源码、同 taint）。
- **指标**：配对平衡语料正确度量——平衡准确率 BA、MCC、逐 CVE 配对判别（correct/inverted/both/neither）
  + McNemar 精确二项 p（`paired_metrics.py`）；并统计「加 AST 后逐版本判定翻转率」。

## 3. 结果

| 条件 | BA | MCC | correct | inverted | both | neither | net 判别 | p(精确) |
|------|-----|------|---------|----------|------|---------|----------|---------|
| 无 AST（基线） | 0.514 | +0.033 | 2 | 0 | 15 | 57 | +0.027 | 0.2500 |
| **含 AST** | **0.493** | **−0.015** | 5 | 6 | 18 | 45 | **−0.014** | 0.7256 |

- Δ net_discrimination = **−0.041**（含 AST 反而更差，从略正变略负）。
- 逐版本翻转：**59/148（39.9%）**——近四成版本在加入 AST 后改变判定，说明 AST 段未起「 grounding 」作用，
  而是扰动了一个本就接近随机的判定边界。
- 判别类别变化的 CVE：**36/74** 个。

## 4. 结论

1. **显式 AST 对 7B 的配对判别无增益**，且使 BA/MCC 双双向随机值（0.500 / 0）回落、net 判别转负。
   原决策「源码已隐式编码 AST、显式注入只烧 token」的直觉被数据支持，且更强：不仅无帮助，还略损。
2. **高翻转率（~40%）**表明 AST 段是噪声信号，加剧了已近随机判别器的不稳定性，而非提供可判定的结构线索。
3. OPEN #11 关闭：维持默认「不进 AST」（`slice_builder.py --include-ast` 仍保留作可选项，但主协议不启用）。

## 5. 局限（诚实标注）

- **prompt 长度混淆**：含 AST 条件相对基线多了一段最长 ~11.7K 字符的 AST 文本，prompt 总长约 18K。
  降解来自「AST 内容」还是「更长 prompt 的位置/注意力效应」无法在本题设下完全分离；二者共同构成
  「含 AST」条件，结论「含 AST 不提升判别」不受影响，但「降解归因于 AST 噪声」为次级推断。
- **仅 7B**：未跑 14B 规模对照；大模型是否从显式 AST 获益未知（属独立问题，非 #11 范围）。
- **原生 AST vs CodeQL AST**：边列表来源不同，但假设检验等价；若改用 CodeQL `ast.csv` 预期方向一致。
