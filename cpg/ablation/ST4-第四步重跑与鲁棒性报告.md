# ST4 · 第四步重跑与多管线鲁棒性报告（2026-09-04）

> 任务：终版计划 ④ —— 在刷新后的 corpus_db（union 93 CVE，含 D1）上重跑 74+85 消融协议，与 v9 完全同口径
> （`--skip-baseline --with-local-llm`，qwen2.5-coder:7b temp=0 无摘要），目的：① 多管线鲁棒性（无回归验证）；② 最终实测 d。
> 产物（权威）：`seeds/v10_74_7b/` + `seeds/v10_d1_7b/`（results.csv + raw_llm_responses.jsonl 148/170 行 + summary + taint_coverage）。
> 跑批：74-set 18:57:49→19:04:34（6m45s），D1-set →19:12:34（8min），双 EXIT=0，`paired_metrics.py --check` 通过。

## 1. 核心结果：判别信号跨重建**完全复现**（无回归）

配对判别（LocalLLMScorer，剔除任一侧源缺失的 CVE 后）：

| 判定器/集 | v9（重建前） | v10（重建后） | 判别 CVE（两次一致） |
|---|---|---|---|
| 74-set LocalLLM | 成功3/反向1, n_disc=4, p=0.3125, F1=0.321/BA=0.514/MCC=+0.033 | 成功3/反向0, n_disc=3, **p=0.1250**, F1=0.324/BA=0.520/MCC=+0.050 | **{54574, 61539, 67435} 100% 复现** |
| D1-set LocalLLM（n=82，剔 3 空源） | 成功3/反向1, n_disc=4, p=0.3125 | 成功3/反向0, n_disc=3, **p=0.1250** | **{54574, 61539, 67435} 100% 复现** |
| 74-set CPGEvidence | 0.196/0.500/0.000 | 0.196/0.500/0.000（逐位相同） | — |
| D1-set CPGEvidence（剔 70485） | 0.158/0.500/0.000 | 0/0 判别（70485 剔除后归零） | — |

- **核心判别信号 = 3 个 CVE {54574, 61539, 67435}**，在 corpus_db 重建前后、在 74 与 D1 两个语料上**逐字一致**——这是"信号真实存在"的最强可复现性证据（非随机噪声能稳定复现的判别样本）。
- v9→v10 唯一差异：59890 由"反向(错误判别)"变为"双漏(无判别)"（n_disc 4→3），F1/BA/MCC 漂移 ≤0.017——n_disc=3-4 边界的单样本噪声（第三轮 AI 预警的脆弱点，本次给出实测数据点）。

## 2. 关键方法学发现：**假显著性必须拦截**

v10 D1-set 原始配对曾显示 **correct=5 → p=0.0312（<0.05，看似首次显著）**。逐一核验发现：

| 新增判别 CVE | fixed 侧源 | 判定 |
|---|---|---|
| 53500 | **0 文件（空）** | ❌ 空洞——fixed 无代码 → 平凡判 benign |
| 70485 | **0 文件（空）** | ❌ 空洞（同 GT0/ST2 已申报的语料缺口） |
| 54574/61539/67435 | 3/1/1 文件 | ✅ 真判别 |

**D1 语料有 3 个 fixed 空源 CVE（53500/59224/70485，即 P0-1 已知"82/85 完整"），但从未从配对判别口径剔除**。
空 fixed 侧使判定器平凡判 benign → 制造"vuln→benign"空洞判别 → 假 p<0.05。
**剔除后：D1 诚实数字 = 3/82，n_disc=3，p=0.1250（不显著）。**

**该"显著"是语料缺口制造的假阳性**——若未逐样本核验直接写稿，将是送审即死的错误。
处置：
1. 新增 `pair_completeness.py`（扫描语料任一侧源缺失 → exit 1），配对度量一律在完整对上计算；
2. 论文方法学：**配对语料完整性门禁**（vuln/fixed 任一侧源缺失的 CVE 必须排除，否则空洞判别伪造显著性）；
3. 历史口径更正：D1 判别率分母 85 → **82**（v9 曾报 3/85，应为 3/82；判别样本未变，仅分母）。

## 3. 最终实测 d 与结论

- **最终 d（诚实）**：74-set 判别率 = 3/74 ≈ 0.041；D1 = 3/82 ≈ 0.037；n_disc=3、q=1.0（无反向）→ 单侧 p=0.125，**不显著**。
- 按 `power-analysis.md`：d≈0.04 需 ~500+ 对才有 80% 功效（当前 74-82 对差一个数量级）→ "不显著"含功效不足成分，但不能宣布有效应。
- **三线闭合（GT0/PA1/②）+ 本报告**：CPG-alone 判别随机（证据层净化器盲区）；LLM 补丁边界判别微弱且不显著（3 个可复现判别 CVE），跨管线重建稳健。
- 论文叙事：判别信号**真实存在但极弱**（3/74-3/82 可复现），CPG 证据不提供判别、只提供报警位置（14B 去 taint TP 21→3 已证）；规模无关 + 负面结果方法论稿成立。

## 4. 复现

```bash
python cpg/ablation/run_ablation.py --dataset cpg/dataset.jsonl   --skip-baseline --with-local-llm --out-dir cpg/ablation/seeds/v10_74_7b
python cpg/ablation/run_ablation.py --dataset cpg/dataset_d1.jsonl --skip-baseline --with-local-llm --out-dir cpg/ablation/seeds/v10_d1_7b
python cpg/ablation/paired_metrics.py cpg/ablation/seeds/v10_74_7b/results.csv --mode code --check
python cpg/ablation/pair_completeness.py --dataset cpg/dataset_d1.jsonl   # 应列出 3 空源
```
