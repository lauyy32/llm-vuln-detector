# Spec - 三模式上下文消融实验 v0.1

> 生成日期：2026-08-08
> 基于：PRD-ablation-3mode.md (v1) + ARCHITECTURE.md (v1) + DESIGN.md (v1)
> 状态：已确认（用户确认三文档 + request 模式决策）
> 项目总监：大湾区靓仔 | PM：许清楚 | 架构师：高见远 | 设计师：颜好看

---

## 1. 产品定义
- **一句话**：LLM+CPG 漏洞检测的「三模式（request / code / both）」消融实验骨架，以 CodeQL 2.26.2 官方套件作基线。
- **目标用户**：研究者（本人）、导师汇报。
- **核心问题**：给 LLM 注入代码级 CPG 上下文，是否比仅请求侧信息更能准确判定漏洞。

## 2. MVP 范围（锁定——不在列表的功能一律不做）
| 优先级 | 功能 | 验收标准摘要 |
|--------|------|-------------|
| P0 | `POST /api/v1/detect{mode}` 端点 | 三模式枚举校验，返回 verdict/confidence/cwe/mode/scorer/evidence |
| P0 | 可插拔 `Scorer` 抽象 + 注册 | `CodeQLBaselineScorer` / `StructuralHeuristicScorer` / `LocalLLMScorer`(stub) |
| P0 | `DetectionContext` 数据类 | 字段 request_info / advisory_meta / code_text / cpg_slices |
| P0 | 按 mode 构造 context | request 模式**显式 abstain**（见 §8）；code/both 填 CPG 切片 |
| P0 | CodeQL 基线适配器 | `codeql database analyze` 跑官方 `python-code-scanning` 套件，SARIF→verdict |
| P0 | 消融 harness `run_ablation.py` | 遍历 dataset.jsonl（展开 vuln/fixed），三模式+基线，聚 P/R/F1 + per-CWE，落 results.csv + summary.md |

## 3. 明确不做（Out-of-Scope）
| 不做 | 原因 | 何时考虑 |
|------|------|----------|
| 接真实 LLM（LocalLLMScorer 仅 stub） | 先消 API 漂移、立即可复现 | 锁 Ollama Qwen2.5-Coder 后 |
| Web 前端 | 本期科研骨架优先，设计方向已留 | 导师汇报前 |
| 扩语料（维持 16 CVE） | GitHub API 60/hr 限制，耗时 | 后续独立任务 |
| request 模式派生 PoC | dataset.jsonl 无请求字段，raw_advisories 无结构化 PoC | 后续补请求侧语料 |

## 4. 技术架构（锁定）
- **后端**：FastAPI（独立 app `cpg/ablation/api.py`，uvicorn 可启）；Python 用 managed `3.13.12` 建 venv 隔离
- **无新数据库**：全文件化，结果落 `cpg/ablation/`
- **CodeQL 2.26.2 CLI**：`cpg/codeql/codeql.exe`，复用 `pipeline.py` 已建 DB（不重建）
- **Defender 排除**：`C:/Users/lenovo/cpg_db` 必须已排除，否则 dataflow 缓存锁失败
- **幂等**：pipeline 按 CSV 数据行跳过；harness 以 `sample_id+mode+scorer` 缓存 verdict

## 5. API 端点（锁定）
`POST /api/v1/detect`
```jsonc
// 请求
{"mode":"request|code|both","sample_id":"CVE-xxxx",
 "code":"<vuln_code 文本，仅 code/both>",
 "request":{"poc":"...","trigger_input":"...",
            "advisory":{"cve_id":"...","cwe":"CWE-22","summary":"..."}}}
// 响应
{"verdict":"vulnerable|benign|abstain","confidence":0.0,
 "cwe":"CWE-22","mode":"code","scorer":"StructuralHeuristicScorer",
 "evidence":[{"type":"taint","cwe":"CWE-22","sourceLine":19,"sinkLine":30,"file":"penelope.py"}]}
```
`mode` 非法值返回 422。

## 6. Scorer 接口（锁定）
```python
@dataclass
class DetectionContext:
    request_info: dict | None   # poc / trigger_input
    advisory_meta: dict | None   # cve_id / cwe / summary
    code_text: str | None
    cpg_slices: str | None      # slice_builder 文本

@dataclass
class Verdict:
    label: str        # vulnerable | benign | abstain
    confidence: float
    cwe: str | None
    evidence: list

class Scorer(ABC):
    def score(self, ctx: DetectionContext) -> Verdict: ...
```
- `CodeQLBaselineScorer`：对样本源码跑官方 `database analyze`（python-code-scanning），解析 SARIF 得纯静态 baseline verdict，**不依赖 mode**。
- `StructuralHeuristicScorer`：消费 `cpg_slices` 与 `taint.csv`，按「目标 CWE 是否存 source→sink 流」判 vulnerable，无 LLM。
- `LocalLLMScorer`（预留 stub）：`score()` 抛 `NotImplementedError`，签名已留。

## 7. 数据集与指标（锁定）
- `dataset.jsonl` 16 CVE → 展开 vuln(正例)/fixed(负例) = **32 判定实例**；良性来源=配对修复版，禁用 SARD。
- 指标：全局 + per-CWE 的 P/R/F1 + 混淆矩阵（期望 CWE × 判定 CWE）。
- **分两组报告**（效度要求）：`可污点类`（CPG taint 覆盖的 022/089/078/094/918/079）vs `逻辑类`（862/863/639/444/295/200/400 等）。
- CodeQL 基线=官方套件 SARIF；`taint.csv` 仅喂 StructuralHeuristic，二者分流。

## 8. 边界与决策（锁定）
- **request 模式**：本期**显式 abstain**（verdict=`abstain`，confidence=0）；消融计为「未判 vulnerable」→ 对 vuln 样本召回记 0。真实比较在 **code vs both** 与 **CodeQL 基线**三路。这诚实呈现「无码检测天花板≈0」。
- 小样本：配 leave-one-out（后续）与效应量，不过度宣称。
- 版本固化：CodeQL 锁 2.26.2 并记录。

## 9. 端到端验证步骤（Spec 锁定）
```bash
# 1. 建 venv（managed python 3.13.12）
# 2. dry-run：复用 cpg/samples 已建 DB
python3 pipeline.py --rebuild --force --out-dir output_demo   # 已有 taint.csv
# 3. 端点冒烟
uvicorn cpg.ablation.api:app --port 8011
curl -X POST localhost:8011/api/v1/detect -d '{"mode":"code","sample_id":"demo","code":"..."}'
# 4. 基线适配器
python3 -c "from cpg.ablation.codeql_baseline import run_codeql_baseline; ..."
# 5. harness 单样本 -> 聚合
python3 cpg/ablation/run_ablation.py --limit 3   # 落 results.csv / summary.md
```

## 10. 变更记录
| 日期 | 变更 | 原因 | 影响 |
|------|------|------|------|
| 2026-08-08 | 初版 Spec | 三文档确认 + request 模式 abstain 决策 | 全范围 |
