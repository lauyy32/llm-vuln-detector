# 后端架构：上下文增强漏洞检测（三模式消融）

> 复用既有基础设施：`cpg/pipeline.py`（CodeQL 2.26.2 CLI 管线）、`cpg/slice_builder.py`、16 条 `dataset.jsonl`（vuln/→vulnerable，fixed/→benign）。不重写 CPG 提取。

## 1. API 端点（OpenAPI 风格）
`POST /api/v1/detect`

请求体（以一次 CWE-22 tar 解压案为例，示例非指定）：
```json
{"mode":"request|code|both","sample_id":"CVE-2026-50558",
 "code":"<vuln_code 文本，仅 code/both>",
 "request":{"poc":"...","trigger_input":"...",
            "advisory":{"cve_id":"...","cwe":"CWE-22","summary":"..."}}}
```
响应体：
```json
{"verdict":"vulnerable|benign","confidence":0.0,"cwe":"CWE-22",
 "mode":"code","scorer":"StructuralHeuristicScorer",
 "evidence":[{"type":"taint","cwe":"CWE-22","sourceLine":19,"sinkLine":30,"file":"penelope.py"}]}
```
mode 组装 `DetectionContext`：request 仅填 `request_info`/`advisory_meta`，`code_text` 与 `cpg_slices` 空；code 填 `code_text` 并据 pipeline 产物生成 `cpg_slices`；both 二者皆填。request 模式 MVP 下无 CPG，仅作「无码检测天花板」对照点（预留 LLM）。

## 2. Scorer 接口（以 StructuralHeuristic 为例，示例非指定）
```python
@dataclass
class DetectionContext:
    request_info: dict | None   # poc / trigger_input
    advisory_meta: dict | None  # cve_id / cwe / summary
    code_text: str | None
    cpg_slices: str | None      # slice_builder 文本

class Scorer(ABC):
    def score(self, ctx: DetectionContext) -> Verdict: ...   # Verdict{label,confidence,cwe,evidence}
```
- `CodeQLBaselineScorer`：对样本源码跑官方 `database analyze`（python-code-scanning 套件），解析 SARIF 得纯静态 baseline verdict，不依赖 mode。
- `StructuralHeuristicScorer`：消费 `cpg_slices` 与 `taint.csv`，按「目标 CWE 是否存 source→sink 流」判 vulnerable，无 LLM。
- `LocalLLMScorer`（预留，本期不实现）：吃 context 文本调 Ollama Qwen2.5-Coder；`score()` 签名已留。

## 3. CodeQL 基线适配器
复用 pipeline.py 已建同一 DB（不重建）：
```bash
codeql.exe database analyze C:/Users/lenovo/cpg_db/sample_db ^
  codeql/python-queries:codeql-suites/python-code-scanning.qls ^
  --format=sarif-latest --output=cpg/ablation/<sample>/baseline.sarif --download
```
解析 SARIF：`run.tool.driver.rules[].properties.tags` 含 `cwe/CWE-089`，建 `ruleId→CWE` 映射；每条 `result` 按 `locations[].physicalLocation.artifactLocation.uri` 是否命中样本文件且 CWE 匹配，得「是否命中 CWE-X」verdict。pipeline 的自定义 taint 查询仅供 StructuralHeuristic，与官方基线分流、互不覆盖。

## 4. 消融 harness
`cpg/ablation/run_ablation.py` 遍历 `dataset.jsonl`：每行展开为 vuln 文件(label=vulnerable)、fixed 文件(label=benign) 两样本；对各样本构造 request/code/both 三种 `DetectionContext`，调用 Scorer 集（含 CodeQLBaseline）；收集 `(sample, mode, scorer, predicted, truth)`。聚合全量及 per-CWE 的 P/R/F1，输出 `cpg/ablation/results.csv` 与 `summary.md`。

## 5. 复用现有 pipeline 产物
code 模式对样本跑 `pipeline.py`（复用其 DB 与 ast/cfg/dfg/taint 查询）得 `taint.csv`（列 `cwe,file,sourceLine,sourceNode,sinkLine,sinkNode`）与切片；调 `slice_builder.build_slice(out_dir, source, func, ...)` 文本塞入 `DetectionContext.cpg_slices`。StructuralHeuristicScorer 直接读 `taint.csv`：同文件、同目标 CWE 存在 source→sink 即判 vulnerable。不重新实现 CPG 提取。

## 6. 技术约束
- 无新数据库：全文件化，结果落 `cpg/ablation/`。
- Python 隔离：以 `C:\Users\lenovo\.workbuddy\binaries\python\versions\3.13.12\python.exe -m venv .venv` 建 venv，依赖入 venv。
- 必须先把 `C:/Users/lenovo/cpg_db` 加入 Windows Defender 排除项，否则 dataflow 因缓存锁失败。
- 幂等：pipeline 按 CSV 是否含数据行跳过；harness 以 `sample_id+mode+scorer` 缓存 verdict，重跑仅补缺。
