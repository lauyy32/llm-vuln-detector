"""消融实验共享常量与 CodeQL 调用辅助。

这里的 win_path / make_env / run / _csv_has_rows / _is_defender_block /
CWE_TAINT_QUERIES / QUERY_TIMEOUT 全部逐字复制自 ``cpg/pipeline.py``（已验证可跑通的
命令与 bqrs 解码逻辑），目的是把单样本级逻辑泛化到 cpg_eval.extract_taint，而不重写
CodeQL 调用。任何 Windows 路径陷阱、Defender 缓存锁、JAVA_HOME 要求都沿用 pipeline 的
既定处理。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径锚点
# ---------------------------------------------------------------------------
# cpg/ablation/config.py -> parents[0]=cpg/ablation, parents[1]=cpg, parents[2]=repo
HERE = Path(__file__).resolve().parent
CPG_DIR = HERE.parent                       # .../llm-vuln-detector/cpg
REPO_ROOT = CPG_DIR.parent                  # .../llm-vuln-detector
ABLATION_DIR = HERE                         # .../cpg/ablation

CODEQL_EXE = CPG_DIR / "codeql" / ("codeql.exe" if os.name == "nt" else "codeql")
CODEQL_QUERIES_DIR = CPG_DIR / "codeql-queries"   # 自定义 cpg 查询（含 qlpack.yml）
QUERIES_DIR = CPG_DIR / "queries"                 # taint.ql / cwe-XXX.ql

# 外部数据根（DB / 语料源 / SARIF）——单点配置，避免跨脚本硬编码。
# 默认落在已加入 Windows Defender 排除项的短路径；可用环境变量 CPG_DATA_ROOT 覆盖。
_DATA_ROOT_DEFAULT = Path(os.environ.get("CPG_DATA_ROOT", "C:/Users/lenovo/cpg_db"))
DATA_ROOT = _DATA_ROOT_DEFAULT if _DATA_ROOT_DEFAULT.is_absolute() else _DATA_ROOT_DEFAULT

# 已建好的复用资源（Dry-run A 直接复用，不重建）
DEMO_DB = DATA_ROOT / "sample_db"
DEMO_TAINT_CSV = CPG_DIR / "output_demo" / "taint.csv"
SAMPLES_DIR = CPG_DIR / "samples"
DATASET_JSONL = CPG_DIR / "dataset.jsonl"
RESULTS_CSV = ABLATION_DIR / "results.csv"
SUMMARY_MD = ABLATION_DIR / "summary.md"
WORK_DIR = ABLATION_DIR / ".work"          # 真实样本临时 DB / taint 产物

# 语料库级产物（corpus_db.py 引用；单点定义，脚本间共享）
CORPUS_SRC = DATA_ROOT / "corpus_src"
CORPUS_DB = DATA_ROOT / "corpus_db"
CORPUS_SARIF = DATA_ROOT / "corpus_baseline.sarif"

# Bandit 可执行文件（P1 工具对比用；环境变量 BANDIT_EXE 可覆盖）
BANDIT_EXE = Path(os.environ.get(
    "BANDIT_EXE",
    "C:/Users/lenovo/.workbuddy/binaries/python/envs/default/Scripts/bandit.exe",
))

# Ollama 服务地址（LocalLLMScorer 默认值同源）
OLLAMA_BASE = os.environ.get("OLLAMA_BASE", "http://localhost:11434")

# ---------------------------------------------------------------------------
# Java / CodeQL 运行环境
# ---------------------------------------------------------------------------
DEFAULT_JAVA_HOME = r"C:/Program Files/Java/jdk-21.0.1"

# ---------------------------------------------------------------------------
# CWE -> taint 查询 basename（复制自 pipeline.CWE_TAINT_QUERIES）
# 键统一用 3 位补零形式（CWE-022），与查询 select 输出的 "CWE-022" 一致。
# dataset.jsonl 里写的是 "CWE-22"（无前导零），需经过 normalize_cwe 对齐。
# ---------------------------------------------------------------------------
CWE_TAINT_QUERIES = (
    ("CWE-022", "taint"),     # queries/taint.ql       -> PathInjectionFlow
    ("CWE-022", "tarslip"),   # queries/tarslip.ql     -> TarSlipFlow（extractall/extract 提取）
    ("CWE-089", "cwe-089"),   # SqlInjectionFlow
    ("CWE-078", "cwe-078"),   # CommandInjectionFlow
    ("CWE-094", "cwe-094"),   # CodeInjectionFlow
    ("CWE-918", "cwe-918"),   # FullServerSideRequestForgeryFlow
    ("CWE-079", "cwe-079"),   # ReflectedXssFlow
)

# 可污点类（CPG taint 覆盖的 CWE），用于消融分两组报告（SPEC §7）
TAINT_COVERED_CWES = {"CWE-022", "CWE-089", "CWE-078", "CWE-094", "CWE-918", "CWE-079"}

# 查询超时（秒）。单样本 DB 较小，dataflow 查询给足余量（复制自 pipeline.QUERY_TIMEOUT）。
QUERY_TIMEOUT = {"ast": 120, "cfg": 120, "dfg": 180, "taint": 1200}
EXTRACT_TAINT_TIMEOUT = 1200   # extract_taint 单样本建 DB + dataflow 的墙钟上限
DB_CREATE_TIMEOUT = 300


# ---------------------------------------------------------------------------
# CWE 归一化
# ---------------------------------------------------------------------------
def normalize_cwe(cwe: str | None) -> str | None:
    """把任意形状写成 CodeQL 标签用的 3 位补零形式。

    "CWE-22"  -> "CWE-022"
    "cwe-918" -> "CWE-918"
    "CWE-79"  -> "CWE-079"
    空/None   -> None
    """
    if not cwe:
        return None
    s = str(cwe).strip().upper().lstrip("CWE-").strip("-")
    if not s.isdigit():
        # 已带字母或无法解析，原样返回（去除空白）
        return str(cwe).strip()
    return f"CWE-{int(s):03d}"


def taint_query_basename(cwe: str | None) -> str | None:
    """返回该 CWE 对应的查询文件名（不含扩展名），无 taint 查询返回 None。"""
    norm = normalize_cwe(cwe)
    if norm is None:
        return None
    for q_cwe, qbase in CWE_TAINT_QUERIES:
        if q_cwe == norm:
            return qbase
    return None


# ---------------------------------------------------------------------------
# 复制自 pipeline.py 的辅助函数（保持行为一致）
# ---------------------------------------------------------------------------
def win_path(p: Path) -> str:
    """Render a path the way the native codeql.exe expects it."""
    return str(p.resolve()).startswith("/") and str(p.resolve()) or str(p.resolve()).replace("\\", "/")


def codeql_binary() -> Path:
    exe = CODEQL_EXE
    if not exe.exists():
        sys.exit(f"codeql binary not found at {exe}; see cpg/README.md for the bundle download")
    return exe


def make_env(java_home: str) -> dict[str, str]:
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    return env


def _kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        import signal

        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except Exception:
            pass


def run(cmd: list[str], env: dict[str, str], timeout_s: int) -> int:
    """Run a command under a wall-clock watchdog. Returns the exit code.

    超时则杀掉整棵进程树并返回哨兵值 124（复制自 pipeline.run）。
    """
    print("$", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        out, err = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_tree(proc.pid)
        try:
            out, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out, err = "", ""
        print(f"[timeout] killed after {timeout_s}s: {' '.join(cmd)}", flush=True)
        if out:
            print(out, flush=True)
        if err:
            print(err, file=sys.stderr, flush=True)
        return 124
    if out:
        print(out, flush=True)
    if err:
        print(err, file=sys.stderr, flush=True)
    return proc.returncode


def _csv_has_rows(csv_path: Path) -> bool:
    if not csv_path.exists():
        return False
    lines = csv_path.read_text(encoding="utf-8").splitlines()
    return len(lines) >= 2  # header + at least one data row


def _is_defender_block(stderr: str) -> bool:
    return any(
        sig in stderr
        for sig in (
            "Cant write tuple pool file",
            "AccessDeniedException",
            "ResourceError",
            "Severe disk cache trouble",
        )
    )


def resolve_suite() -> str:
    """返回 python-code-scanning 套件的引用形式。

    优先用发行版自带的绝对路径（离线可用、版本无关由 glob 处理）；
    若发行版布局变更，则回退到 pack-id 形式 ``codeql/python-queries:...``。
    """
    candidates = sorted(CODEQL_EXE.parent.glob(
        "qlpacks/codeql/python-queries/*/codeql-suites/python-code-scanning.qls"
    ))
    if candidates:
        return win_path(candidates[0])
    return "codeql/python-queries:codeql-suites/python-code-scanning.qls"


def ensure_sys_path() -> Path:
    """把仓库根加入 sys.path，使 ``from cpg.ablation import X`` 在脚本直跑时可用。"""
    root = REPO_ROOT
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    return root
