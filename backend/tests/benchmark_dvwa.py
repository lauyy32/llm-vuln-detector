#!/usr/bin/env python
"""
============================================================================
  DVWA 靶场端到端对比评测
  LLM-VulnDetector vs ModSecurity OWASP CRS (工业级 WAF 基线)

  测试场景：
    1. SQL Injection (GET, id参数)
    2. Blind SQL Injection (GET, id参数)
    3. Reflected XSS (GET, name参数)
    4. Stored XSS (POST, 留言板)
    5. Command Injection (POST, ping参数)
    6. File Inclusion (GET, page参数)

  每个场景发送两组请求：
    - benign: 正常参数（预期不被拦截/不检出漏洞）
    - attack: 攻击 payload（预期被拦截/检出漏洞）

  双轨对比：
    - ModSecurity CRS: 在线 WAF 拦截 → 看 403 响应码
    - LLM-VulnDetector: 离线分析 raw HTTP → 看 is_vulnerable 判定
============================================================================
"""
import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx

# ---- 配置 ----

API_URL = os.environ.get("VD_API_URL", "http://localhost:8000")
DVWA_URL = os.environ.get("DVWA_URL", "http://localhost:8080")
MODSEC_URL = os.environ.get("MODSEC_URL", "http://localhost:8081")

DVWA_USER = "admin"
DVWA_PASS = "password"
SECURITY_LEVEL = "low"

REPORT_DIR = Path(__file__).parent / "reports"


# ================================================================
#  DVWA 自动化
# ================================================================

class DVWAClient:
    """DVWA 自动化客户端：登录、设置安全等级、操作漏洞页面。"""

    def __init__(self, base_url: str = DVWA_URL, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)
        self.logged_in = False

    def _get_token(self, page_path: str) -> str:
        """从 DVWA 页面提取 CSRF token (user_token)。"""
        try:
            resp = self.client.get(f"{self.base_url}{page_path}")
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", resp.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    # ----- 初始化 -----

    def setup_database(self) -> bool:
        """初始化 DVWA 数据库（等价于点击 setup.php 的 Create/Reset Database）。"""
        print("[DVWA] 初始化数据库...")
        try:
            resp = self.client.get(f"{self.base_url}/setup.php")
            token = self._get_token("/setup.php")
            resp = self.client.post(
                f"{self.base_url}/setup.php",
                data={
                    "create_db": "Create / Reset Database",
                    "user_token": token,
                },
            )
            if "Database has been created" in resp.text or "Setup successful" in resp.text:
                print("[DVWA] 数据库初始化成功")
                return True
            if "already exists" in resp.text.lower():
                print("[DVWA] 数据库已存在，跳过初始化")
                return True
            print(f"[DVWA] 数据库初始化可能需要重试, status={resp.status_code}")
            return False
        except Exception as e:
            print(f"[DVWA] 数据库初始化失败: {e}")
            return False

    def login(self) -> bool:
        """登录 DVWA。"""
        if self.logged_in:
            return True
        print("[DVWA] 登录...")
        try:
            resp = self.client.get(f"{self.base_url}/login.php")
            token = self._get_token("/login.php")
            self.client.headers.update({
                "User-Agent": "LLM-VulnDetector-Benchmark/1.0",
            })
            resp = self.client.post(
                f"{self.base_url}/login.php",
                data={
                    "username": DVWA_USER,
                    "password": DVWA_PASS,
                    "Login": "Login",
                    "user_token": token or "",
                },
            )
            if "Welcome" in resp.text or "Logout" in resp.text:
                self.logged_in = True
                print("[DVWA] 登录成功")
                return True
            print(f"[DVWA] 登录失败, status={resp.status_code}, url={resp.url}")
            return False
        except Exception as e:
            print(f"[DVWA] 登录异常: {e}")
            return False

    def set_security(self, level: str = SECURITY_LEVEL) -> bool:
        """设置 DVWA 安全等级。"""
        print(f"[DVWA] 设置安全等级为 {level}...")
        try:
            resp = self.client.get(f"{self.base_url}/security.php")
            token = self._get_token("/security.php")
            resp = self.client.post(
                f"{self.base_url}/security.php",
                data={
                    "security": level,
                    "seclev_submit": "Submit",
                    "user_token": token or "",
                },
            )
            if "Security level set" in resp.text or "security" in resp.text.lower():
                print(f"[DVWA] 安全等级设置成功: {level}")
                return True
            return False
        except Exception as e:
            print(f"[DVWA] 设置安全等级失败: {e}")
            return False

    def init(self) -> bool:
        """完整的 DVWA 初始化流程：setup → login → set security。"""
        # 重试数据库初始化（容器启动时 MySQL 可能未就绪）
        for attempt in range(5):
            if self.setup_database():
                break
            print(f"  重试 {attempt + 1}/5...")
            time.sleep(3)
        else:
            print("[DVWA] 数据库初始化重试耗尽，跳过初始化继续")
        if not self.login():
            return False
        self.set_security(SECURITY_LEVEL)
        return True

    # ----- 漏洞场景操作 -----

    def get_page(self, path: str) -> httpx.Response:
        """GET 某个 DVWA 页面。"""
        return self.client.get(f"{self.base_url}{path}")

    def post_form(self, path: str, data: dict) -> httpx.Response:
        """POST 表单（自动填充 user_token）。"""
        token = self._get_token(path)
        if "user_token" not in data:
            data["user_token"] = token or ""
        return self.client.post(f"{self.base_url}{path}", data=data)

    def close(self):
        self.client.close()


# ================================================================
#  攻击场景定义
# ================================================================

@dataclass
class TestScenario:
    """单个测试场景：良性 vs 攻击性请求。"""
    id: str
    name: str                          # 场景名称（中文）
    category: str                      # 漏洞类别（中文）
    page_path: str                     # DVWA 页面路径
    benign_method: str                 # GET 或 POST
    benign_params: dict                # 正常请求参数（URL 参数或 POST 数据）
    attack_method: str
    attack_params: dict                # 攻击请求参数
    extra_headers: dict = field(default_factory=dict)  # 额外请求头


# 6 个漏洞场景，每个 benign + attack = 12 个测试用例
SCENARIOS = [
    TestScenario(
        id="sqli_get",
        name="SQL 注入 (GET)",
        category="SQL注入",
        page_path="/vulnerabilities/sqli/",
        benign_method="GET",
        benign_params={"id": "1", "Submit": "Submit"},
        attack_method="GET",
        attack_params={"id": "1' OR '1'='1", "Submit": "Submit"},
    ),
    TestScenario(
        id="sqli_blind",
        name="SQL 盲注 (GET)",
        category="SQL注入",
        page_path="/vulnerabilities/sqli_blind/",
        benign_method="GET",
        benign_params={"id": "1", "Submit": "Submit"},
        attack_method="GET",
        attack_params={"id": "1' AND SLEEP(5)#", "Submit": "Submit"},
    ),
    TestScenario(
        id="xss_reflected",
        name="反射型 XSS (GET)",
        category="XSS",
        page_path="/vulnerabilities/xss_r/",
        benign_method="GET",
        benign_params={"name": "John"},
        attack_method="GET",
        attack_params={"name": "<script>alert(1)</script>"},
    ),
    TestScenario(
        id="xss_stored",
        name="存储型 XSS (POST)",
        category="XSS",
        page_path="/vulnerabilities/xss_s/",
        benign_method="POST",
        benign_params={"txtName": "test", "mtxMessage": "hello world"},
        attack_method="POST",
        attack_params={"txtName": "hacker", "mtxMessage": "<script>alert(document.cookie)</script>"},
    ),
    TestScenario(
        id="cmdi",
        name="命令注入 (POST)",
        category="命令注入",
        page_path="/vulnerabilities/exec/",
        benign_method="POST",
        benign_params={"ip": "127.0.0.1", "Submit": "Submit"},
        attack_method="POST",
        attack_params={"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"},
    ),
    TestScenario(
        id="lfi",
        name="文件包含 (GET)",
        category="文件包含",
        page_path="/vulnerabilities/fi/",
        benign_method="GET",
        benign_params={"page": "include.php"},
        attack_method="GET",
        attack_params={"page": "../../../../etc/passwd"},
    ),
]


# ================================================================
#  构造 Raw HTTP 请求（供 LLM 分析）
# ================================================================

def build_raw_http(method: str, path: str, params: dict,
                   host: str = "dvwa:80", extra_headers: dict = None,
                   use_cookie: str = "") -> str:
    """将请求参数构造成标准 raw HTTP 请求文本。"""
    lines = []
    if params and method in ("GET",):
        from urllib.parse import urlencode
        query = urlencode(params)
        path = f"{path}?{query}" if "?" not in path else f"{path}&{query}"
    lines.append(f"{method} {path} HTTP/1.1")
    lines.append(f"Host: {host}")
    if use_cookie:
        lines.append(f"Cookie: {use_cookie}")
    lines.append("User-Agent: LLM-VulnDetector-Benchmark/1.0")
    lines.append("Accept: */*")
    if method == "POST" and params:
        from urllib.parse import urlencode
        body = urlencode(params)
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append(body)
    else:
        lines.append("")
    return "\r\n".join(lines)


# ================================================================
#  评测主逻辑
# ================================================================

@dataclass
class SingleResult:
    """单条测试结果。"""
    scenario_id: str
    scenario_name: str
    category: str
    label: str                # "benign" 或 "attack"
    expected_vuln: bool       # 是否预期有漏洞

    # LLM-VulnDetector
    llm_is_vulnerable: Optional[bool] = None
    llm_risk_level: Optional[str] = None
    llm_max_confidence: Optional[int] = None
    llm_types: list = field(default_factory=list)
    llm_elapsed: Optional[float] = None
    llm_error: Optional[str] = None

    # ModSecurity CRS
    modsec_blocked: Optional[bool] = None   # True=403返回, False=放行
    modsec_status: Optional[int] = None
    modsec_elapsed: Optional[float] = None
    modsec_error: Optional[str] = None

    @property
    def llm_tp(self) -> bool:
        """LLM 正确检出攻击请求。"""
        return self.expected_vuln and (self.llm_is_vulnerable is True)

    @property
    def llm_tn(self) -> bool:
        """LLM 正确判定正常请求。"""
        return (not self.expected_vuln) and (self.llm_is_vulnerable is False)

    @property
    def llm_fp(self) -> bool:
        """LLM 误报（正常请求被判有漏洞）。"""
        return (not self.expected_vuln) and (self.llm_is_vulnerable is True)

    @property
    def llm_fn(self) -> bool:
        """LLM 漏报（攻击请求未检出）。"""
        return self.expected_vuln and (self.llm_is_vulnerable is False)

    @property
    def modsec_correct(self) -> bool:
        """ModSecurity 正确判定。"""
        if self.expected_vuln:
            return self.modsec_blocked is True    # 攻击请求应该被拦截
        else:
            return self.modsec_blocked is False   # 良性请求不应该被拦截

    @property
    def modsec_fp(self) -> bool:
        """ModSecurity 误报（良性请求被拦截）。"""
        return (not self.expected_vuln) and self.modsec_blocked

    @property
    def modsec_fn(self) -> bool:
        """ModSecurity 漏报（攻击请求未被拦截）。"""
        return self.expected_vuln and (self.modsec_blocked is False)


def call_llm_detect(raw_http: str, timeout: int = 90) -> dict:
    """调用 LLM-VulnDetector API。"""
    resp = httpx.post(
        f"{API_URL}/api/detect",
        json={"raw_request": raw_http},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def send_via_modsec(path: str, method: str, params: dict,
                    dvwa_client: "DVWAClient", cookie_str: str = "") -> dict:
    """通过 ModSecurity 代理发送请求，返回拦截状态。"""
    url = f"{MODSEC_URL}{path}"
    headers = {}
    if cookie_str:
        headers["Cookie"] = cookie_str

    try:
        resp = dvwa_client.client.get(url, params=params, headers=headers) if method == "GET" else (
            dvwa_client.client.post(url, data=params, headers=headers)
        )
        return {
            "blocked": resp.status_code in (403, 406, 501),
            "status": resp.status_code,
            "error": None,
        }
    except Exception as e:
        return {"blocked": None, "status": None, "error": str(e)}


def evaluate(cases: list[dict], dvwa_client: "DVWAClient") -> list[SingleResult]:
    """运行所有测试用例，双轨评测。"""
    results: list[SingleResult] = []
    cookie_header = ""
    # 从客户端提取 session cookie（httpx.Cookies 支持 dict 接口）
    for cookie_name, cookie_value in dict(dvwa_client.client.cookies).items():
        if cookie_name.lower() == "phpsessid":
            cookie_header = f"PHPSESSID={cookie_value}; security={SECURITY_LEVEL}"
            break

    for idx, case in enumerate(cases):
        scen = case["scenario"]
        label = case["label"]
        expected = case["expected_vuln"]
        method = case["method"]
        params = case["params"]

        scenario_id = f"{scen.id}_{label}"
        print(f"  [{idx + 1}/{len(cases)}] {scen.name} ({label})...", end=" ", flush=True)

        r = SingleResult(
            scenario_id=scenario_id,
            scenario_name=scen.name,
            category=scen.category,
            label=label,
            expected_vuln=expected,
        )

        # ---- 1) LLM-VulnDetector 检测 ----
        raw_http = build_raw_http(method, scen.page_path, params,
                                  host="dvwa:80", use_cookie=cookie_header)
        start = time.time()
        try:
            result = call_llm_detect(raw_http)
            r.llm_elapsed = round(time.time() - start, 2)
            r.llm_is_vulnerable = result.get("is_vulnerable", False)
            r.llm_risk_level = result.get("risk_level", "info")
            vulns = result.get("vulnerabilities", [])
            r.llm_types = list({v["type"] for v in vulns})
            r.llm_max_confidence = max((v["confidence"] for v in vulns), default=0)
        except Exception as e:
            r.llm_elapsed = round(time.time() - start, 2)
            r.llm_error = str(e)

        # ---- 2) ModSecurity CRS 检测 ----
        start = time.time()
        modsec_result = send_via_modsec(
            scen.page_path, method, params, dvwa_client,
            cookie_str=cookie_header
        )
        r.modsec_elapsed = round(time.time() - start, 2)
        r.modsec_blocked = modsec_result["blocked"]
        r.modsec_status = modsec_result["status"]
        r.modsec_error = modsec_result["error"]

        # 打印
        if r.llm_error:
            print(f"LLM-ERR: {r.llm_error[:30]}  MS={r.modsec_status} ({r.llm_elapsed}s)")
        elif r.expected_vuln:
            status = "LLM-HIT" if r.llm_tp else "LLM-MISS"
            ms_status = "BLOCK" if r.modsec_blocked else "PASS"
            print(f"{status} {r.llm_types[:2]} MS={ms_status} ({r.llm_elapsed}s)")
        else:
            status = "LLM-TN" if r.llm_tn else "LLM-FP!"
            ms_status = "PASS" if not r.modsec_blocked else "BLOCK!"
            print(f"{status} MS={ms_status} ({r.llm_elapsed}s)")

        results.append(r)

    return results


def compute_comparison_metrics(results: list[SingleResult]) -> dict:
    """计算对比指标。"""
    total = len(results)
    attacks = [r for r in results if r.expected_vuln]
    benigns = [r for r in results if not r.expected_vuln]
    errors = [r for r in results if r.llm_error]

    # ---- LLM-VulnDetector ----
    llm_tp = sum(1 for r in attacks if r.llm_tp)
    llm_fn = sum(1 for r in attacks if r.llm_fn)
    llm_tn = sum(1 for r in benigns if r.llm_tn)
    llm_fp = sum(1 for r in benigns if r.llm_fp)

    llm_detection_rate = round(llm_tp / len(attacks) * 100, 1) if attacks else 0
    llm_fpr = round(llm_fp / len(benigns) * 100, 1) if benigns else 0
    llm_accuracy = round((llm_tp + llm_tn) / (total - len(errors)) * 100, 1) if (total - len(errors)) else 0

    llm_confs = [r.llm_max_confidence for r in results if r.llm_tp and r.llm_max_confidence]
    llm_avg_conf = round(sum(llm_confs) / len(llm_confs), 1) if llm_confs else 0

    llm_times = [r.llm_elapsed for r in results if r.llm_elapsed]
    llm_avg_time = round(sum(llm_times) / len(llm_times), 2) if llm_times else 0

    # ---- ModSecurity CRS ----
    modsec_tp = sum(1 for r in attacks if r.modsec_correct)
    modsec_fn = sum(1 for r in attacks if not r.modsec_correct and r.modsec_blocked is not None)
    modsec_tn = sum(1 for r in benigns if r.modsec_correct)
    modsec_fp = sum(1 for r in benigns if r.modsec_fp)

    modsec_detection_rate = round(modsec_tp / len(attacks) * 100, 1) if attacks else 0
    modsec_fpr = round(modsec_fp / len(benigns) * 100, 1) if benigns else 0
    ms_valid = total - sum(1 for r in results if r.modsec_blocked is None)
    modsec_accuracy = round((modsec_tp + modsec_tn) / ms_valid * 100, 1) if ms_valid else 0

    modsec_times = [r.modsec_elapsed for r in results if r.modsec_elapsed]
    modsec_avg_time = round(sum(modsec_times) / len(modsec_times), 3) if modsec_times else 0

    # ---- 各场景明细 ----
    scenario_detail = {}
    for r in results:
        key = r.scenario_name
        if key not in scenario_detail:
            scenario_detail[key] = {
                "category": r.category,
                "benign_llm_tn": False, "benign_llm_fp": False,
                "benign_modsec_tn": False, "benign_modsec_fp": False,
                "attack_llm_tp": False, "attack_llm_fn": False,
                "attack_modsec_blocked": False, "attack_modsec_passed": False,
            }
        d = scenario_detail[key]
        if r.label == "benign":
            if r.llm_tn: d["benign_llm_tn"] = True
            if r.llm_fp: d["benign_llm_fp"] = True
            if not r.modsec_fp: d["benign_modsec_tn"] = True
            if r.modsec_fp: d["benign_modsec_fp"] = True
        else:
            if r.llm_tp: d["attack_llm_tp"] = True
            if r.llm_fn: d["attack_llm_fn"] = True
            if r.modsec_blocked: d["attack_modsec_blocked"] = True
            if (not r.modsec_blocked) and r.modsec_blocked is not None: d["attack_modsec_passed"] = True

    return {
        "total_cases": total,
        "attack_cases": len(attacks),
        "benign_cases": len(benigns),
        "errors": len(errors),
        "llm": {
            "detection_rate": llm_detection_rate,
            "false_positive_rate": llm_fpr,
            "accuracy": llm_accuracy,
            "tp": llm_tp, "fn": llm_fn, "tn": llm_tn, "fp": llm_fp,
            "avg_confidence": llm_avg_conf,
            "avg_time_seconds": llm_avg_time,
        },
        "modsecurity": {
            "detection_rate": modsec_detection_rate,
            "false_positive_rate": modsec_fpr,
            "accuracy": modsec_accuracy,
            "tp": modsec_tp, "fn": modsec_fn, "tn": modsec_tn, "fp": modsec_fp,
            "avg_time_seconds": modsec_avg_time,
        },
        "scenario_detail": scenario_detail,
    }


def print_comparison_report(metrics: dict, results: list[SingleResult]):
    """打印对比评测报告。"""
    llm = metrics["llm"]
    ms = metrics["modsecurity"]
    detail = metrics["scenario_detail"]

    print("\n" + "=" * 72)
    print("  DVWA 靶场端到端对比评测")
    print("  LLM-VulnDetector (上下文增强)  vs  ModSecurity OWASP CRS (工业级 WAF)")
    print("=" * 72)

    print(f"\n  测试配置:")
    print(f"    总用例数:      {metrics['total_cases']} ({metrics['attack_cases']} attacks + "
          f"{metrics['benign_cases']} benign)")
    print(f"    靶场:          DVWA (low security)")
    print(f"    WAF 基线:      ModSecurity + OWASP CRS 3.x (Paranoia Level 1)")
    print(f"    LLM 模型:      DeepSeek-Chat (上下文增强)")
    print(f"    检测失败:      {metrics['errors']}")

    print(f"\n  --- 各场景明细 ---")
    print(f"  {'场景':<22} {'LLM检出':<8} {'LLM误报':<8} {'MS拦截':<8} {'MS误报':<8}")
    print(f"  {'-'*22} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    for name, d in sorted(detail.items()):
        llm_det = "Y" if d["attack_llm_tp"] else "N" if d["attack_llm_fn"] else "?"
        llm_fp = "Y" if d["benign_llm_fp"] else "N"
        ms_block = "Y" if d["attack_modsec_blocked"] else "N" if d["attack_modsec_passed"] else "?"
        ms_fp = "Y" if d["benign_modsec_fp"] else "N"
        print(f"  {name:<22} {llm_det:<8} {llm_fp:<8} {ms_block:<8} {ms_fp:<8}")

    print(f"\n  --- 综合对比 ---")
    print(f"  {'指标':<30} {'LLM-VulnDetector':<18} {'ModSecurity CRS':<18}")
    print(f"  {'-'*30} {'-'*18} {'-'*18}")
    print(f"  {'攻击检出率 (Detection Rate)':<30} {llm['detection_rate']:>5.1f}%"
          f"{'':>10} {ms['detection_rate']:>5.1f}%{'':>10}")
    print(f"  {'良性误报率 (FPR)':<30} {llm['false_positive_rate']:>5.1f}%"
          f"{'':>10} {ms['false_positive_rate']:>5.1f}%{'':>10}")
    print(f"  {'综合准确率 (Accuracy)':<30} {llm['accuracy']:>5.1f}%"
          f"{'':>10} {ms['accuracy']:>5.1f}%{'':>10}")
    print(f"  {'平均响应时间':<30} {llm['avg_time_seconds']:>5.2f}s"
          f"{'':>9} {ms['avg_time_seconds']:>5.3f}s{'':>4}")
    print(f"  {'平均置信度':<30} {llm['avg_confidence']:>5.1f}%"
          f"{'':>10} {'N/A (二元拦截)'}")

    print(f"\n  --- 混淆矩阵 ---")
    print(f"  LLM-VulnDetector:  TP={llm['tp']}  FN={llm['fn']}  FP={llm['fp']}  TN={llm['tn']}")
    print(f"  ModSecurity CRS:   TP={ms['tp']}  FN={ms['fn']}  FP={ms['fp']}  TN={ms['tn']}")

    # 差距分析
    gap = llm['detection_rate'] - ms['detection_rate']
    print(f"\n  --- 差距分析 ---")
    print(f"  LLM vs ModSecurity 检出率差异: {gap:+.1f}%")
    if gap > 0:
        print(f"  LLM-VulnDetector 在攻击检出率上优于 ModSecurity CRS")
    elif gap < 0:
        print(f"  ModSecurity CRS 在攻击检出率上优于 LLM-VulnDetector")
    else:
        print(f"  两者攻击检出率持平")

    # 方法论诚实声明
    print(f"\n  --- 方法论声明 ---")
    print(f"  1. 本评测基于 DVWA (Damn Vulnerable Web Application) 靶场 low 安全等级")
    print(f"  2. 攻击 payload 为常见教科书式案例（非对抗样本）")
    print(f"  3. ModSecurity 运行在 OWASP CRS 3.x 默认 Paranoia Level 1")
    print(f"  4. LLM-VulnDetector 使用上下文增强模式（结构化解析 + 预扫描）")
    print(f"  5. 样本量有限（{metrics['total_cases']}条），结论仅供参考，不代表生产环境表现")

    print("\n" + "=" * 72 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="DVWA 靶场端到端对比评测: LLM-VulnDetector vs ModSecurity CRS"
    )
    parser.add_argument("--output", type=str, default="benchmark_dvwa.json",
                       help="输出报告 JSON 文件名")
    parser.add_argument("--no-dvwa", action="store_true",
                       help="跳过 DVWA 初始化（DVWA 已手动配置过时使用）")
    parser.add_argument("--no-modsec", action="store_true",
                       help="跳过 ModSecurity CRS 对比（ModSecurity 未启动时使用）")
    args = parser.parse_args()

    # ---- 检查 LLM-VulnDetector 后端 ----
    print("检查 LLM-VulnDetector 后端...")
    try:
        health = httpx.get(f"{API_URL}/health", timeout=5)
        health.raise_for_status()
        print(f"  后端在线: {health.json()}")
    except Exception:
        print(f"  错误: 无法连接 {API_URL}，请先启动后端: docker-compose up backend")
        print(f"  或手动: cd backend && uvicorn app.main:app --reload --port 8000")
        sys.exit(1)

    # ---- 初始化 DVWA ----
    dvwa_client = DVWAClient(DVWA_URL)
    if not args.no_dvwa:
        print(f"\n初始化 DVWA靶场 ({DVWA_URL})...")
        if not dvwa_client.init():
            print("  警告: DVWA 初始化失败，请检查 docker-compose up dvwa")
            if args.no_modsec:
                dvwa_client.close()
                sys.exit(1)

    # ---- 构建测试用例 ----
    cases = []
    for scen in SCENARIOS:
        # 良性请求
        cases.append({
            "scenario": scen,
            "label": "benign",
            "expected_vuln": False,
            "method": scen.benign_method,
            "params": scen.benign_params,
        })
        # 攻击请求
        cases.append({
            "scenario": scen,
            "label": "attack",
            "expected_vuln": True,
            "method": scen.attack_method,
            "params": scen.attack_params,
        })

    print(f"\n开始评测: {len(cases)} 条测试用例...\n")
    results = evaluate(cases, dvwa_client)
    dvwa_client.close()

    # ---- 汇总指标 ----
    metrics = compute_comparison_metrics(results)
    print_comparison_report(metrics, results)

    # ---- 保存报告 ----
    REPORT_DIR.mkdir(exist_ok=True)
    report = {
        "title": "DVWA 靶场端到端对比评测",
        "subtitle": "LLM-VulnDetector (上下文增强) vs ModSecurity OWASP CRS",
        "config": {
            "dvwa_url": DVWA_URL,
            "modsec_url": MODSEC_URL,
            "api_url": API_URL,
            "security_level": SECURITY_LEVEL,
        },
        "metrics": metrics,
        "results": [
            {
                "scenario_id": r.scenario_id,
                "scenario_name": r.scenario_name,
                "category": r.category,
                "label": r.label,
                "expected_vuln": r.expected_vuln,
                "llm_is_vulnerable": r.llm_is_vulnerable,
                "llm_risk_level": r.llm_risk_level,
                "llm_max_confidence": r.llm_max_confidence,
                "llm_types": r.llm_types,
                "llm_elapsed": r.llm_elapsed,
                "llm_error": r.llm_error,
                "modsec_blocked": r.modsec_blocked,
                "modsec_status": r.modsec_status,
                "modsec_elapsed": r.modsec_elapsed,
                "modsec_error": r.modsec_error,
                "llm_tp": r.llm_tp,
                "llm_fp": r.llm_fp,
                "llm_fn": r.llm_fn,
                "llm_tn": r.llm_tn,
                "modsec_correct": r.modsec_correct,
            }
            for r in results
        ],
    }
    out_path = REPORT_DIR / args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"报告已保存: {out_path}")


if __name__ == "__main__":
    main()
