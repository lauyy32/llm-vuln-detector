#!/usr/bin/env python
"""
============================================================================
  DVWA 靶场端到端对比评测（多难度 + 多 WAF 级别）
  LLM-VulnDetector vs ModSecurity OWASP CRS (工业级 WAF 基线)

  测试矩阵：
    - DVWA 安全等级: low / medium / high（3 档）
    - ModSecurity Paranoia Level: PL1 / PL2 / PL3（3 档）
    - 漏洞场景: 6 个（SQLi / Blind SQLi / XSS-R / XSS-S / CMDi / LFI）
    - 每个场景: benign + attack = 2 条

  总计: 3 × 6 × 2 = 36 条 LLM 检测 + 每条的 3 PL ModSecurity = 108 次 WAF 检测
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

# 三档 DVWA 安全等级
DVWA_SECURITY_LEVELS = ["low", "medium", "high"]

# 三档 ModSecurity Paranoia Level（各跑独立容器）
MODSEC_ENDPOINTS = {
    "PL1": os.environ.get("MODSEC_PL1_URL", "http://localhost:8081"),
    "PL2": os.environ.get("MODSEC_PL2_URL", "http://localhost:8082"),
    "PL3": os.environ.get("MODSEC_PL3_URL", "http://localhost:8083"),
}

DVWA_USER = "admin"
DVWA_PASS = "password"

REPORT_DIR = Path(__file__).parent / "reports"


# ================================================================
#  DVWA 自动化（支持多安全等级切换）
# ================================================================

class DVWAClient:
    """DVWA 自动化客户端：登录、设置安全等级、操作漏洞页面。"""

    def __init__(self, base_url: str = DVWA_URL, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout, follow_redirects=False)
        self.logged_in = False
        self.current_security = None

    def _get_token(self, page_path: str) -> str:
        try:
            resp = self.client.get(f"{self.base_url}{page_path}")
            m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", resp.text)
            if m:
                return m.group(1)
        except Exception:
            pass
        return ""

    def setup_database(self) -> bool:
        """初始化 DVWA 数据库。"""
        print("[DVWA] 初始化数据库...")
        try:
            resp = self.client.get(f"{self.base_url}/setup.php")
            token = self._get_token("/setup.php")
            resp = self.client.post(
                f"{self.base_url}/setup.php",
                data={"create_db": "Create / Reset Database", "user_token": token},
            )
            ok = "Database has been created" in resp.text or "Setup successful" in resp.text
            if ok:
                print("[DVWA] 数据库初始化成功")
                return True
            if "already exists" in resp.text.lower():
                print("[DVWA] 数据库已存在，跳过")
                return True
            print(f"[DVWA] 数据库初始化状态异常, status={resp.status_code}")
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
            self.client.headers.update({"User-Agent": "LLM-VulnDetector-Benchmark/2.0"})
            resp = self.client.post(
                f"{self.base_url}/login.php",
                data={
                    "username": DVWA_USER, "password": DVWA_PASS,
                    "Login": "Login", "user_token": token or "",
                },
            )
            if "Welcome" in resp.text or "Logout" in resp.text:
                self.logged_in = True
                print("[DVWA] 登录成功")
                return True
            print(f"[DVWA] 登录失败, status={resp.status_code}")
            return False
        except Exception as e:
            print(f"[DVWA] 登录异常: {e}")
            return False

    def set_security(self, level: str) -> bool:
        """设置 DVWA 安全等级。"""
        if self.current_security == level:
            return True
        print(f"[DVWA] 设置安全等级 -> {level}")
        try:
            resp = self.client.get(f"{self.base_url}/security.php")
            token = self._get_token("/security.php")
            resp = self.client.post(
                f"{self.base_url}/security.php",
                data={
                    "security": level, "seclev_submit": "Submit",
                    "user_token": token or "",
                },
            )
            if "Security level set" in resp.text or "security" in resp.text.lower():
                self.current_security = level
                print(f"[DVWA] 安全等级 {level} 设置成功")
                return True
            # 有些版本返回不带 "set" 字样，只要状态正常就算成功
            if resp.status_code < 400:
                self.current_security = level
                return True
            return False
        except Exception as e:
            print(f"[DVWA] 设置安全等级失败: {e}")
            return False

    def init(self, security: str = "low") -> bool:
        """完整的 DVWA 初始化：setup → login → set security。"""
        for attempt in range(5):
            if self.setup_database():
                break
            print(f"  数据库初始化重试 {attempt + 1}/5...")
            time.sleep(3)
        if not self.login():
            return False
        self.set_security(security)
        return True

    def close(self):
        self.client.close()


# ================================================================
#  攻击场景定义
# ================================================================

@dataclass
class TestScenario:
    id: str
    name: str
    category: str
    page_path: str
    benign_method: str
    benign_params: dict
    attack_method: str
    attack_params: dict


SCENARIOS = [
    TestScenario(
        id="sqli_get", name="SQL 注入 (GET)", category="SQL注入",
        page_path="/vulnerabilities/sqli/",
        benign_method="GET", benign_params={"id": "1", "Submit": "Submit"},
        attack_method="GET", attack_params={"id": "1' OR '1'='1", "Submit": "Submit"},
    ),
    TestScenario(
        id="sqli_blind", name="SQL 盲注 (GET)", category="SQL注入",
        page_path="/vulnerabilities/sqli_blind/",
        benign_method="GET", benign_params={"id": "1", "Submit": "Submit"},
        attack_method="GET", attack_params={"id": "1' AND SLEEP(5)#", "Submit": "Submit"},
    ),
    TestScenario(
        id="xss_reflected", name="反射型 XSS (GET)", category="XSS",
        page_path="/vulnerabilities/xss_r/",
        benign_method="GET", benign_params={"name": "John"},
        attack_method="GET", attack_params={"name": "<script>alert(1)</script>"},
    ),
    TestScenario(
        id="xss_stored", name="存储型 XSS (POST)", category="XSS",
        page_path="/vulnerabilities/xss_s/",
        benign_method="POST", benign_params={"txtName": "test", "mtxMessage": "hello world"},
        attack_method="POST", attack_params={"txtName": "hacker", "mtxMessage": "<script>alert(document.cookie)</script>"},
    ),
    TestScenario(
        id="cmdi", name="命令注入 (POST)", category="命令注入",
        page_path="/vulnerabilities/exec/",
        benign_method="POST", benign_params={"ip": "127.0.0.1", "Submit": "Submit"},
        attack_method="POST", attack_params={"ip": "127.0.0.1; cat /etc/passwd", "Submit": "Submit"},
    ),
    TestScenario(
        id="lfi", name="文件包含 (GET)", category="文件包含",
        page_path="/vulnerabilities/fi/",
        benign_method="GET", benign_params={"page": "include.php"},
        attack_method="GET", attack_params={"page": "../../../../etc/passwd"},
    ),
]


# ================================================================
#  构造 Raw HTTP 请求
# ================================================================

def build_raw_http(method: str, path: str, params: dict,
                   host: str = "dvwa:80", use_cookie: str = "") -> str:
    """将请求参数构造成标准 raw HTTP 请求文本。"""
    from urllib.parse import urlencode
    lines = []
    final_path = path
    if method == "GET" and params:
        query = urlencode(params)
        final_path = f"{path}?{query}"
    lines.append(f"{method} {final_path} HTTP/1.1")
    lines.append(f"Host: {host}")
    if use_cookie:
        lines.append(f"Cookie: {use_cookie}")
    lines.append("User-Agent: LLM-VulnDetector-Benchmark/2.0")
    lines.append("Accept: */*")
    if method == "POST" and params:
        body = urlencode(params)
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body)}")
        lines.append("")
        lines.append(body)
    else:
        lines.append("")
    return "\r\n".join(lines)


# ================================================================
#  评测结果与判定逻辑
# ================================================================

@dataclass
class SingleResult:
    """单条测试结果（含 DVWA 难度 + 三档 ModSecurity PL 结果）。"""
    scenario_id: str
    scenario_name: str
    category: str
    label: str            # "benign" 或 "attack"
    dvwa_level: str       # "low" / "medium" / "high"
    expected_vuln: bool

    # --- LLM-VulnDetector ---
    llm_is_vulnerable: Optional[bool] = None
    llm_risk_level: Optional[str] = None
    llm_max_confidence: Optional[int] = None
    llm_types: list = field(default_factory=list)
    llm_elapsed: Optional[float] = None
    llm_error: Optional[str] = None

    # --- ModSecurity (per Paranoia Level) ---
    modsec_pl1_blocked: Optional[bool] = None
    modsec_pl1_status: Optional[int] = None
    modsec_pl1_elapsed: Optional[float] = None
    modsec_pl1_error: Optional[str] = None

    modsec_pl2_blocked: Optional[bool] = None
    modsec_pl2_status: Optional[int] = None
    modsec_pl2_elapsed: Optional[float] = None
    modsec_pl2_error: Optional[str] = None

    modsec_pl3_blocked: Optional[bool] = None
    modsec_pl3_status: Optional[int] = None
    modsec_pl3_elapsed: Optional[float] = None
    modsec_pl3_error: Optional[str] = None

    # ---- LLM 判定 ----
    @property
    def llm_tp(self) -> bool:
        return self.expected_vuln and (self.llm_is_vulnerable is True)

    @property
    def llm_tn(self) -> bool:
        return (not self.expected_vuln) and (self.llm_is_vulnerable is False)

    @property
    def llm_fp(self) -> bool:
        return (not self.expected_vuln) and (self.llm_is_vulnerable is True)

    @property
    def llm_fn(self) -> bool:
        return self.expected_vuln and (self.llm_is_vulnerable is False)

    # ---- ModSecurity 判定（通用） ----
    def modsec_correct(self, blocked: Optional[bool]) -> bool:
        if self.expected_vuln:
            return blocked is True
        else:
            return blocked is False


# ================================================================
#  API 调用
# ================================================================

def call_llm_detect(raw_http: str, timeout: int = 90) -> dict:
    resp = httpx.post(
        f"{API_URL}/api/detect",
        json={"raw_request": raw_http},
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def send_via_modsec(modsec_url: str, path: str, method: str,
                    params: dict, cookie_str: str = "",
                    timeout: int = 15) -> dict:
    """通过指定 ModSecurity 代理发送请求，返回拦截状态。"""
    url = f"{modsec_url}{path}"
    headers = {}
    if cookie_str:
        headers["Cookie"] = cookie_str
    try:
        client = httpx.Client(timeout=timeout, follow_redirects=False)
        if method == "GET":
            resp = client.get(url, params=params, headers=headers)
        else:
            resp = client.post(url, data=params, headers=headers)
        client.close()
        return {
            "blocked": resp.status_code in (403, 406, 501),
            "status": resp.status_code,
            "error": None,
        }
    except Exception as e:
        return {"blocked": None, "status": None, "error": str(e)}


# ================================================================
#  主评测流程
# ================================================================

def run_benchmark(dvwa_client: "DVWAClient",
                  active_modsec_pls: list = None) -> list[SingleResult]:
    """
    遍历 3 档 DVWA 安全等级 + 3 档 ModSecurity PL 进行评测。
    返回所有 SingleResult。
    """
    if active_modsec_pls is None:
        active_modsec_pls = list(MODSEC_ENDPOINTS.keys())

    results: list[SingleResult] = []
    all_cases = []  # (scenario, label, expected_vuln, method, params)
    for scen in SCENARIOS:
        all_cases.append((scen, "benign", False, scen.benign_method, scen.benign_params))
        all_cases.append((scen, "attack", True, scen.attack_method, scen.attack_params))

    total_cases = len(DVWA_SECURITY_LEVELS) * len(all_cases)
    case_idx = 0

    for security in DVWA_SECURITY_LEVELS:
        print(f"\n{'='*60}")
        print(f"  DVWA 安全等级: {security.upper()}")
        print(f"{'='*60}")

        # 切换安全等级
        dvwa_client.set_security(security)
        time.sleep(0.5)

        # 提取当前等级的 session cookie
        cookie_header = ""
        for cookie_name, cookie_value in dict(dvwa_client.client.cookies).items():
            if cookie_name.lower() == "phpsessid":
                cookie_header = f"PHPSESSID={cookie_value}; security={security}"
                break

        for scen, label, expected, method, params in all_cases:
            case_idx += 1
            scenario_id = f"{scen.id}_{security}_{label}"
            prefix = f"  [{case_idx}/{total_cases}] {security:6s} | {scen.name:22s} ({label:6s})"

            r = SingleResult(
                scenario_id=scenario_id,
                scenario_name=scen.name,
                category=scen.category,
                label=label,
                dvwa_level=security,
                expected_vuln=expected,
            )

            # ---- Step 1: LLM-VulnDetector ----
            raw_http = build_raw_http(method, scen.page_path, params,
                                      host="dvwa:80", use_cookie=cookie_header)
            start = time.time()
            try:
                api_result = call_llm_detect(raw_http)
                r.llm_elapsed = round(time.time() - start, 2)
                r.llm_is_vulnerable = api_result.get("is_vulnerable", False)
                r.llm_risk_level = api_result.get("risk_level", "info")
                vulns = api_result.get("vulnerabilities", [])
                r.llm_types = list({v["type"] for v in vulns})
                r.llm_max_confidence = max((v["confidence"] for v in vulns), default=0)
            except Exception as e:
                r.llm_elapsed = round(time.time() - start, 2)
                r.llm_error = str(e)

            # ---- Step 2: ModSecurity (all active PL levels) ----
            for pl in active_modsec_pls:
                ms_url = MODSEC_ENDPOINTS[pl]
                start = time.time()
                ms_result = send_via_modsec(ms_url, scen.page_path, method,
                                            params, cookie_str=cookie_header)
                elapsed = round(time.time() - start, 2)

                if pl == "PL1":
                    r.modsec_pl1_blocked = ms_result["blocked"]
                    r.modsec_pl1_status = ms_result["status"]
                    r.modsec_pl1_elapsed = elapsed
                    r.modsec_pl1_error = ms_result["error"]
                elif pl == "PL2":
                    r.modsec_pl2_blocked = ms_result["blocked"]
                    r.modsec_pl2_status = ms_result["status"]
                    r.modsec_pl2_elapsed = elapsed
                    r.modsec_pl2_error = ms_result["error"]
                elif pl == "PL3":
                    r.modsec_pl3_blocked = ms_result["blocked"]
                    r.modsec_pl3_status = ms_result["status"]
                    r.modsec_pl3_elapsed = elapsed
                    r.modsec_pl3_error = ms_result["error"]

            # 单条结果摘要
            llm_tag = "LLM-HIT" if r.llm_tp else ("LLM-MISS" if r.llm_fn else "LLM-TN" if r.llm_tn else "LLM-FP!")
            if r.llm_error:
                llm_tag = "LLM-ERR"

            ms_summary = []
            for pl in active_modsec_pls:
                blocked = getattr(r, f"modsec_{pl.lower()}_blocked")
                if r.expected_vuln:
                    ms_summary.append(f"{'BLOCK' if blocked else 'PASS'}")
                else:
                    ms_summary.append(f"{'PASS' if not blocked else 'FP!'}")
            ms_tag = " | ".join(f"{pl}={s}" for pl, s in zip(active_modsec_pls, ms_summary))

            print(f"{prefix} {llm_tag}  MS[{ms_tag}]  ({r.llm_elapsed or '?'}s)")

            results.append(r)

    return results


# ================================================================
#  指标计算（含多维度拆分）
# ================================================================

def compute_metrics(results: list[SingleResult],
                    active_pls: list = None) -> dict:
    """计算多维度对比指标。"""
    if active_pls is None:
        active_pls = ["PL1", "PL2", "PL3"]

    total = len(results)
    errors = [r for r in results if r.llm_error]

    # ---- 按 DVWA 安全等级拆分 ----
    by_level = {}
    for security in DVWA_SECURITY_LEVELS:
        subset = [r for r in results if r.dvwa_level == security]
        attacks = [r for r in subset if r.expected_vuln]
        benigns = [r for r in subset if not r.expected_vuln]

        llm_tp = sum(1 for r in attacks if r.llm_tp)
        llm_fn = sum(1 for r in attacks if r.llm_fn)
        llm_tn = sum(1 for r in benigns if r.llm_tn)
        llm_fp = sum(1 for r in benigns if r.llm_fp)

        by_level[security] = {
            "total": len(subset),
            "attacks": len(attacks),
            "benigns": len(benigns),
            "llm": {
                "detection_rate": round(llm_tp / len(attacks) * 100, 1) if attacks else 0,
                "fpr": round(llm_fp / len(benigns) * 100, 1) if benigns else 0,
                "tp": llm_tp, "fn": llm_fn, "tn": llm_tn, "fp": llm_fp,
            },
        }
        # ModSecurity per PL within this security level
        for pl in active_pls:
            blocked_key = f"modsec_{pl.lower()}_blocked"
            ms_tp = sum(1 for r in attacks
                       if getattr(r, blocked_key) is True)
            ms_fn = sum(1 for r in attacks
                       if getattr(r, blocked_key) is False)
            ms_tn = sum(1 for r in benigns
                       if getattr(r, blocked_key) is False)
            ms_fp = sum(1 for r in benigns
                       if getattr(r, blocked_key) is True)
            by_level[security][f"modsec_{pl.lower()}"] = {
                "detection_rate": round(ms_tp / len(attacks) * 100, 1) if attacks else 0,
                "fpr": round(ms_fp / len(benigns) * 100, 1) if benigns else 0,
                "tp": ms_tp, "fn": ms_fn, "tn": ms_tn, "fp": ms_fp,
            }

    # ---- 综合指标 ----
    attacks = [r for r in results if r.expected_vuln]
    benigns = [r for r in results if not r.expected_vuln]
    valid_total = total - len(errors)

    llm_tp = sum(1 for r in attacks if r.llm_tp)
    llm_fn = sum(1 for r in attacks if r.llm_fn)
    llm_tn = sum(1 for r in benigns if r.llm_tn)
    llm_fp = sum(1 for r in benigns if r.llm_fp)
    llm_confs = [r.llm_max_confidence for r in results if r.llm_tp and r.llm_max_confidence]
    llm_times = [r.llm_elapsed for r in results if r.llm_elapsed]

    overall = {
        "total_cases": total,
        "attack_cases": len(attacks),
        "benign_cases": len(benigns),
        "errors": len(errors),
        "llm": {
            "detection_rate": round(llm_tp / len(attacks) * 100, 1) if attacks else 0,
            "fpr": round(llm_fp / len(benigns) * 100, 1) if benigns else 0,
            "accuracy": round((llm_tp + llm_tn) / valid_total * 100, 1) if valid_total else 0,
            "tp": llm_tp, "fn": llm_fn, "tn": llm_tn, "fp": llm_fp,
            "avg_confidence": round(sum(llm_confs) / len(llm_confs), 1) if llm_confs else 0,
            "avg_time_s": round(sum(llm_times) / len(llm_times), 2) if llm_times else 0,
        },
    }

    for pl in active_pls:
        blocked_key = f"modsec_{pl.lower()}_blocked"
        ms_tp = sum(1 for r in attacks if getattr(r, blocked_key) is True)
        ms_fn = sum(1 for r in attacks if getattr(r, blocked_key) is False)
        ms_tn = sum(1 for r in benigns if getattr(r, blocked_key) is False)
        ms_fp = sum(1 for r in benigns if getattr(r, blocked_key) is True)
        ms_valid = total - sum(1 for r in results if getattr(r, blocked_key) is None)

        elapsed_key = f"modsec_{pl.lower()}_elapsed"
        ms_times = [getattr(r, elapsed_key) for r in results if getattr(r, elapsed_key)]

        overall[f"modsec_{pl.lower()}"] = {
            "detection_rate": round(ms_tp / len(attacks) * 100, 1) if attacks else 0,
            "fpr": round(ms_fp / len(benigns) * 100, 1) if benigns else 0,
            "accuracy": round((ms_tp + ms_tn) / ms_valid * 100, 1) if ms_valid else 0,
            "tp": ms_tp, "fn": ms_fn, "tn": ms_tn, "fp": ms_fp,
            "avg_time_s": round(sum(ms_times) / len(ms_times), 3) if ms_times else 0,
        }

    return {
        "overall": overall,
        "by_dvwa_level": by_level,
    }


def print_report(metrics: dict, results: list[SingleResult], active_pls: list):
    """打印对比评测报告。"""
    ov = metrics["overall"]
    llm = ov["llm"]

    print("\n" + "=" * 78)
    print("  DVWA 靶场端到端对比评测（多难度 + 多 WAF 级别）")
    print("  LLM-VulnDetector (上下文增强)  vs  ModSecurity OWASP CRS (PL1/PL2/PL3)")
    print("=" * 78)

    print(f"\n  测试矩阵:")
    print(f"    DVWA 难度:     low / medium / high（3 档）")
    print(f"    漏洞场景:      6 个（SQLi / Blind SQLi / XSS-R / XSS-S / CMDi / LFI）")
    print(f"    请求类型:      benign + attack（每场景 2 条）")
    print(f"    总用例数:      {ov['total_cases']} ({ov['attack_cases']} attacks + {ov['benign_cases']} benign)")
    print(f"    ModSecurity:   {', '.join(active_pls)}（3 档 Paranoia Level）")
    print(f"    LLM 模型:      DeepSeek-Chat（上下文增强）")
    print(f"    检测失败:      {ov['errors']}")

    # ---- 按 DVWA 难度拆分 ----
    print(f"\n  --- 按 DVWA 难度拆分 ---")
    header = f"  {'DVWA':<8}"
    for pl in active_pls:
        header += f" {'LLM检出':>8} {'LLM误报':>7}"
        header += f" {'MS-'+pl:>7} {'MS-'+pl+'误':>7}"
    print(header)
    print(f"  {'-'*8}{' ' + '-'*(len(active_pls)*31)}")

    for security in DVWA_SECURITY_LEVELS:
        d = metrics["by_dvwa_level"][security]
        line = f"  {security:<8}"
        line += f" {d['llm']['detection_rate']:>4.1f}%{'':>3}  {d['llm']['fpr']:>4.1f}%{'':>2}"
        for pl in active_pls:
            ms = d[f"modsec_{pl.lower()}"]
            line += f" {ms['detection_rate']:>4.1f}%{'':>2} {ms['fpr']:>4.1f}%{'':>2}"
        print(line)

    # ---- 综合对比 ----
    print(f"\n  --- 综合对比（36 条总样本）---")
    print(f"  {'指标':<30} {'LLM':>8}", end="")
    for pl in active_pls:
        print(f"  {'MS-'+pl:>8}", end="")
    print()
    print(f"  {'-'*30} {'-'*8}" + f" {'-'*8}" * len(active_pls))

    print(f"  {'攻击检出率':<30} {llm['detection_rate']:>5.1f}%", end="")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        print(f"  {ms['detection_rate']:>5.1f}%", end="")
    print()

    print(f"  {'良性误报率':<30} {llm['fpr']:>5.1f}%", end="")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        print(f"  {ms['fpr']:>5.1f}%", end="")
    print()

    print(f"  {'综合准确率':<30} {llm['accuracy']:>5.1f}%", end="")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        print(f"  {ms['accuracy']:>5.1f}%", end="")
    print()

    print(f"  {'平均响应时间':<30} {llm['avg_time_s']:>5.2f}s", end="")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        print(f"  {ms['avg_time_s']:>5.3f}s", end="")
    print()

    print(f"  {'平均置信度':<30} {llm['avg_confidence']:>5.1f}%", end="")
    print("  " + "  ".join(["N/A    " for _ in active_pls]))

    # ---- 混淆矩阵 ----
    print(f"\n  --- 混淆矩阵 ---")
    print(f"  LLM-VulnDetector:   TP={llm['tp']}  FN={llm['fn']}  FP={llm['fp']}  TN={llm['tn']}")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        print(f"  ModSecurity {pl}:   TP={ms['tp']}  FN={ms['fn']}  FP={ms['fp']}  TN={ms['tn']}")

    # ---- 差距分析 ----
    print(f"\n  --- 差距分析（LLM vs ModSecurity）---")
    for pl in active_pls:
        ms = ov[f"modsec_{pl.lower()}"]
        gap = llm['detection_rate'] - ms['detection_rate']
        fpr_gap = llm['fpr'] - ms['fpr']
        print(f"  {pl}: 检出率差距 {gap:+.1f}%  |  误报率差距 {fpr_gap:+.1f}%")

    # ---- 漏报/误报明细 ----
    llm_missed = [r for r in results if r.llm_fn]
    llm_fped = [r for r in results if r.llm_fp]
    if llm_missed:
        print(f"\n  --- LLM 漏报明细 ({len(llm_missed)} 条) ---")
        for r in llm_missed:
            print(f"    [{r.dvwa_level}] {r.scenario_name}: 未检出攻击 payload")
    if llm_fped:
        print(f"\n  --- LLM 误报明细 ({len(llm_fped)} 条) ---")
        for r in llm_fped:
            print(f"    [{r.dvwa_level}] {r.scenario_name}: 正常请求被判为攻击")

    for pl in active_pls:
        blocked_key = f"modsec_{pl.lower()}_blocked"
        ms_missed = [r for r in results if r.expected_vuln and getattr(r, blocked_key) is False]
        ms_fped = [r for r in results if (not r.expected_vuln) and getattr(r, blocked_key) is True]
        if ms_missed:
            print(f"\n  --- ModSecurity {pl} 漏报明细 ({len(ms_missed)} 条) ---")
            for r in ms_missed:
                print(f"    [{r.dvwa_level}] {r.scenario_name}: 攻击未被拦截")
        if ms_fped:
            print(f"\n  --- ModSecurity {pl} 误报明细 ({len(ms_fped)} 条) ---")
            for r in ms_fped:
                print(f"    [{r.dvwa_level}] {r.scenario_name}: 正常请求被拦截")

    # ---- 方法论声明 ----
    print(f"\n  --- 方法论声明 ---")
    print(f"  1. DVWA 覆盖 low/medium/high 三档难度，部分攻击在 medium/high 可能被防护")
    print(f"  2. ModSecurity 覆盖 PL1/PL2/PL3 三档 Paranoia Level")
    print(f"  3. 攻击 payload 基于 DVWA 靶场教科书案例（非对抗样本）")
    print(f"  4. LLM-VulnDetector 使用上下文增强模式（结构化解析 + 预扫描）")
    print(f"  5. 样本量 {ov['total_cases']} 条，结论仅供参考，不代表生产环境表现")

    print("\n" + "=" * 78 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="DVWA 靶场端到端对比评测（多难度 + 多 WAF 级别）"
    )
    parser.add_argument("--output", type=str, default="benchmark_dvwa.json",
                       help="输出报告 JSON 文件名")
    parser.add_argument("--no-dvwa", action="store_true",
                       help="跳过 DVWA 初始化")
    parser.add_argument("--no-modsec", action="store_true",
                       help="跳过 ModSecurity CRS 对比")
    parser.add_argument("--modsec-pls", type=str, default="PL1,PL2,PL3",
                       help="要测试的 ModSecurity PL 级别，逗号分隔（如: PL1,PL2）")
    args = parser.parse_args()

    active_pls = [p.strip() for p in args.modsec_pls.split(",") if p.strip() in MODSEC_ENDPOINTS]
    if not active_pls:
        print("错误: 没有有效的 ModSecurity PL 级别")
        sys.exit(1)

    # ---- 检查后端 ----
    print("检查 LLM-VulnDetector 后端...")
    try:
        health = httpx.get(f"{API_URL}/health", timeout=5)
        health.raise_for_status()
        print(f"  后端在线: {health.json()}")
    except Exception:
        print(f"  无法连接 {API_URL}，请先启动后端")
        sys.exit(1)

    # ---- 检查 ModSecurity 容器 ----
    if not args.no_modsec:
        for pl in active_pls:
            ms_url = MODSEC_ENDPOINTS[pl]
            try:
                httpx.get(ms_url, timeout=3)
                print(f"  ModSecurity {pl} ({ms_url}) 在线")
            except Exception:
                print(f"  警告: ModSecurity {pl} ({ms_url}) 不可达，将跳过该级别")
                active_pls.remove(pl)
        if not active_pls:
            print("  所有 ModSecurity 端点不可达，将以 --no-modsec 模式运行")
            args.no_modsec = True

    # ---- 初始化 DVWA ----
    dvwa_client = DVWAClient(DVWA_URL)
    if not args.no_dvwa:
        print(f"\n初始化 DVWA 靶场 ({DVWA_URL})...")
        if not dvwa_client.init(security="low"):
            print("  警告: DVWA 初始化失败")
            if args.no_modsec:
                dvwa_client.close()
                sys.exit(1)

    # ---- 运行评测 ----
    print(f"\n开始评测: {len(DVWA_SECURITY_LEVELS)} 难度 x {len(SCENARIOS)} 场景 x 2 类型")
    print(f"         = {len(DVWA_SECURITY_LEVELS) * len(SCENARIOS) * 2} 条 LLM 检测")
    if not args.no_modsec:
        print(f"         x {len(active_pls)} ModSecurity PL = {len(DVWA_SECURITY_LEVELS) * len(SCENARIOS) * 2 * len(active_pls)} 次 WAF 检测\n")

    results = run_benchmark(dvwa_client, active_pls if not args.no_modsec else [])
    dvwa_client.close()

    # ---- 汇总 ----
    metrics = compute_metrics(results, active_pls if not args.no_modsec else [])
    print_report(metrics, results, active_pls)

    # ---- 保存 JSON ----
    REPORT_DIR.mkdir(exist_ok=True)

    serialized = []
    for r in results:
        d = {
            "scenario_id": r.scenario_id,
            "scenario_name": r.scenario_name,
            "category": r.category,
            "label": r.label,
            "dvwa_level": r.dvwa_level,
            "expected_vuln": r.expected_vuln,
            "llm_is_vulnerable": r.llm_is_vulnerable,
            "llm_risk_level": r.llm_risk_level,
            "llm_max_confidence": r.llm_max_confidence,
            "llm_types": r.llm_types,
            "llm_elapsed": r.llm_elapsed,
            "llm_error": r.llm_error,
            "llm_tp": r.llm_tp, "llm_fp": r.llm_fp, "llm_fn": r.llm_fn, "llm_tn": r.llm_tn,
        }
        for pl in active_pls:
            d[f"modsec_{pl.lower()}_blocked"] = getattr(r, f"modsec_{pl.lower()}_blocked")
            d[f"modsec_{pl.lower()}_status"] = getattr(r, f"modsec_{pl.lower()}_status")
            d[f"modsec_{pl.lower()}_elapsed"] = getattr(r, f"modsec_{pl.lower()}_elapsed")
        serialized.append(d)

    report = {
        "title": "DVWA 靶场端到端对比评测（多难度 + 多 WAF 级别）",
        "subtitle": "LLM-VulnDetector (上下文增强) vs ModSecurity OWASP CRS (PL1/PL2/PL3)",
        "config": {
            "dvwa_url": DVWA_URL,
            "modsec_endpoints": {pl: MODSEC_ENDPOINTS[pl] for pl in active_pls},
            "api_url": API_URL,
            "dvwa_security_levels": DVWA_SECURITY_LEVELS,
            "active_modsec_pls": active_pls,
            "total_cases": len(results),
        },
        "metrics": metrics,
        "results": serialized,
    }
    out_path = REPORT_DIR / args.output
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"报告已保存: {out_path}")


if __name__ == "__main__":
    main()
