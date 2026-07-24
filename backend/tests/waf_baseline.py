#!/usr/bin/env python
"""
============================================================================
  轻量规则 WAF 基线（模拟 OWASP CRS 的 PL1 / PL2 / PL3 严格度）

  ⚠️ 重要声明：
  - 这是「自建规则引擎」，用于沙箱无 Docker 环境下替代真实 ModSecurity CRS 容器。
  - 规则为简化版，不代表真实 CRS 的检测精度，仅用于演示「规则 WAF 随 Paranoia
    Level 上升而更激进」的行为特征，以及「LLM 语义检测 vs 规则签名」的方法差异。
  - 待用户在具备 Docker 的环境运行 docker-compose 后，可用真实 ModSecurity CRS
    复现本书的端到端对比（benchmark_dvwa.py 原生支持）。

  PL 严格度递增（高 PL 继承低 PL 的全部规则）：
    PL1 — 只拦最明显的签名（教科书攻击）
    PL2 — PL1 + 大小写/注释/编码变形
    PL3 — PL1+PL2 + 最宽泛启发式（可能更高误报，但本靶场 benign 干净故仍低）
============================================================================
"""
import re
from typing import Optional
from urllib.parse import unquote_plus

# 每档 PL 的规则集：(category, compiled_regex)
# 注意：高 PL 在 __init__ 中会累积继承低 PL 的全部规则（严格度递增）
_RAW_RULES = {
    "PL1": [
        ("sqli", r"(?i)('|\")\s*(or|and)\s+('|\"|\d)"),        # ' OR '1'='1
        ("sqli", r"(?i)union\s+select"),
        ("sqli", r"(?i)\bor\s+\d+\s*=\s*\d+"),                # OR 1=1
        ("sqli", r"(?i)sleep\s*\("),
        ("sqli", r"(?i)information_schema"),
        ("xss", r"(?i)<script"),
        ("xss", r"(?i)(onerror|onload|onmouseover)\s*="),
        ("xss", r"(?i)javascript:"),
        ("xss", r"(?i)alert\s*\("),
        ("cmdi", r"(?i)[;|]\s*(cat|ls|id|whoami|pwd)"),
        ("cmdi", r"(?i)&&|\|\|"),
        ("lfi", r"/etc/passwd"),
        ("lfi", r"(\.\./|\.\\){2,}"),                          # ../../ 或 ..\
        ("lfi", r"(?i)(php|file|expect|data)://"),
    ],
    "PL2": [
        # 变形 / 绕过
        ("sqli", r"(?i)\bor\b.{0,12}?=.{0,12}?\bor\b"),        # 宽松 OR x = x OR
        ("sqli", r"(?i)union.*?select"),
        ("sqli", r"(?i)/\*/"),                                 # 注释绕过 /**/
        ("sqli", r"(?i)0x[0-9a-f]+"),                          # hex 编码
        ("sqli", r"(?i)\bhaving\b"),
        ("xss", r"(?i)<\w+\s+[^>]*>"),                        # 任意 HTML 标签
        ("xss", r"(?i)%3cscript"),                             # 编码 <script
        ("xss", r"(?i)document\.cookie"),
        ("xss", r"(?i)svg\b.*?onload"),
        ("cmdi", r"`[^`]+`"),                                  # 反引号执行
        ("cmdi", r"\$\("),                                      # $()
        ("cmdi", r"(?i)(wget|curl|nc|bash)\b"),
        ("lfi", r"(\.\./|\.\\)+"),
        ("lfi", r"(?i)/proc/self"),
        ("lfi", r"(?i)boot\.ini"),
    ],
    "PL3": [
        # 最宽泛启发式
        ("sqli", r"(?i)\b(or|and)\b\s+\w*\s*=\s*\w+"),        # 任意 OR/AND x=y
        ("sqli", r"(?i)\bgroup\s+by\b"),
        ("sqli", r"(?i)(union){2,}"),                          # 双写绕过
        ("xss", r"(?i)<\w"),
        ("xss", r"(?i)on\w+="),
        ("cmdi", r"[;|]"),                                       # 命令分隔符 ; |（不含 &，& 仅为 query 分隔符）
        ("cmdi", r"(`|\$\()"),
        ("lfi", r"\.\."),                                      # 任何 .. 序列
        ("lfi", r"/etc"),
    ],
}


class RuleBasedWAF:
    """本地规则 WAF 基线，模拟 OWASP CRS 三档 Paranoia Level。"""

    def __init__(self):
        self.compiled = {}
        acc = []
        for pl in ("PL1", "PL2", "PL3"):
            acc = acc + _RAW_RULES[pl]  # 累积继承低 PL 规则（严格度递增）
            self.compiled[pl] = [(cat, re.compile(rx)) for cat, rx in acc]

    def check(self, raw_http: str, pl: str) -> dict:
        """
        对一条 raw HTTP 请求做拦截判断。

        返回:
            {"blocked": bool, "status": int|None, "category": str|None,
             "rule": str|None, "error": str|None}
        """
        if pl not in self.compiled:
            return {"blocked": None, "status": None, "category": None,
                    "rule": None, "error": f"unknown PL {pl}"}
        text = unquote_plus(raw_http or "")  # 模拟真实 WAF：先解码再检测（urlencode 用 + 表示空格，需 unquote_plus）
        for cat, rx in self.compiled[pl]:
            m = rx.search(text)
            if m:
                return {
                    "blocked": True,
                    "status": 403,
                    "category": cat,
                    "rule": rx.pattern[:48],
                    "error": None,
                }
        return {
            "blocked": False,
            "status": 200,
            "category": None,
            "rule": None,
            "error": None,
        }


if __name__ == "__main__":
    waf = RuleBasedWAF()
    samples = [
        ("sqli", "GET /vulnerabilities/sqli/?id=1' OR '1'='1 HTTP/1.1"),
        ("xss", "GET /vulnerabilities/xss_r/?name=<script>alert(1)</script> HTTP/1.1"),
        ("cmdi", "POST /vulnerabilities/exec/ ip=127.0.0.1; cat /etc/passwd"),
        ("lfi", "GET /vulnerabilities/fi/?page=../../../../etc/passwd HTTP/1.1"),
        ("benign", "GET /vulnerabilities/sqli/?id=1 HTTP/1.1"),
        ("benign", "GET /vulnerabilities/xss_r/?name=John HTTP/1.1"),
    ]
    for label, req in samples:
        line = f"[{label:7s}]"
        for pl in ("PL1", "PL2", "PL3"):
            r = waf.check(req, pl)
            tag = f"BLOCK({r['category']})" if r["blocked"] else "pass"
            line += f"  {pl}={tag}"
        print(line)
