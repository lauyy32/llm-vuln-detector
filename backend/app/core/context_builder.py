"""
HTTP 请求解析与上下文构造器。

整合安全专家的预扫描方案：
1. 解析原始 HTTP 请求文本
2. 对参数做风险信号预扫描（正则匹配）
3. 构造结构化上下文 + LLM messages
"""
import json
import re
from urllib.parse import urlparse, parse_qsl, unquote
from dataclasses import dataclass, field

from app.core.prompt_templates import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, USER_PROMPT_TEMPLATE_NO_CONTEXT


# ============================================================
#  风险信号预扫描正则
# ============================================================

RISK_PATTERNS = {
    "sql_meta_char":     r"""['";#]|--""",
    "sql_keyword":       r"(?i)\b(or|union|select|and|insert|update|delete|drop)\b",
    "sql_tautology":     r"(?i)(['\"]?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    "shell_meta":        r"[;|&`$()]",
    "shell_keyword":     r"(?i)\b(cat|ls|whoami|id|wget|nc|bash|sh|chmod|rm)\b",
    "path_traversal":    r"(\.\./|\.\.\\|%2e%2e)",
    "xss_tag":           r"(?i)<(script|img|svg|iframe|body|object|embed)",
    "xss_event":         r"(?i)on(error|load|click|mouseover|focus|blur)\s*=",
    "xss_protocol":      r"(?i)javascript:",
    "ssrf_internal":     r"(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    "ssrf_protocol":     r"(?i)(file|gopher|dict|ftp)://",
    "xxe_marker":        r"(?i)(<!doctype|<!entity|system\s)",
    "ssti_marker":       r"(\{\{.*\}\}|\$\{.*\}|\{%.+%\})",
    "nosql_operator":    r"\$(ne|gt|lt|where|regex|in|nin)",
    "open_redirect":     r"(https?://)",
}


def scan_risk_signals(value: str) -> list[str]:
    """对参数值做正则预扫描，返回命中的风险信号列表。"""
    signals = []
    for sig, pat in RISK_PATTERNS.items():
        if re.search(pat, value):
            signals.append(sig)
    return signals


# ============================================================
#  数据结构
# ============================================================

@dataclass
class ParsedParam:
    name: str
    value: str
    decoded: str
    value_type: str  # int / string
    risk_signals: list[str] = field(default_factory=list)


@dataclass
class ParsedHttpRequest:
    method: str = ""
    path: str = ""
    protocol: str = ""
    host: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    body_type: str = "none"  # none / json / form / xml / raw
    query_params: list = field(default_factory=list)
    body_params: list = field(default_factory=list)
    raw: str = ""


# ============================================================
#  解析函数
# ============================================================

def parse_raw_request(raw_text: str) -> ParsedHttpRequest:
    """
    解析原始 HTTP 请求文本。
    支持 GET/POST，支持 query params、JSON body、form body。
    """
    result = ParsedHttpRequest(raw=raw_text)
    normalized = raw_text.replace("\r\n", "\n").strip()
    parts = normalized.split("\n\n", 1)
    header_block = parts[0]
    body_block = parts[1] if len(parts) > 1 else ""

    lines = header_block.split("\n")
    if not lines:
        return result

    # --- 解析 request line ---
    request_line = lines[0].strip()
    tokens = request_line.split()
    if len(tokens) >= 3:
        result.method, result.path, result.protocol = tokens[0], tokens[1], tokens[2]
    elif len(tokens) >= 2:
        result.method, result.path = tokens[0], tokens[1]

    # --- 解析 headers ---
    for line in lines[1:]:
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        result.headers[key] = value
        if key.lower() == "host":
            result.host = value

    # --- 解析 query params ---
    if "?" in result.path:
        path_only, _, query_string = result.path.partition("?")
        result.path = path_only
        for name, value in parse_qsl(query_string, keep_blank_values=True):
            decoded = unquote(value)
            signals = scan_risk_signals(decoded)
            result.query_params.append(
                ParsedParam(name, value, decoded, "int" if decoded.isdigit() else "string", signals)
            )

    # --- 解析 body ---
    body_block = body_block.strip()
    if body_block:
        result.body = body_block
        content_type = result.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            result.body_type = "json"
            # 尝试解析 JSON 中的字段
            try:
                data = json.loads(body_block)
                if isinstance(data, dict):
                    for k, v in data.items():
                        val_str = str(v)
                        signals = scan_risk_signals(val_str)
                        result.body_params.append(
                            ParsedParam(k, val_str, val_str, "string", signals)
                        )
            except json.JSONDecodeError:
                pass
        elif "application/x-www-form-urlencoded" in content_type:
            result.body_type = "form"
            for name, value in parse_qsl(body_block, keep_blank_values=True):
                decoded = unquote(value)
                signals = scan_risk_signals(decoded)
                result.body_params.append(
                    ParsedParam(name, value, decoded, "int" if decoded.isdigit() else "string", signals)
                )
        elif "xml" in content_type:
            result.body_type = "xml"
            signals = scan_risk_signals(body_block)
            result.body_params.append(ParsedParam("<xml>", body_block, body_block, "string", signals))
        else:
            result.body_type = "raw"
            signals = scan_risk_signals(body_block)
            result.body_params.append(ParsedParam("<raw>", body_block, body_block, "string", signals))

    return result


# ============================================================
#  上下文构造
# ============================================================

def build_structured_context(parsed: ParsedHttpRequest, request_id: str) -> str:
    """
    将解析后的 HTTP 请求构造为结构化上下文字符串（供 LLM 阅读）。
    包含预扫描结果，帮助 LLM 快速定位可疑参数。
    """
    # 汇总所有高风险参数
    all_params = parsed.query_params + parsed.body_params
    high_risk = [p.name for p in all_params if p.risk_signals]

    context = {
        "request_id": request_id,
        "method": parsed.method,
        "path": parsed.path,
        "host": parsed.host,
        "query_params": [
            {
                "name": p.name,
                "value": p.value,
                "decoded": p.decoded,
                "risk_signals": p.risk_signals,
            }
            for p in parsed.query_params
        ],
        "body_type": parsed.body_type,
        "body_params": [
            {
                "name": p.name,
                "value": p.value[:200],  # 截断长值
                "risk_signals": p.risk_signals,
            }
            for p in parsed.body_params
        ],
        "interesting_headers": {
            k: v for k, v in parsed.headers.items()
            if k.lower() in ("cookie", "content-type", "authorization", "referer")
        },
        "pre_scan": {
            "high_risk_params": high_risk,
            "note": f"预扫描发现 {len(high_risk)} 个可疑参数，建议重点分析" if high_risk
                    else "预扫描未发现明显风险信号",
        },
    }
    return json.dumps(context, indent=2, ensure_ascii=False)


def build_detection_messages(parsed: ParsedHttpRequest, request_id: str) -> list[dict]:
    """
    构造 LLM messages 列表（system + user）。
    """
    structured_ctx = build_structured_context(parsed, request_id)
    user_content = USER_PROMPT_TEMPLATE.format(
        request_id=request_id,
        structured_context=structured_ctx,
        raw_http=parsed.raw,
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]


def build_detection_messages_no_context(raw_http: str, request_id: str) -> list[dict]:
    """
    构造 LLM messages 列表（system + user）—— 无上下文增强版（消融实验对照）。
    直接发送原始 HTTP 请求，不做结构化解析和预扫描。
    """
    user_content = USER_PROMPT_TEMPLATE_NO_CONTEXT.format(
        request_id=request_id,
        raw_http=raw_http,
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]
