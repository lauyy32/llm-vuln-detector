"""
HTTP 请求解析与多维上下文构造器 v2.0。

升级内容：
1. 编码检测与逐层解码 — URL/Unicode/HTML实体/Base64
2. 混淆模式分析 — 大小写混淆/空白符替代/注释注入/NULL截断
3. 结构化多维度上下文报告

整合安全专家的预扫描方案：
1. 解析原始 HTTP 请求文本
2. 编码检测 + 逐层解码还原
3. 混淆模式识别
4. 对参数做风险信号预扫描（正则匹配）
5. 构造多维结构化上下文 + LLM messages
"""
import base64
import html
import json
import re
from urllib.parse import urlparse, parse_qsl, unquote
from dataclasses import dataclass, field
from typing import Optional

from app.core.prompt_templates import (
    SYSTEM_PROMPT,
    USER_PROMPT_TEMPLATE,
    USER_PROMPT_TEMPLATE_NO_CONTEXT,
)

# ============================================================
#  编码检测与解码
# ============================================================

def detect_encoding_layers(value: str) -> dict:
    """
    检测参数值中应用的编码层级，并尝试逐层解码。

    Returns: {
        "layers": ["url_single", "url_double", "unicode", "html_entity", "base64"],
        "decoded_chain": [("url_single", "..."), ("unicode", "...")],
        "final_decoded": "...",  # 最深解码后的值
        "depth": 1
    }
    """
    result = {
        "layers": [],
        "decoded_chain": [],
        "final_decoded": value,
        "depth": 0,
    }
    current = value

    # 简化的编码层检测（逐一检测，不做全组合）
    # 0. 空值跳过
    if not current or not isinstance(current, str):
        return result

    # 1. 检测 Base64（长度 > 8 且无空格，主要由 A-Za-z0-9+/= 组成）
    b64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    if len(current) >= 8 and b64_pattern.match(current.strip()):
        result["layers"].append("base64")
        try:
            decoded = base64.b64decode(current).decode("utf-8", errors="replace")
            if _has_meaningful_content(decoded, current):
                result["decoded_chain"].append(("base64", decoded[:200]))
                current = decoded
                result["depth"] += 1
        except Exception:
            pass

    # 2. 检测双重 URL 编码（%25xx = % 的编码形式）
    if "%25" in current:
        result["layers"].append("url_double")
        try:
            decoded = unquote(current)
            if decoded != current:
                result["decoded_chain"].append(("url_double", decoded[:200]))
                current = decoded
                result["depth"] += 1
        except Exception:
            pass

    # 3. 检测单层 URL 编码（%xx 形式）
    if "%" in current and any(c.isdigit() or c in "abcdefABCDEF" for c in _chars_after_percent(current)):
        result["layers"].append("url_single")
        try:
            decoded = unquote(current)
            if decoded != current:
                result["decoded_chain"].append(("url_single", decoded[:200]))
                current = decoded
                result["depth"] += 1
        except Exception:
            pass

    # 4. 检测 Unicode 编码（\\uXXXX 或 \uXXXX 形式）
    if "\\u" in current or "\\U" in current or "&#x" in current:
        result["layers"].append("unicode")
        try:
            decoded = _decode_unicode_escapes(current)
            if decoded != current:
                result["decoded_chain"].append(("unicode", decoded[:200]))
                current = decoded
                result["depth"] += 1
        except Exception:
            pass

    # 5. 检测 HTML 实体编码（&#xx; &lt; &gt; &amp; &quot;）
    if "&" in current and ";" in current:
        html_entity_pattern = re.compile(r'&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);')
        if html_entity_pattern.search(current):
            result["layers"].append("html_entity")
            try:
                decoded = html.unescape(current)
                if decoded != current:
                    result["decoded_chain"].append(("html_entity", decoded[:200]))
                    current = decoded
                    result["depth"] += 1
            except Exception:
                pass

    result["final_decoded"] = current
    return result


def _chars_after_percent(s: str) -> list:
    """提取 % 后两个字符。"""
    chars = []
    for i in range(len(s) - 2):
        if s[i] == "%":
            chars.extend([s[i+1], s[i+2]])
    return chars


def _decode_unicode_escapes(s: str) -> str:
    """解码 Unicode 转义序列 \\uXXXX 和 &#xXXXX;。"""
    # 先处理 &#xXXXX; 形式
    s = re.sub(r'&#x([0-9a-fA-F]+);', lambda m: chr(int(m.group(1), 16)), s)
    # 再处理 \\uXXXX 形式
    s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    # 处理 \uXXXX 形式的 JS 字符串（但前面可能没有反斜杠转义了）
    s = re.sub(r'\\\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    return s


def _has_meaningful_content(decoded: str, original: str) -> bool:
    """判断解码后的内容是否有意义（不是纯噪音）。"""
    if not decoded or len(decoded) < 2:
        return False
    # 如果解码后包含常见攻击特征，认为有意义
    meaningful_chars = set("'\"<>&()[]{}|;/=:")
    return any(c in decoded for c in meaningful_chars) or decoded != original


# ============================================================
#  混淆模式分析
# ============================================================

def analyze_confusion(value: str, decoded: str = "") -> dict:
    """
    分析 payload 中的混淆手法。

    Returns: {
        "techniques": ["case_confusion", "whitespace_variation", "comment_injection",
                       "null_byte", "string_splicing", "hex_encoding_inline"],
        "details": {"case_confusion": "UnIoN SeLeCt -> union select", ...},
        "score": 0-10  (混淆程度, 0=无混淆, 10=高度混淆)
    }
    """
    techniques = []
    details = {}
    score = 0
    target = decoded if decoded else value

    # 1. 大小写混淆（检测大小写交替模式）
    case_pattern = re.compile(r'(?i)(union|select|or|and|insert|drop|alert|script|onerror|javascript)', re.IGNORECASE)
    case_matches = case_pattern.findall(target)
    mixed_case = [w for w in case_matches if not (w.islower() or w.isupper() or w.lower() == w)]
    # 简单检测：关键词有大写也有小写混合
    if case_matches:
        has_upper = any(c.isupper() for c in target)
        has_lower = any(c.islower() for c in target)
        if has_upper and has_lower and any(kw.lower() != kw for kw in case_matches):
            techniques.append("case_confusion")
            normalized = target
            for kw in case_matches:
                normalized = re.sub(kw, kw.lower(), normalized, flags=re.IGNORECASE)
            details["case_confusion"] = f"检测到 {len(mixed_case) or len(case_matches)} 处大小写混淆的关键词"
            score += 2

    # 2. 空白符变体（检测 TAB/换行/垂直tab/CRLF替代空格）
    whitespace_variants = {
        "\\t": r'\t',
        "\\n": r'\n',
        "\\r": r'\r',
        "\\x0b": r'\x0b',
        "\\x0c": r'\x0c',
    }
    found_variants = []
    for name, pat in whitespace_variants.items():
        if re.search(pat, target) and not re.search(pat, value):
            found_variants.append(name)
    if found_variants:
        techniques.append("whitespace_variation")
        details["whitespace_variation"] = f"检测到替代空格: {', '.join(found_variants)}"
        score += 3

    # 3. 注释注入（SQL 内联注释 /**/、--、#、/*!...*/）
    comment_patterns = [
        (r'/\*!?\d*', "MySQL条件注释 /*!...*/"),
        (r'/\*\*', "空注释 /**/"),
        (r'--\s', "SQL双减号注释"),
        (r'#\s', "哈希注释"),
    ]
    for pat, desc in comment_patterns:
        if re.search(pat, target):
            techniques.append("comment_injection")
            details["comment_injection"] = desc
            score += 2
            break

    # 4. NULL 字节注入
    if "\x00" in target or "\\x00" in target or "\\0" in target:
        techniques.append("null_byte")
        details["null_byte"] = "检测到 NULL 字节截断企图"
        score += 2

    # 5. 字符串拼接/绕行
    if "+'\'+'" in target or "+'\"'+" in target or "CONCAT" in target.upper():
        techniques.append("string_splicing")
        details["string_splicing"] = "检测到字符串拼接绕过"
        score += 2

    # 6. 内联十六进制编码
    hex_pattern = re.compile(r'0x[0-9a-fA-F]{4,}')
    if hex_pattern.search(target):
        techniques.append("hex_inline")
        details["hex_inline"] = "检测到内联十六进制编码"
        score += 1

    # 7. 宽字节绕过
    if "%df" in value.lower() or "%bf" in value.lower():
        techniques.append("wide_byte")
        details["wide_byte"] = "检测到宽字节注入绕过 (GBK)"
        score += 3

    # 8. 换行编码绕过（CR/LF 注入）
    if "\r\n" in target and any(kw in target.lower() for kw in ["host:", "content-length:", "transfer-encoding:"]):
        techniques.append("header_injection")
        details["header_injection"] = "检测到 HTTP 头注入 (CRLF)"
        score += 3

    return {
        "techniques": techniques,
        "details": details,
        "score": min(score, 10),
    }


# ============================================================
#  风险信号预扫描正则（保留原有，扩展新增）
# ============================================================

RISK_PATTERNS = {
    "sql_meta_char":      r"""['";#]|--""",
    "sql_keyword":        r"(?i)\b(or|union|select|and|insert|update|delete|drop)\b",
    "sql_tautology":      r"(?i)(['\"]?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)",
    "shell_meta":         r"[;|&`$()]",
    "shell_keyword":      r"(?i)\b(cat|ls|whoami|id|wget|nc|bash|sh|chmod|rm|curl)\b",
    "path_traversal":     r"(\.\./|\.\.\\|%2e%2e|%252e%252e)",
    "xss_tag":            r"(?i)<(script|img|svg|iframe|body|object|embed)",
    "xss_event":          r"(?i)on(error|load|click|mouseover|focus|blur)\s*=",
    "xss_protocol":       r"(?i)javascript:",
    "ssrf_internal":      r"(127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)",
    "ssrf_protocol":      r"(?i)(file|gopher|dict|ftp)://",
    "xxe_marker":         r"(?i)(<!doctype|<!entity|system\s)",
    "ssti_marker":        r"(\{\{.*\}\}|\$\{.*\}|\{%.+%\})",
    "nosql_operator":     r"\$(ne|gt|lt|where|regex|in|nin)",
    "open_redirect":      r"(https?://)",
    # v2.0 新增 — 对抗性检测
    "encoded_attack":     r"(%27|%22|%3C|%3E|%3B|%7C|%26|%24)",
    "comment_injection":  r"/\*.*?\*/|/\*!.*?\*/",
    "null_byte":          r"\\x00|\\0|%00",
    "wide_byte_escape":   r"%[bd]f%27",
    "shell_reverse_shell": r"(?i)(nc\s+-[el]|bash\s+-i|python\s+-c|socat|mkfifo)",
    "xxe_combined":       r"(?i)(<\?xml.+!DOCTYPE.*SYSTEM)",
}


def scan_risk_signals(value: str) -> list[str]:
    """对参数值做正则预扫描，返回命中的风险信号列表。"""
    signals = []
    for sig, pat in RISK_PATTERNS.items():
        if re.search(pat, value):
            signals.append(sig)
        # 对 v2.0 新增的信号也在解码后的值上检测
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
    # v2.0 新增
    encoding_info: Optional[dict] = None    # detect_encoding_layers 的结果
    confusion_info: Optional[dict] = None   # analyze_confusion 的结果


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
    # v2.0 新增 — 全局编码/混淆摘要
    global_encoding_summary: list[str] = field(default_factory=list)
    global_confusion_summary: list[str] = field(default_factory=list)


# ============================================================
#  解析函数
# ============================================================

def _analyze_param(param: ParsedParam, original_value: str):
    """对单个参数执行编码检测和混淆分析。"""
    # 同时在原始值和解码值上做编码检测
    encoding_raw = detect_encoding_layers(original_value)
    encoding_decoded = detect_encoding_layers(param.decoded) if param.decoded != original_value else {}

    # 合并在原始值上检测到的编码层
    all_layers = encoding_raw.get("layers", [])
    for layer in encoding_decoded.get("layers", []):
        if layer not in all_layers:
            all_layers.append(layer)

    if all_layers:
        param.encoding_info = {
            "layers": all_layers,
            "depth": max(encoding_raw.get("depth", 0), encoding_decoded.get("depth", 0)),
            "raw_layers": encoding_raw.get("layers", []),
            "decoded_chain": encoding_raw.get("decoded_chain", []),
            "final_decoded": encoding_raw.get("final_decoded", param.decoded),
        }
    else:
        param.encoding_info = {"layers": [], "depth": 0, "final_decoded": param.decoded}

    # 混淆分析（在解码后的值上做）
    target_for_confusion = param.encoding_info.get("final_decoded", param.decoded)
    param.confusion_info = analyze_confusion(param.decoded, target_for_confusion)


def _extract_raw_query_pairs(query_string: str) -> dict:
    """从原始 query string 中提取 key-value 对（不做 URL 解码），保留原始编码值。"""
    pairs = {}
    if not query_string:
        return pairs
    for part in query_string.split("&"):
        if "=" in part:
            key, _, value = part.partition("=")
            pairs[key] = value
        else:
            pairs[part] = ""
    return pairs


def parse_raw_request(raw_text: str) -> ParsedHttpRequest:
    """
    解析原始 HTTP 请求文本（v2.0 升级版）。
    支持 GET/POST，支持 query params、JSON body、form body。
    新增：编码检测 + 混淆分析。
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
        # parse_qsl 默认解码 URL 编码，所以 value 是已解码的
        # 需要从 query_string 中提取原始值用于编码检测
        raw_pairs = _extract_raw_query_pairs(query_string)
        for name, decoded_value in parse_qsl(query_string, keep_blank_values=True):
            # 从 raw_pairs 中获取原始值（未解码的）
            raw_value = raw_pairs.get(name, decoded_value)
            signals = scan_risk_signals(decoded_value)
            param = ParsedParam(name, raw_value, decoded_value,
                              "int" if decoded_value.isdigit() else "string", signals)
            _analyze_param(param, raw_value)
            result.query_params.append(param)

    # --- 解析 body ---
    body_block = body_block.strip()
    if body_block:
        result.body = body_block
        content_type = result.headers.get("Content-Type", "").lower()
        if "application/json" in content_type:
            result.body_type = "json"
            try:
                data = json.loads(body_block)
                if isinstance(data, dict):
                    for k, v in data.items():
                        val_str = str(v)
                        signals = scan_risk_signals(val_str)
                        param = ParsedParam(k, val_str, val_str, "string", signals)
                        _analyze_param(param, val_str)
                        result.body_params.append(param)
            except json.JSONDecodeError:
                pass
        elif "application/x-www-form-urlencoded" in content_type:
            result.body_type = "form"
            raw_pairs = _extract_raw_query_pairs(body_block)
            for name, decoded_value in parse_qsl(body_block, keep_blank_values=True):
                raw_value = raw_pairs.get(name, decoded_value)
                signals = scan_risk_signals(decoded_value)
                param = ParsedParam(name, raw_value, decoded_value,
                                  "int" if decoded_value.isdigit() else "string", signals)
                _analyze_param(param, raw_value)
                result.body_params.append(param)
        elif "xml" in content_type:
            result.body_type = "xml"
            signals = scan_risk_signals(body_block)
            param = ParsedParam("<xml>", body_block, body_block, "string", signals)
            _analyze_param(param, body_block)
            result.body_params.append(param)
        else:
            result.body_type = "raw"
            signals = scan_risk_signals(body_block)
            param = ParsedParam("<raw>", body_block, body_block, "string", signals)
            _analyze_param(param, body_block)
            result.body_params.append(param)

    # 汇总全局编码/混淆摘要
    all_params = result.query_params + result.body_params
    encoding_set = set()
    confusion_set = set()
    for p in all_params:
        if p.encoding_info and p.encoding_info.get("layers"):
            for layer in p.encoding_info["layers"]:
                encoding_set.add(layer)
        if p.confusion_info and p.confusion_info.get("techniques"):
            for technique in p.confusion_info["techniques"]:
                confusion_set.add(technique)
    result.global_encoding_summary = sorted(encoding_set)
    result.global_confusion_summary = sorted(confusion_set)

    return result


# ============================================================
#  上下文构造（v2.0 升级 — 多维上下文）
# ============================================================

def build_encoding_report(param: ParsedParam) -> dict:
    """为单个参数生成编码分析报告。"""
    if not param.encoding_info or not param.encoding_info.get("layers"):
        return None
    info = param.encoding_info
    return {
        "detected_layers": info.get("layers", []),
        "depth": info.get("depth", 0),
        "decoded_chain": [
            {"stage": layer, "result": result}
            for layer, result in info.get("decoded_chain", [])
        ],
        "final_decoded": info.get("final_decoded", param.decoded)[:300],
    }


def build_confusion_report(param: ParsedParam) -> dict:
    """为单个参数生成混淆分析报告。"""
    if not param.confusion_info or not param.confusion_info.get("techniques"):
        return None
    info = param.confusion_info
    return {
        "techniques": info.get("techniques", []),
        "details": info.get("details", {}),
        "score": info.get("score", 0),
    }


def build_structured_context(parsed: ParsedHttpRequest, request_id: str) -> str:
    """
    将解析后的 HTTP 请求构造为多维结构化上下文字符串（v2.0 升级版）。
    包含预扫描结果 + 编码分析 + 混淆分析，帮助 LLM 全面理解攻击复杂度。
    """
    all_params = parsed.query_params + parsed.body_params
    high_risk = [p.name for p in all_params if p.risk_signals]

    context = {
        "request_id": request_id,
        "method": parsed.method,
        "path": parsed.path,
        "host": parsed.host,
        # 全局摘要
        "global_summary": {
            "total_params": len(all_params),
            "high_risk_params": len(high_risk),
            "encoding_layers_detected": parsed.global_encoding_summary,
            "confusion_techniques_detected": parsed.global_confusion_summary,
            "overall_threat_assessment": (
                "高度可疑 — 存在多层编码和混淆手法" if parsed.global_encoding_summary and parsed.global_confusion_summary
                else "可疑 — 检测到攻击载荷特征" if high_risk
                else "低风险 — 未发现明显攻击特征"
            ),
        },
        "query_params": [],
        "body_params": [],
        "interesting_headers": {
            k: v for k, v in parsed.headers.items()
            if k.lower() in ("cookie", "content-type", "authorization", "referer", "user-agent",
                               "x-forwarded-for", "x-real-ip")
        },
        "pre_scan": {
            "high_risk_params": high_risk,
            "note": (
                f"预扫描发现 {len(high_risk)} 个可疑参数（含编码/混淆检测），建议分步推理分析"
                if high_risk else "预扫描未发现明显风险信号"
            ),
        },
    }

    for p in parsed.query_params:
        entry = {
            "name": p.name,
            "value": p.value[:200],
            "decoded": p.decoded[:200],
            "risk_signals": p.risk_signals,
        }
        enc_report = build_encoding_report(p)
        if enc_report:
            entry["encoding_analysis"] = enc_report
        conf_report = build_confusion_report(p)
        if conf_report:
            entry["confusion_analysis"] = conf_report
        context["query_params"].append(entry)

    for p in parsed.body_params:
        entry = {
            "name": p.name,
            "value": p.value[:200],
            "risk_signals": p.risk_signals,
        }
        enc_report = build_encoding_report(p)
        if enc_report:
            entry["encoding_analysis"] = enc_report
        conf_report = build_confusion_report(p)
        if conf_report:
            entry["confusion_analysis"] = conf_report
        context["body_params"].append(entry)

    return json.dumps(context, indent=2, ensure_ascii=False)


def build_detection_messages(parsed: ParsedHttpRequest, request_id: str) -> list[dict]:
    """构造 LLM messages 列表（system + user），使用增强版上下文。"""
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
