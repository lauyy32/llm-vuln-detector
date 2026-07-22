"""
LLM 调用引擎 v2.0 — 异步调用 LLM API 做攻击载荷识别。

支持模式：
- cot: Chain-of-Thought 分步推理（默认，使用增强上下文 + CoT prompt）
- standard: 标准检测（使用增强上下文 + 标准 prompt，消融对比）
- no-context: 无上下文增强（消融基线）

支持 provider：
- deepseek (DeepSeek-Chat)
- glm (智谱 GLM-4-Flash)

特性：
- httpx 异步调用 + 连接池复用
- tenacity 指数退避重试（仅 5xx/超时）
- JSON 响应三级容错解析
"""
import json
import logging
import time
import httpx
from typing import Optional
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

logger = logging.getLogger(__name__)


class LLMEngineError(Exception):
    """LLM 引擎异常。"""
    pass


class LLMEngine:
    """LLM 调用引擎 v2.0，支持 CoT 和标准模式。"""

    def __init__(self, config: dict):
        """
        Args:
            config: {
                "provider": "deepseek" | "glm",
                "api_key": "xxx",
                "base_url": "...",
                "model": "...",
                "timeout": 60,
                "max_retries": 3,
                "temperature": 0.1,
            }
        """
        self.provider = config["provider"]
        self.api_key = config["api_key"]
        self.base_url = config.get("base_url", "")
        self.model = config.get("model", "")
        self.timeout = config.get("timeout", 60)
        self.max_retries = config.get("max_retries", 3)
        self.temperature = config.get("temperature", 0.1)
        self._client: Optional[httpx.AsyncClient] = None

        # v2.0 — 统计信息
        self.total_calls = 0
        self.total_time_ms = 0
        self.failed_calls = 0

        if not self.api_key:
            raise LLMEngineError(f"未配置 {self.provider} 的 API Key")

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout, connect=10.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.HTTPStatusError)),
        reraise=True,
    )
    async def _call_api(self, messages: list[dict]) -> tuple[str, float]:
        """实际调用 LLM API，带重试。返回 (content, elapsed_ms)。"""
        client = await self._get_client()
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }
        # DeepSeek 支持 json_object，智谱不支持
        if self.provider == "deepseek":
            payload["response_format"] = {"type": "json_object"}

        logger.info("调用 LLM: provider=%s, model=%s, mode=CoT", self.provider, self.model)
        t0 = time.time()
        resp = await client.post(
            f"{self.base_url}/chat/completions",
            headers=headers,
            json=payload,
        )
        elapsed = (time.time() - t0) * 1000

        if resp.status_code >= 500:
            raise httpx.HTTPStatusError(
                f"LLM API 返回 {resp.status_code}: {resp.text[:200]}",
                request=resp.request,
                response=resp,
            )
        if resp.status_code >= 400:
            raise LLMEngineError(f"LLM API 请求失败 ({resp.status_code}): {resp.text[:200]}")
        resp.raise_for_status()
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        logger.info("LLM 响应成功, 长度=%d, 耗时=%dms", len(content), int(elapsed))
        return content, elapsed

    def _parse_json_response(self, content: str) -> dict:
        """三级容错解析 LLM 返回的 JSON。"""
        content = content.strip()
        # 1. 直接解析
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass
        # 2. 提取 ```json ... ``` 代码块
        if "```json" in content:
            start = content.index("```json") + 7
            end = content.index("```", start)
            try:
                return json.loads(content[start:end].strip())
            except (json.JSONDecodeError, ValueError):
                pass
        # 3. 提取第一个 { 到最后一个 }
        first = content.find("{")
        last = content.rfind("}")
        if first != -1 and last != -1:
            try:
                return json.loads(content[first:last + 1])
            except json.JSONDecodeError:
                pass
        raise LLMEngineError(f"无法解析 LLM 响应为 JSON: {content[:200]}...")

    async def detect(self, messages: list[dict]) -> dict:
        """
        调用 LLM 进行攻击载荷识别（CoT 模式）。
        Returns: 包含 is_vulnerable, vulnerabilities 等字段的 dict
        """
        try:
            raw_content, elapsed = await self._call_api(messages)
            self.total_calls += 1
            self.total_time_ms += elapsed
            result = self._parse_json_response(raw_content)
            result["_meta"] = {
                "mode": "cot",
                "elapsed_ms": int(elapsed),
                "provider": self.provider,
                "model": self.model,
            }
            return result
        except httpx.TimeoutException:
            self.failed_calls += 1
            raise LLMEngineError(f"LLM API 调用超时（{self.timeout}s）")
        except httpx.HTTPStatusError as e:
            self.failed_calls += 1
            raise LLMEngineError(f"LLM API HTTP 错误: {e}")
        except LLMEngineError:
            self.failed_calls += 1
            raise
        except Exception as e:
            self.failed_calls += 1
            raise LLMEngineError(f"LLM 调用异常: {e}")

    def get_stats(self) -> dict:
        """返回引擎统计信息。"""
        return {
            "total_calls": self.total_calls,
            "failed_calls": self.failed_calls,
            "total_time_ms": int(self.total_time_ms),
            "avg_time_ms": int(self.total_time_ms / self.total_calls) if self.total_calls > 0 else 0,
            "provider": self.provider,
            "model": self.model,
        }

    async def close(self):
        """关闭 httpx client。"""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
