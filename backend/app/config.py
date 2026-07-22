"""
应用配置，从环境变量 / .env 文件读取。
"""
from typing import ClassVar

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="APP_")

    # LLM Provider: glm | deepseek
    llm_provider: str = "glm"

    # API Keys
    glm_api_key: str = ""
    deepseek_api_key: str = ""

    # 可选覆盖
    llm_base_url: str = ""
    llm_model: str = ""
    llm_timeout: int = 60
    llm_max_retries: int = 3
    llm_temperature: float = 0.1

    # 服务配置
    app_name: str = "LLM-VulnDetector"
    debug: bool = False

    # Provider 默认配置
    PROVIDER_DEFAULTS: ClassVar[dict] = {
        "glm": {
            "base_url": "https://open.bigmodel.cn/api/paas/v4",
            "model": "glm-4-flash",
        },
        "deepseek": {
            "base_url": "https://api.deepseek.com",
            "model": "deepseek-chat",
        },
    }

    def get_llm_config(self) -> dict:
        """构造 LLMEngine 所需的配置字典。"""
        provider = self.llm_provider
        api_key = (
            self.glm_api_key if provider == "glm" else self.deepseek_api_key
        )
        defaults = self.PROVIDER_DEFAULTS.get(provider, {})
        config = {
            "provider": provider,
            "api_key": api_key,
            "timeout": self.llm_timeout,
            "max_retries": self.llm_max_retries,
            "temperature": self.llm_temperature,
            "base_url": defaults.get("base_url", ""),
            "model": defaults.get("model", ""),
        }
        if self.llm_base_url:
            config["base_url"] = self.llm_base_url
        if self.llm_model:
            config["model"] = self.llm_model
        return config


settings = Settings()
