"""Configuration schema using Pydantic."""

from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator
from pydantic.alias_generators import to_camel
from pydantic_settings import BaseSettings


class Base(BaseModel):
    """Base model that accepts both camelCase and snake_case keys."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


def normalize_openai_api_base(value: str | None) -> str | None:
    """Normalize an OpenAI-compatible base URL for human-friendly input."""
    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    candidate = raw if "://" in raw else f"http://{raw}"
    parsed = urlsplit(candidate)

    # If parsing still fails to produce a host, keep the raw value untouched.
    if not parsed.netloc:
        return raw

    path = parsed.path.rstrip("/")
    if not path:
        path = "/v1"

    return urlunsplit((parsed.scheme or "http", parsed.netloc, path, "", ""))


class ChannelsConfig(Base):
    """Configuration for chat channels.

    Built-in and plugin channel configs are stored as extra fields.
    Each channel parses its own config in __init__.
    """

    model_config = ConfigDict(extra="allow")

    send_progress: bool = True
    send_tool_hints: bool = False
    send_max_retries: int = Field(default=3, ge=0, le=10)


class AgentDefaults(Base):
    """Default agent configuration."""

    workspace: str = "~/.forensic-claw/workspace"
    model: str = "qwen1.5-35b-4bit"
    provider: str = "vllm"
    max_tokens: int = 8192
    context_window_tokens: int = 65_536
    temperature: float = 0.1
    max_tool_iterations: int = 40
    reasoning_effort: str | None = None
    timezone: str = "UTC"
    thinking_language: str = "en"
    response_language: str = "ko"
    enforce_response_language: bool = True
    archive_final_answer_as_wiki: bool = False
    reset_session_after_answer: bool = False


class AgentsConfig(Base):
    """Agent configuration."""

    defaults: AgentDefaults = Field(default_factory=AgentDefaults)


class ProviderConfig(Base):
    """LLM provider configuration."""

    api_key: str = ""
    api_base: str | None = None
    extra_headers: dict[str, str] | None = None

    @field_validator("api_base", mode="before")
    @classmethod
    def _normalize_api_base(cls, value: str | None) -> str | None:
        return normalize_openai_api_base(value)


class ProvidersConfig(Base):
    """Configuration for local OpenAI-compatible providers."""

    custom: ProviderConfig = Field(default_factory=ProviderConfig)
    vllm: ProviderConfig = Field(default_factory=ProviderConfig)


class HeartbeatConfig(Base):
    """Heartbeat service configuration."""

    enabled: bool = True
    interval_s: int = 30 * 60
    keep_recent_messages: int = 8


class GatewayConfig(Base):
    """Gateway/server configuration."""

    host: str = "127.0.0.1"
    port: int = 18790
    heartbeat: HeartbeatConfig = Field(default_factory=HeartbeatConfig)


class WebSearchConfig(Base):
    """Web search tool configuration."""

    provider: str = "brave"
    api_key: str = ""
    base_url: str = ""
    max_results: int = 5


class WebToolsConfig(Base):
    """Web tools configuration."""

    proxy: str | None = None
    search: WebSearchConfig = Field(default_factory=WebSearchConfig)


class ExecToolConfig(Base):
    """Shell exec tool configuration."""

    enable: bool = True
    timeout: int = 60
    path_append: str = ""
    elevate_on_windows: bool = True


class MCPServerConfig(Base):
    """MCP server connection configuration (stdio or HTTP)."""

    type: Literal["stdio", "sse", "streamableHttp"] | None = None
    command: str = ""
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str = ""
    headers: dict[str, str] = Field(default_factory=dict)
    tool_timeout: int = 30
    enabled_tools: list[str] = Field(default_factory=lambda: ["*"])


class ToolsConfig(Base):
    """Tools configuration."""

    web: WebToolsConfig = Field(default_factory=WebToolsConfig)
    exec: ExecToolConfig = Field(default_factory=ExecToolConfig)
    restrict_to_workspace: bool = False
    mcp_servers: dict[str, MCPServerConfig] = Field(default_factory=dict)


class Config(BaseSettings):
    """Root configuration for forensic-claw."""

    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    channels: ChannelsConfig = Field(default_factory=ChannelsConfig)
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    gateway: GatewayConfig = Field(default_factory=GatewayConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)

    @property
    def workspace_path(self) -> Path:
        """Get expanded workspace path."""
        return Path(self.agents.defaults.workspace).expanduser()

    def _match_provider(
        self, model: str | None = None
    ) -> tuple["ProviderConfig | None", str | None]:
        """Match provider config and its registry name."""
        from forensic_claw.providers.registry import PROVIDERS, find_by_name

        forced = self.agents.defaults.provider
        if forced != "auto":
            spec = find_by_name(forced)
            if spec:
                provider = getattr(self.providers, spec.name, None)
                return (provider, spec.name) if provider else (None, None)
            return None, None

        model_lower = (model or self.agents.defaults.model).lower()
        model_normalized = model_lower.replace("-", "_")
        model_prefix = model_lower.split("/", 1)[0] if "/" in model_lower else ""
        normalized_prefix = model_prefix.replace("-", "_")

        def _kw_matches(keyword: str) -> bool:
            keyword = keyword.lower()
            return keyword in model_lower or keyword.replace("-", "_") in model_normalized

        for spec in PROVIDERS:
            provider = getattr(self.providers, spec.name, None)
            if provider and model_prefix and normalized_prefix == spec.name:
                if spec.is_local or spec.is_direct or provider.api_key:
                    return provider, spec.name

        for spec in PROVIDERS:
            provider = getattr(self.providers, spec.name, None)
            if provider and any(_kw_matches(keyword) for keyword in spec.keywords):
                if spec.is_local or spec.is_direct or provider.api_key:
                    return provider, spec.name

        local_fallback: tuple[ProviderConfig, str] | None = None
        for spec in PROVIDERS:
            if not spec.is_local:
                continue
            provider = getattr(self.providers, spec.name, None)
            if not provider:
                continue
            if provider.api_base and spec.detect_by_base_keyword and spec.detect_by_base_keyword in provider.api_base:
                return provider, spec.name
            if local_fallback is None:
                local_fallback = (provider, spec.name)
        if local_fallback:
            return local_fallback

        for spec in PROVIDERS:
            provider = getattr(self.providers, spec.name, None)
            if provider and (spec.is_local or spec.is_direct or provider.api_key):
                return provider, spec.name
        return None, None

    def get_provider(self, model: str | None = None) -> ProviderConfig | None:
        """Get matched provider config."""
        provider, _ = self._match_provider(model)
        return provider

    def get_provider_name(self, model: str | None = None) -> str | None:
        """Get the registry name of the matched provider."""
        _, name = self._match_provider(model)
        return name

    def get_api_key(self, model: str | None = None) -> str | None:
        """Get API key for the given model."""
        provider = self.get_provider(model)
        return provider.api_key if provider else None

    def get_api_base(self, model: str | None = None) -> str | None:
        """Get API base URL for the given model."""
        from forensic_claw.providers.registry import find_by_name

        provider, name = self._match_provider(model)
        if provider and provider.api_base:
            return provider.api_base
        if name:
            spec = find_by_name(name)
            if spec and (spec.is_gateway or spec.is_local or spec.is_direct) and spec.default_api_base:
                return spec.default_api_base
        return None

    model_config = ConfigDict(env_prefix="FORENSIC_CLAW_", env_nested_delimiter="__")
