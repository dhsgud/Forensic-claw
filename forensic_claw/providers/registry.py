"""Single source of truth for supported LLM provider metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic.alias_generators import to_snake


@dataclass(frozen=True)
class ProviderSpec:
    """Metadata for one configured provider."""

    name: str
    keywords: tuple[str, ...]
    env_key: str
    display_name: str = ""
    backend: str = "openai_compat"
    env_extras: tuple[tuple[str, str], ...] = ()
    is_gateway: bool = False
    is_local: bool = False
    detect_by_key_prefix: str = ""
    detect_by_base_keyword: str = ""
    default_api_base: str = ""
    strip_model_prefix: bool = False
    model_overrides: tuple[tuple[str, dict[str, Any]], ...] = ()
    is_oauth: bool = False
    is_direct: bool = False
    supports_prompt_caching: bool = False

    @property
    def label(self) -> str:
        return self.display_name or self.name.title()


PROVIDERS: tuple[ProviderSpec, ...] = (
    ProviderSpec(
        name="custom",
        keywords=(),
        env_key="",
        display_name="Custom (llama.cpp)",
        backend="openai_compat",
        is_direct=True,
    ),
    ProviderSpec(
        name="vllm",
        keywords=("vllm",),
        env_key="HOSTED_VLLM_API_KEY",
        display_name="vLLM/Local",
        backend="openai_compat",
        is_local=True,
        default_api_base="http://localhost:8000/v1",
    ),
)


def find_by_name(name: str) -> ProviderSpec | None:
    """Find a provider spec by config field name."""
    normalized = to_snake(name.replace("-", "_"))
    for spec in PROVIDERS:
        if spec.name == normalized:
            return spec
    return None
