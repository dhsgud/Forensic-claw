"""Provider construction helpers shared by CLI and runtime settings."""

from __future__ import annotations

from forensic_claw.config.schema import Config
from forensic_claw.providers.base import GenerationSettings, LLMProvider
from forensic_claw.providers.openai_compat_provider import OpenAICompatProvider
from forensic_claw.providers.registry import find_by_name


def create_provider(config: Config) -> LLMProvider:
    """Create the configured provider without doing network I/O."""
    model = config.agents.defaults.model
    provider_name = config.get_provider_name(model)
    provider_config = config.get_provider(model)
    spec = find_by_name(provider_name) if provider_name else None
    backend = spec.backend if spec else "openai_compat"

    if backend == "openai_compat":
        needs_key = not (provider_config and provider_config.api_key)
        exempt = spec and (spec.is_local or spec.is_direct)
        if needs_key and not exempt:
            raise ValueError("No API key configured for selected provider.")

    provider = OpenAICompatProvider(
        api_key=provider_config.api_key if provider_config else None,
        api_base=config.get_api_base(model),
        default_model=model,
        extra_headers=provider_config.extra_headers if provider_config else None,
        spec=spec,
    )

    defaults = config.agents.defaults
    provider.generation = GenerationSettings(
        temperature=defaults.temperature,
        max_tokens=defaults.max_tokens,
        reasoning_effort=defaults.reasoning_effort,
    )
    return provider
