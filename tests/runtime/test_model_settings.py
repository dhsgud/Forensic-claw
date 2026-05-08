from __future__ import annotations

import json
from typing import Any

import pytest

from forensic_claw.config.schema import Config
from forensic_claw.providers.base import LLMProvider, LLMResponse
from forensic_claw.runtime.model_settings import RuntimeModelSettings


class DummyProvider(LLMProvider):
    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        model: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        reasoning_effort: str | None = None,
        tool_choice: str | dict[str, Any] | None = None,
    ) -> LLMResponse:
        return LLMResponse(content="ok")

    def get_default_model(self) -> str:
        return "dummy"


@pytest.mark.asyncio
async def test_model_settings_updates_config_and_runtime_when_endpoint_changes(tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config = Config()
    applied: list[tuple[LLMProvider, str]] = []
    created: list[Config] = []

    def create_dummy_provider(next_config: Config) -> LLMProvider:
        created.append(next_config)
        return DummyProvider(api_base=next_config.get_api_base())

    service = RuntimeModelSettings(
        config,
        config_path=config_path,
        provider_factory=create_dummy_provider,
    )
    service.add_apply_callback(lambda provider, model: applied.append((provider, model)))

    snapshot = await service.apply(
        provider="ollama",
        model="qwen2.5:7b-instruct",
        api_base="127.0.0.1:11434",
        api_base_supplied=True,
    )

    saved = json.loads(config_path.read_text(encoding="utf-8"))
    assert snapshot["provider"] == "ollama"
    assert snapshot["model"] == "qwen2.5:7b-instruct"
    assert snapshot["apiBase"] == "http://127.0.0.1:11434/v1"
    assert config.agents.defaults.provider == "ollama"
    assert config.providers.ollama.api_base == "http://127.0.0.1:11434/v1"
    assert saved["agents"]["defaults"]["provider"] == "ollama"
    assert saved["providers"]["ollama"]["apiBase"] == "http://127.0.0.1:11434/v1"
    assert created[0].get_provider_name() == "ollama"
    assert len(applied) == 1
    assert applied[0][1] == "qwen2.5:7b-instruct"


def test_model_settings_snapshot_lists_local_windows_providers() -> None:
    service = RuntimeModelSettings(Config())

    provider_names = [item["name"] for item in service.snapshot()["availableProviders"]]

    assert "ollama" in provider_names
    assert "lmstudio" in provider_names


@pytest.mark.asyncio
async def test_model_settings_applies_saved_profile_to_runtime(tmp_path) -> None:
    config = Config()
    applied: list[str] = []

    def create_dummy_provider(next_config: Config) -> LLMProvider:
        return DummyProvider(api_base=next_config.get_api_base())

    service = RuntimeModelSettings(
        config,
        config_path=tmp_path / "config.json",
        provider_factory=create_dummy_provider,
    )
    service.add_apply_callback(lambda _provider, model: applied.append(model))

    await service.apply(
        provider="ollama",
        model="qwen2.5:7b-instruct",
        api_base="127.0.0.1:11434",
        api_base_supplied=True,
    )
    service.save_profile("windows-ollama")
    await service.apply(
        provider="lmstudio",
        model="local-test",
        api_base="127.0.0.1:1234",
        api_base_supplied=True,
    )

    snapshot = await service.use_profile("windows-ollama")

    assert snapshot["activeProfile"] == "windows-ollama"
    assert snapshot["provider"] == "ollama"
    assert snapshot["model"] == "qwen2.5:7b-instruct"
    assert snapshot["apiBase"] == "http://127.0.0.1:11434/v1"
    assert applied[-1] == "qwen2.5:7b-instruct"
