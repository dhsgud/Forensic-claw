from __future__ import annotations

from types import SimpleNamespace

import pytest

from forensic_claw.bus.events import InboundMessage
from forensic_claw.command.builtin import cmd_model
from forensic_claw.command.router import CommandContext


class FakeModelSettings:
    def __init__(self) -> None:
        self.applied: list[dict] = []
        self.saved_profiles: list[str] = []

    def snapshot(self) -> dict:
        return {
            "provider": "custom",
            "providerLabel": "Custom",
            "model": "local-model",
            "apiBase": "http://127.0.0.1:1234/v1",
            "availableProviders": [{"name": "custom"}, {"name": "ollama"}],
            "profiles": [{"name": name} for name in self.saved_profiles],
        }

    async def apply(self, **kwargs) -> dict:
        self.applied.append(kwargs)
        snapshot = self.snapshot()
        if kwargs.get("api_base"):
            snapshot["apiBase"] = kwargs["api_base"]
        if kwargs.get("model"):
            snapshot["model"] = kwargs["model"]
        if kwargs.get("provider"):
            snapshot["provider"] = kwargs["provider"]
        return snapshot

    async def test_connection(self, **kwargs) -> dict:
        return {
            "ok": True,
            "apiBase": kwargs.get("api_base") or "http://127.0.0.1:1234/v1",
            "status": 200,
            "models": ["local-model"],
        }

    def save_profile(self, name: str) -> dict:
        self.saved_profiles.append(name)
        return self.snapshot()

    async def use_profile(self, name: str) -> dict:
        self.applied.append({"profile": name})
        return self.snapshot()


def _ctx(args: str, service: FakeModelSettings) -> CommandContext:
    return CommandContext(
        msg=InboundMessage(
            channel="discord",
            sender_id="user-1",
            chat_id="chan-1",
            content=f"/model {args}".strip(),
        ),
        session=None,
        key="discord:chan-1",
        raw=f"/model {args}".strip(),
        args=args,
        loop=SimpleNamespace(model_settings=service),
    )


@pytest.mark.asyncio
async def test_model_command_returns_runtime_status_when_no_arguments() -> None:
    service = FakeModelSettings()

    response = await cmd_model(_ctx("", service))

    assert "provider: custom" in response.content
    assert "apiBase: http://127.0.0.1:1234/v1" in response.content


@pytest.mark.asyncio
async def test_model_command_updates_api_base_when_set_argument_is_used() -> None:
    service = FakeModelSettings()

    response = await cmd_model(_ctx("set apiBase http://127.0.0.1:11434/v1", service))

    assert service.applied == [
        {"api_base": "http://127.0.0.1:11434/v1", "api_base_supplied": True}
    ]
    assert "Model settings updated" in response.content


@pytest.mark.asyncio
async def test_model_command_tests_endpoint_when_test_argument_is_used() -> None:
    service = FakeModelSettings()

    response = await cmd_model(_ctx("test", service))

    assert "Model endpoint test ok" in response.content
    assert "local-model" in response.content


@pytest.mark.asyncio
async def test_model_command_saves_profile_when_profile_save_is_used() -> None:
    service = FakeModelSettings()

    response = await cmd_model(_ctx("profile save lab-pc", service))

    assert service.saved_profiles == ["lab-pc"]
    assert "Model profile saved" in response.content
