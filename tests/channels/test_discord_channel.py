from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

import forensic_claw.channels.discord as discord_module
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.discord import DiscordChannel


@pytest.mark.parametrize("mention", ["<@bot-1>", "<@!bot-1>"])
@pytest.mark.asyncio
async def test_handle_message_create_strips_leading_bot_mention_for_commands(mention: str) -> None:
    channel = DiscordChannel({"enabled": True, "allowFrom": ["*"]}, MessageBus())
    channel._bot_user_id = "bot-1"
    channel._start_typing = AsyncMock()
    channel._handle_message = AsyncMock()

    await channel._handle_message_create(
        {
            "id": "msg-1",
            "author": {"id": "user-1", "bot": False},
            "channel_id": "chan-1",
            "guild_id": "guild-1",
            "content": f"{mention}   /reset",
            "mentions": [{"id": "bot-1"}],
            "attachments": [],
        }
    )

    channel._handle_message.assert_awaited_once()
    assert channel._handle_message.await_args.kwargs["content"] == "/reset"


class _FailingConnect:
    async def __aenter__(self):
        raise RuntimeError("Authentication failed")

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


class _FakeWebSocket:
    def __init__(self, messages: list[str]) -> None:
        self._messages = list(messages)
        self.sent: list[str] = []

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    async def close(self) -> None:
        return None


class _SuccessfulConnect:
    def __init__(self, ws: _FakeWebSocket) -> None:
        self._ws = ws

    async def __aenter__(self) -> _FakeWebSocket:
        return self._ws

    async def __aexit__(self, exc_type, exc, tb) -> bool:
        return False


@pytest.mark.asyncio
async def test_start_stops_after_five_failed_connect_attempts(monkeypatch: pytest.MonkeyPatch) -> None:
    channel = DiscordChannel(
        {"enabled": True, "allowFrom": ["*"], "token": "test-token"},
        MessageBus(),
    )
    sleep_calls: list[int] = []
    connect_calls = 0

    async def fake_sleep(delay: int) -> None:
        sleep_calls.append(delay)

    def fake_connect(url: str) -> _FailingConnect:
        nonlocal connect_calls
        connect_calls += 1
        return _FailingConnect()

    monkeypatch.setattr(discord_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(discord_module.websockets, "connect", fake_connect)

    await channel.start()

    assert connect_calls == 5
    assert sleep_calls == [5, 5, 5, 5]
    assert channel.is_running is False
    assert channel._http is None


@pytest.mark.asyncio
async def test_start_resets_failed_attempts_after_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    channel = DiscordChannel(
        {
            "enabled": True,
            "allowFrom": ["*"],
            "token": "test-token",
            "maxConnectAttempts": 2,
        },
        MessageBus(),
    )
    sleep_calls: list[int] = []
    connect_attempts = [
        _SuccessfulConnect(
            _FakeWebSocket(
                [
                    json.dumps({"op": 10, "d": {"heartbeat_interval": 45_000}}),
                    json.dumps(
                        {
                            "op": 0,
                            "t": "READY",
                            "s": 1,
                            "d": {"user": {"id": "bot-1"}},
                        }
                    ),
                ]
            )
        ),
        _FailingConnect(),
        _FailingConnect(),
    ]

    async def fake_sleep(delay: int) -> None:
        sleep_calls.append(delay)

    def fake_connect(url: str):
        return connect_attempts.pop(0)

    channel._start_heartbeat = AsyncMock()

    monkeypatch.setattr(discord_module.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(discord_module.websockets, "connect", fake_connect)

    await channel.start()

    assert connect_attempts == []
    assert sleep_calls == [5, 5]
    assert channel.is_running is False
