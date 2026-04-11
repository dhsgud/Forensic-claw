"""Focused tests for the reduced channel set and manager behavior."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.base import BaseChannel
from forensic_claw.channels.manager import ChannelManager
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.config.schema import ChannelsConfig


class _FakePlugin(BaseChannel):
    name = "fakeplugin"
    display_name = "Fake Plugin"

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    async def send(self, msg: OutboundMessage) -> None:
        return None


def _make_entry_point(name: str, cls: type):
    return SimpleNamespace(name=name, load=lambda _cls=cls: _cls)


def test_discover_all_includes_supported_builtins():
    from forensic_claw.channels.registry import discover_all

    with patch("importlib.metadata.entry_points", return_value=[]):
        result = discover_all()

    assert "discord" in result
    assert "kakaotalk" in result
    assert "webui" in result


@pytest.mark.asyncio
async def test_manager_loads_plugin_from_dict_config():
    fake_config = SimpleNamespace(
        channels=ChannelsConfig.model_validate(
            {
                "fakeplugin": {"enabled": True, "allowFrom": ["*"]},
            }
        ),
    )

    with patch("forensic_claw.channels.registry.discover_all", return_value={"fakeplugin": _FakePlugin}):
        mgr = ChannelManager.__new__(ChannelManager)
        mgr.config = fake_config
        mgr.bus = MessageBus()
        mgr.channels = {}
        mgr._dispatch_task = None
        mgr._init_channels()

    assert "fakeplugin" in mgr.channels
    assert isinstance(mgr.channels["fakeplugin"], _FakePlugin)


@pytest.mark.asyncio
async def test_manager_auto_enables_webui_without_config_section():
    fake_config = SimpleNamespace(channels=ChannelsConfig())

    with patch("forensic_claw.channels.registry.discover_all", return_value={"webui": WebUIChannel}):
        mgr = ChannelManager.__new__(ChannelManager)
        mgr.config = fake_config
        mgr.bus = MessageBus()
        mgr.session_manager = None
        mgr.channels = {}
        mgr._dispatch_task = None
        mgr._init_channels()

    assert "webui" in mgr.channels
    assert isinstance(mgr.channels["webui"], WebUIChannel)


@pytest.mark.asyncio
async def test_send_with_retry_retries_on_failure():
    call_count = 0

    class _FailingChannel(BaseChannel):
        name = "failing"
        display_name = "Failing"

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

        async def send(self, msg: OutboundMessage) -> None:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("simulated failure")

    fake_config = SimpleNamespace(channels=ChannelsConfig(send_max_retries=3))

    mgr = ChannelManager.__new__(ChannelManager)
    mgr.config = fake_config
    mgr.bus = MessageBus()
    mgr.channels = {"failing": _FailingChannel(fake_config, mgr.bus)}
    mgr._dispatch_task = None

    msg = OutboundMessage(channel="failing", chat_id="123", content="test")

    with patch("forensic_claw.channels.manager.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
        await mgr._send_with_retry(mgr.channels["failing"], msg)

    assert call_count == 3
    assert mock_sleep.call_count == 2


@pytest.mark.asyncio
async def test_stop_all_cancels_dispatcher_and_stops_channels():
    class _StartableChannel(BaseChannel):
        name = "startable"
        display_name = "Startable"

        def __init__(self, config, bus):
            super().__init__(config, bus)
            self.stopped = False

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            self.stopped = True

        async def send(self, msg: OutboundMessage) -> None:
            return None

    fake_config = SimpleNamespace(channels=ChannelsConfig())

    mgr = ChannelManager.__new__(ChannelManager)
    mgr.config = fake_config
    mgr.bus = MessageBus()
    ch = _StartableChannel(fake_config, mgr.bus)
    mgr.channels = {"startable": ch}

    async def dummy_task():
        while True:
            await asyncio.sleep(1)

    dispatch_task = asyncio.create_task(dummy_task())
    mgr._dispatch_task = dispatch_task

    await mgr.stop_all()

    assert dispatch_task.cancelled()
    assert ch.stopped is True
