from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from forensic_claw.bus.events import InboundMessage
from forensic_claw.command.builtin import cmd_new
from forensic_claw.command.router import CommandContext
from forensic_claw.session.manager import SessionManager


@pytest.mark.asyncio
async def test_cmd_new_flags_webui_browser_session_reset(tmp_path: Path) -> None:
    session_manager = SessionManager(tmp_path)
    session = session_manager.get_or_create("webui:sess_abc")
    session.add_message("user", "hello")
    session_manager.save(session)

    archive_messages = AsyncMock()
    scheduled: list[object] = []

    loop = SimpleNamespace(
        sessions=session_manager,
        memory_consolidator=SimpleNamespace(archive_messages=archive_messages),
        _schedule_background=scheduled.append,
    )
    msg = InboundMessage(channel="webui", sender_id="user", chat_id="sess_abc", content="/new")
    ctx = CommandContext(msg=msg, session=session, key=session.key, raw="/new", loop=loop)

    outbound = await cmd_new(ctx)

    assert outbound.metadata["webui_reset_browser_session"] is True
    assert session_manager.get_or_create(session.key).messages == []
    assert len(scheduled) == 1

    for task in scheduled:
        task.close()


@pytest.mark.asyncio
async def test_cmd_new_does_not_flag_non_webui_channels(tmp_path: Path) -> None:
    session_manager = SessionManager(tmp_path)
    session = session_manager.get_or_create("cli:test")
    session.add_message("user", "hello")
    session_manager.save(session)

    archive_messages = AsyncMock()
    scheduled: list[object] = []

    loop = SimpleNamespace(
        sessions=session_manager,
        memory_consolidator=SimpleNamespace(archive_messages=archive_messages),
        _schedule_background=scheduled.append,
    )
    msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
    ctx = CommandContext(msg=msg, session=session, key=session.key, raw="/new", loop=loop)

    outbound = await cmd_new(ctx)

    assert "webui_reset_browser_session" not in outbound.metadata

    for task in scheduled:
        task.close()
