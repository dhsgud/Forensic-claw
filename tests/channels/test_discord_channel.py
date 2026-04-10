from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

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
