from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import GenerationSettings
from forensic_claw.session.manager import Session


def _make_loop(tmp_path, *, auto_session_fork: bool = True) -> AgentLoop:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation = GenerationSettings(max_tokens=0)
    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        auto_session_fork=auto_session_fork,
    )
    # No embedder configured in tests → relatedness uses the lexical fallback.
    loop.memory_consolidator.consolidate_messages = AsyncMock(return_value=True)
    loop.sessions.save = MagicMock()
    return loop


def _session_with_topic(text: str, *, count: int) -> Session:
    s = Session(key="cli:direct")
    s.add_message("user", text)
    s.add_message("assistant", "ok")
    s.consolidation_count = count
    return s


def test_lexical_and_cosine_helpers():
    assert AgentLoop._lexical_overlap("alpha beta gamma", "alpha beta delta") > 0.3
    assert AgentLoop._lexical_overlap("alpha beta", "totally different words") == 0.0
    assert AgentLoop._cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert AgentLoop._cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_recent_user_text_collects_last_questions():
    s = Session(key="cli:direct")
    s.add_message("user", "first")
    s.add_message("assistant", "a")
    s.add_message("user", "second")
    assert AgentLoop._recent_user_text(s) == "first second"


@pytest.mark.asyncio
async def test_no_fork_when_not_enough_pressure(tmp_path):
    loop = _make_loop(tmp_path)
    s = _session_with_topic("analyze the chrome browsing history for malware", count=1)
    forked = await loop._maybe_fork_unrelated_session(s, "what about the registry hives now")
    assert forked is False
    assert s.messages  # untouched


@pytest.mark.asyncio
async def test_no_fork_when_topic_related(tmp_path):
    loop = _make_loop(tmp_path)
    s = _session_with_topic("analyze the chrome browsing history for malware", count=3)
    forked = await loop._maybe_fork_unrelated_session(
        s, "continue analyzing the chrome browsing history malware findings"
    )
    assert forked is False
    assert s.messages


@pytest.mark.asyncio
async def test_fork_when_unrelated_and_pressured(tmp_path):
    loop = _make_loop(tmp_path)
    s = _session_with_topic("analyze the chrome browsing history for malware", count=3)
    forked = await loop._maybe_fork_unrelated_session(
        s, "translate this poem about ocean sunsets into french"
    )
    assert forked is True
    assert s.messages == []  # session cleared for the fresh topic
    assert s.consolidation_count == 0
    loop.memory_consolidator.consolidate_messages.assert_awaited()


@pytest.mark.asyncio
async def test_disabled_flag_never_forks(tmp_path):
    loop = _make_loop(tmp_path, auto_session_fork=False)
    s = _session_with_topic("analyze the chrome browsing history for malware", count=9)
    forked = await loop._maybe_fork_unrelated_session(s, "totally unrelated cooking recipe")
    assert forked is False
    assert s.messages
