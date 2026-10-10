from __future__ import annotations

import asyncio

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.agent.subagent import SubagentManager
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import GenerationSettings, LLMResponse


class _Provider:
    generation = GenerationSettings(max_tokens=0)

    def get_default_model(self):
        return "test-model"

    async def chat_with_retry(self, **kwargs):
        return LLMResponse(content="분석이 완료되었습니다.", tool_calls=[])


@pytest.mark.asyncio
async def test_large_system_log_request_auto_backgrounds(tmp_path) -> None:
    provider = _Provider()

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        enforce_response_language=False,
    )

    msg = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="sess_123",
        content="내 컴퓨터 시스템 로그 분석해줘",
        metadata={"case_id": "case-2026-0001", "artifact_id": "EVD-001"},
    )

    response = await loop._process_message(msg)

    assert response is not None
    assert "백그라운드" in response.content
    completed = await loop.bus.consume_inbound()
    assert completed.session_key == msg.session_key
    assert completed.metadata["case_id"] == "case-2026-0001"
    assert completed.metadata["artifact_id"] == "EVD-001"
    assert completed.metadata["trust_checked"] is True

    session = loop.sessions.get_or_create(msg.session_key)
    assert session.messages[0]["role"] == "user"
    assert session.messages[0]["content"] == msg.content
    assert session.messages[1]["role"] == "assistant"
    assert "같은 scope" in session.messages[1]["content"]

    await asyncio.gather(*loop._background_tasks, return_exceptions=True)


@pytest.mark.asyncio
async def test_subagent_announcement_preserves_scope_metadata(tmp_path) -> None:
    bus = MessageBus()
    provider = _Provider()
    mgr = SubagentManager(provider=provider, workspace=tmp_path, bus=bus)

    await mgr._announce_result(
        "sub-1",
        "large-log-analysis",
        "task",
        "done",
        {"channel": "webui", "chat_id": "sess_123"},
        "ok",
        session_key="webui:sess_123:case:case-2026-0001:artifact:EVD-001",
        metadata={"case_id": "case-2026-0001", "artifact_id": "EVD-001"},
    )

    inbound = await asyncio.wait_for(bus.consume_inbound(), timeout=1.0)
    assert inbound.channel == "system"
    assert inbound.session_key == "webui:sess_123:case:case-2026-0001:artifact:EVD-001"
    assert inbound.metadata["case_id"] == "case-2026-0001"
    assert inbound.metadata["artifact_id"] == "EVD-001"


@pytest.mark.asyncio
async def test_system_message_uses_session_key_override_for_persistence(tmp_path) -> None:
    provider = _Provider()

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        enforce_response_language=False,
    )

    msg = InboundMessage(
        channel="system",
        sender_id="subagent",
        chat_id="webui:sess_123",
        content="background result",
        session_key_override="webui:sess_123:case:case-2026-0001:artifact:EVD-001",
        metadata={"case_id": "case-2026-0001", "artifact_id": "EVD-001"},
    )

    response = await loop._process_message(msg)

    assert response is not None
    assert response.chat_id == "sess_123"
    session = loop.sessions.get_or_create("webui:sess_123:case:case-2026-0001:artifact:EVD-001")
    assert session.messages[-1]["content"] == response.content
    assert "background result" not in response.content

    await asyncio.gather(*loop._background_tasks, return_exceptions=True)
