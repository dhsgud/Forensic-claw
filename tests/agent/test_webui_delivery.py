from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import GenerationSettings, LLMResponse


def _make_loop(tmp_path) -> tuple[AgentLoop, MessageBus, MagicMock]:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation = GenerationSettings(max_tokens=0)
    provider.chat_with_retry = AsyncMock(
        return_value=LLMResponse(
            content="<think>동기 thinking</think>동기 최종 답변",
            tool_calls=[],
            reasoning_content=None,
        )
    )

    async def _streaming_response(**kwargs):
        on_content_delta = kwargs.get("on_content_delta")
        if on_content_delta:
            await on_content_delta("<think>스트리밍 thinking</think>실시간 ")
            await on_content_delta("답변")
        return LLMResponse(
            content="<think>스트리밍 thinking</think>실시간 답변",
            tool_calls=[],
            reasoning_content=None,
        )

    provider.chat_stream_with_retry = AsyncMock(side_effect=_streaming_response)

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        model="test-model",
        enforce_response_language=True,
    )
    return loop, loop.bus, provider


@pytest.mark.asyncio
async def test_webui_streams_even_when_response_language_enforced(tmp_path) -> None:
    loop, bus, provider = _make_loop(tmp_path)

    msg = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="sess_123",
        content="안녕",
        metadata={"_wants_stream": True},
    )

    await loop._dispatch(msg)

    first = await bus.consume_outbound()
    second = await bus.consume_outbound()
    third = await bus.consume_outbound()
    end = await bus.consume_outbound()
    final = await bus.consume_outbound()

    assert first.metadata.get("_progress") is True
    assert first.content == "스트리밍 thinking"
    assert second.metadata.get("_stream_delta") is True
    assert second.content == "실시간"
    assert third.metadata.get("_stream_delta") is True
    assert third.content.strip() == "답변"
    assert end.metadata.get("_stream_end") is True
    assert final.content == "실시간 답변"
    assert final.metadata.get("_replace_stream_id")
    assert final.metadata.get("thinking_text") == "스트리밍 thinking"
    provider.chat_stream_with_retry.assert_awaited_once()


@pytest.mark.asyncio
async def test_non_webui_keeps_non_stream_path_when_language_enforced(tmp_path) -> None:
    loop, bus, provider = _make_loop(tmp_path)

    msg = InboundMessage(
        channel="discord",
        sender_id="user",
        chat_id="chan_1",
        content="안녕",
        metadata={"_wants_stream": True},
    )

    await loop._dispatch(msg)

    outbound = await bus.consume_outbound()
    assert outbound.content == "동기 최종 답변"
    assert outbound.metadata.get("_streamed") is not True
    assert outbound.metadata.get("thinking_text") == "동기 thinking"
    provider.chat_with_retry.assert_awaited_once()


@pytest.mark.asyncio
async def test_webui_streams_reasoning_delta_from_provider_field(tmp_path) -> None:
    loop, bus, provider = _make_loop(tmp_path)

    async def _streaming_reasoning_response(**kwargs):
        on_reasoning_delta = kwargs.get("on_reasoning_delta")
        on_content_delta = kwargs.get("on_content_delta")
        if on_reasoning_delta:
            await on_reasoning_delta("분석 1")
            await on_reasoning_delta(" + 분석 2")
        if on_content_delta:
            await on_content_delta("실시간 ")
            await on_content_delta("답변")
        return LLMResponse(
            content="실시간 답변",
            tool_calls=[],
            reasoning_content="분석 1 + 분석 2",
        )

    provider.chat_stream_with_retry = AsyncMock(side_effect=_streaming_reasoning_response)

    msg = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="sess_456",
        content="생각 보여줘",
        metadata={"_wants_stream": True},
    )

    await loop._dispatch(msg)

    first = await bus.consume_outbound()
    second = await bus.consume_outbound()
    third = await bus.consume_outbound()
    fourth = await bus.consume_outbound()
    end = await bus.consume_outbound()
    final = await bus.consume_outbound()

    assert first.metadata.get("_progress") is True
    assert first.content == "분석 1"
    assert second.metadata.get("_progress") is True
    assert second.content == " + 분석 2"
    assert third.metadata.get("_stream_delta") is True
    assert third.content == "실시간"
    assert fourth.metadata.get("_stream_delta") is True
    assert fourth.content == " 답변"
    assert end.metadata.get("_stream_end") is True
    assert final.content == "실시간 답변"
    assert final.metadata.get("thinking_text") == "분석 1 + 분석 2"
