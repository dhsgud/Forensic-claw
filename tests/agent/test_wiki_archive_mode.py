from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import GenerationSettings, LLMResponse


def _make_loop(
    tmp_path: Path,
    *,
    archive_final_answer_as_wiki: bool,
    reset_session_after_answer: bool,
) -> AgentLoop:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation = GenerationSettings(max_tokens=256)
    provider.chat_with_retry = AsyncMock(
        return_value=LLMResponse(content="최종 답변", tool_calls=[])
    )
    provider.chat_stream_with_retry = AsyncMock(
        return_value=LLMResponse(content="최종 답변", tool_calls=[])
    )

    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path,
        model="test-model",
        enforce_response_language=False,
        archive_final_answer_as_wiki=archive_final_answer_as_wiki,
        reset_session_after_answer=reset_session_after_answer,
    )
    loop.tools.get_definitions = MagicMock(return_value=[])
    return loop


@pytest.mark.asyncio
async def test_archives_final_answer_and_clears_session_when_enabled(tmp_path: Path) -> None:
    loop = _make_loop(
        tmp_path,
        archive_final_answer_as_wiki=True,
        reset_session_after_answer=True,
    )

    response = await loop.process_direct("이 증거를 요약해줘", session_key="cli:test")

    assert response is not None
    assert response.content == "최종 답변"
    assert loop.sessions.get_or_create("cli:test").messages == []

    wiki_dir = tmp_path / "wiki" / "sessions" / "cli_test"
    files = list(wiki_dir.glob("*.md"))
    assert len(files) == 1

    saved = files[0].read_text(encoding="utf-8")
    assert "## Request" in saved
    assert "이 증거를 요약해줘" in saved
    assert "## Final Answer" in saved
    assert "최종 답변" in saved

    await loop.close_mcp()


@pytest.mark.asyncio
async def test_archives_final_answer_without_clearing_when_reset_disabled(tmp_path: Path) -> None:
    loop = _make_loop(
        tmp_path,
        archive_final_answer_as_wiki=True,
        reset_session_after_answer=False,
    )

    response = await loop.process_direct("prefetch 흔적 정리해줘", session_key="cli:test")

    assert response is not None
    assert response.content == "최종 답변"
    assert len(loop.sessions.get_or_create("cli:test").messages) == 2

    wiki_dir = tmp_path / "wiki" / "sessions" / "cli_test"
    files = list(wiki_dir.glob("*.md"))
    assert len(files) == 1

    await loop.close_mcp()


@pytest.mark.asyncio
async def test_archives_scoped_answer_under_case_artifact_tree(tmp_path: Path) -> None:
    loop = _make_loop(
        tmp_path,
        archive_final_answer_as_wiki=True,
        reset_session_after_answer=False,
    )

    response = await loop.process_direct(
        "artifact 단위로 정리해줘",
        channel="cli",
        chat_id="direct",
        case_id="Case Alpha",
        artifact_id="Prefetch #1",
    )

    assert response is not None
    scoped_key = "cli:direct:case:Case-Alpha:artifact:Prefetch-1"
    assert len(loop.sessions.get_or_create(scoped_key).messages) == 2

    wiki_dir = tmp_path / "wiki" / "cases" / "Case-Alpha" / "artifacts" / "Prefetch-1"
    files = list(wiki_dir.glob("*.md"))
    assert len(files) == 1

    saved = files[0].read_text(encoding="utf-8")
    assert 'case_id: "Case-Alpha"' in saved
    assert 'artifact_id: "Prefetch-1"' in saved

    await loop.close_mcp()
