from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.config.schema import KnowledgeConfig
from forensic_claw.providers.base import GenerationSettings, LLMResponse


def _write_chrome_history(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER
            );
            """
        )
        chrome_time = int(
            (
                datetime(2026, 5, 7, tzinfo=UTC)
                - datetime(1601, 1, 1, tzinfo=UTC)
            ).total_seconds()
            * 1_000_000
        )
        conn.execute(
            "INSERT INTO urls VALUES (?, ?, ?, ?, ?)",
            (1, "https://example.com/search?q=malware", "Example Search", 3, chrome_time),
        )
        conn.execute("INSERT INTO visits VALUES (?, ?, ?, ?, ?)", (1, 1, chrome_time, 0, 0))


@pytest.mark.asyncio
async def test_chrome_history_request_prepares_knowledge_before_llm_answer(tmp_path, monkeypatch):
    history = tmp_path / "Google" / "Chrome" / "User Data" / "Default" / "History"
    _write_chrome_history(history)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation = GenerationSettings(max_tokens=0)
    provider.chat_with_retry = AsyncMock(
        return_value=LLMResponse(content="Chrome History 준비가 끝났습니다.", tool_calls=[])
    )
    loop = AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(
            chunk_chars=1000,
            chunk_overlap_chars=0,
        ),
    )
    msg = InboundMessage(
        channel="cli",
        sender_id="user",
        chat_id="direct",
        content="크롬 DB 조사해줘",
        metadata={"case_name": "Case Alpha", "investigator_name": "Investigator One"},
    )

    response = await loop._process_message(msg)

    assert response is not None
    assert response.content == "Chrome History 준비가 끝났습니다."
    assert loop.knowledge_service is not None
    assert loop.knowledge_service.status()["store"]["documents"] == 1
    prompt_payloads = [
        json.dumps(call.kwargs["messages"], ensure_ascii=False)
        for call in provider.chat_with_retry.await_args_list
        if call.kwargs.get("messages")
    ]
    assert any("Auto Knowledge Preparation" in payload for payload in prompt_payloads)
    assert any("Knowledge ingest ready" in payload for payload in prompt_payloads)
