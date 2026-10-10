import json

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.providers.base import GenerationSettings, LLMResponse, ToolCallRequest


class CollectionProvider:
    """LLM boundary fake; collection, case storage and validation remain real."""

    generation = GenerationSettings(max_tokens=0)

    def __init__(self, source, *, premature=False):
        self.source = source
        self.premature = premature

    def get_default_model(self):
        return "collection-boundary"

    async def chat_with_retry(self, *, messages, **kwargs):
        hits = []
        for message in messages:
            content = message.get("content") or ""
            if content.startswith("[검증된 사건 근거 JSON]\n"):
                hits = json.loads(content.split("\n", 1)[1])
        if hits:
            return LLMResponse(
                content=json.dumps(
                    {"claims": [{"text": hits[0]["text"], "evidence_ids": [hits[0]["evidenceId"]]}]}
                )
            )
        if self.premature:
            self.premature = False
            return LLMResponse(content='{"claims":[]}')
        return LLMResponse(
            content="",
            tool_calls=[
                ToolCallRequest(
                    id="collect", name="knowledge_ingest", arguments={"path": str(self.source)}
                )
            ],
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("premature", [False, True])
async def test_unattached_question_collects_and_cites_local_source_in_same_answer(
    tmp_path, premature
):
    source = tmp_path / "events.log"
    original = "powershell.exe PID=7420 network connection observed\n"
    source.write_text(original, encoding="utf-8")
    loop = AgentLoop(
        bus=MessageBus(),
        provider=CollectionProvider(source, premature=premature),
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
        max_iterations=5,
    )
    try:
        message = InboundMessage(
            channel="webui",
            sender_id="user",
            chat_id="one",
            content="powershell 분석",
            metadata={"case_id": "auto-case"},
        )
        response = await loop._process_message(message)
        assert "PARTIAL" in response.content and "PID=7420" in response.content
        assert source.read_text(encoding="utf-8") == original
        hits = loop.knowledge_service.search("powershell", case_id="auto-case")["hits"]
        assert hits and all(hit["metadata"]["caseId"] == "auto-case" for hit in hits)
    finally:
        await loop.close_mcp()


@pytest.mark.asyncio
async def test_background_investigation_cites_newly_collected_case_evidence(tmp_path):
    source = tmp_path / "events.log"
    source.write_text("powershell.exe PID=7420 network connection observed", encoding="utf-8")
    bus = MessageBus()
    loop = AgentLoop(
        bus=bus,
        provider=CollectionProvider(source),
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    try:
        await loop.subagents._run_subagent(
            "collection-test",
            "powershell 분석",
            "collection",
            {"channel": "webui", "chat_id": "one"},
            session_key="webui:one:case:auto-case",
            metadata={"case_id": "auto-case"},
        )
        result = await bus.consume_inbound()
        assert "PARTIAL" in result.content and "PID=7420" in result.content
        assert result.metadata["trust_checked"] is True
    finally:
        await loop.close_mcp()
