import json

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.providers.base import GenerationSettings, LLMResponse, ToolCallRequest


class Provider:
    generation = GenerationSettings(max_tokens=0)

    def get_default_model(self):
        return "boundary-fake"

    async def chat_with_retry(self, **kwargs):
        return LLMResponse(
            content=json.dumps(
                {"claims": [{"text": "2027-01-01 malware executed", "evidence_ids": ["invented"]}]}
            )
        )


@pytest.mark.asyncio
async def test_attached_case_query_uses_user_question_instead_of_upload_metadata(tmp_path):
    class ExtractiveProvider(Provider):
        async def chat_with_retry(self, *, messages, **kwargs):
            hits = json.loads(messages[-1]["content"].split("\n", 1)[1])
            return LLMResponse(
                content=json.dumps(
                    {
                        "claims": [
                            {"text": hit["text"], "evidence_ids": [hit["evidenceId"]]}
                            for hit in hits
                        ]
                    }
                )
            )

    loop = AgentLoop(
        bus=MessageBus(),
        provider=ExtractiveProvider(),
        workspace=tmp_path,
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    source = tmp_path / "events.log"
    source.write_text("powershell.exe connected to 10.0.0.5", encoding="utf-8")
    loop.knowledge_service.ingest_path(source, case_name="case")
    message = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="one",
        content=" ".join(f"attachment_metadata_{i}" for i in range(100))
        + "\nUser Request:\npowershell",
        metadata={"case_id": "case", "user_query": "powershell"},
    )
    response = await loop._process_message(message)
    assert "PARTIAL" in response.content and "powershell.exe connected" in response.content
    await loop.close_mcp()


@pytest.mark.asyncio
async def test_case_analysis_blocks_invented_claim_before_streaming_or_persistence(tmp_path):
    loop = AgentLoop(
        bus=MessageBus(),
        provider=Provider(),
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    source = tmp_path / "log.txt"
    source.write_text("powershell.exe connected to 10.0.0.5", encoding="utf-8")
    loop.knowledge_service.ingest_path(source, case_name="case")
    streamed = []

    async def stream(text):
        streamed.append(text)

    msg = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="one",
        content="powershell 분석",
        metadata={"case_id": "case"},
    )
    result = await loop._process_message(msg, on_stream=stream)
    assert "FLAGGED" in result.content and "2027-01-01" not in result.content
    assert not streamed
    session = loop.sessions.get_or_create(msg.session_key)
    assert all(
        "2027-01-01" not in str(message.get("content", ""))
        for message in session.messages
        if message["role"] == "assistant"
    )
    await loop.close_mcp()


@pytest.mark.asyncio
async def test_case_analysis_rejects_evidence_changed_while_model_was_generating(tmp_path):
    class ChangingProvider(Provider):
        async def chat_with_retry(self, *, messages, **kwargs):
            from pathlib import Path

            hits = json.loads(messages[-1]["content"].split("\n", 1)[1])
            Path(hits[0]["sourcePath"]).write_text("tampered after retrieval", encoding="utf-8")
            return LLMResponse(
                content=json.dumps(
                    {"claims": [{"text": hits[0]["text"], "evidence_ids": [hits[0]["evidenceId"]]}]}
                )
            )

    loop = AgentLoop(
        bus=MessageBus(),
        provider=ChangingProvider(),
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    source = tmp_path / "log.txt"
    source.write_text("powershell.exe connected to 10.0.0.5", encoding="utf-8")
    loop.knowledge_service.ingest_path(source, case_name="case")
    result = await loop._process_message(
        InboundMessage(
            channel="webui",
            sender_id="user",
            chat_id="one",
            content="powershell 분석",
            metadata={"case_id": "case"},
        )
    )
    assert "PARTIAL" not in result.content and "VERIFIED" not in result.content.replace(
        "UNVERIFIED", ""
    )
    await loop.close_mcp()


@pytest.mark.asyncio
async def test_case_analysis_blocks_remote_provider_before_sending_evidence(tmp_path):
    class RemoteProvider(Provider):
        api_base = "https://example.org/v1"

        async def chat_with_retry(self, **kwargs):
            raise AssertionError("Remote endpoint must not receive evidence")

    loop = AgentLoop(
        bus=MessageBus(),
        provider=RemoteProvider(),
        workspace=tmp_path,
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    result = await loop._process_message(
        InboundMessage(
            channel="webui",
            sender_id="user",
            chat_id="one",
            content="사건 분석",
            metadata={"case_id": "case"},
        )
    )
    assert "외부 전송을 차단" in result.content
    await loop.close_mcp()


@pytest.mark.asyncio
async def test_evidence_memory_is_kept_local_when_provider_endpoint_is_remote(tmp_path):
    from forensic_claw.agent.memory import MemoryStore

    class RemoteProvider(Provider):
        api_base = "https://example.org/v1"

        def __init__(self):
            self.received = []

        async def chat_with_retry(self, **kwargs):
            self.received.extend(kwargs["messages"])
            return LLMResponse(content="")

    store = MemoryStore(tmp_path)
    provider = RemoteProvider()
    result = await store.consolidate(
        [{"role": "assistant", "content": "PARTIAL: sensitive evidence"}], provider, "test"
    )
    assert result is False
    assert provider.received == []
    assert not store.read_long_term()


@pytest.mark.asyncio
async def test_search_tool_keeps_case_scope_when_identity_is_only_in_session_key(tmp_path):
    class SearchingProvider(Provider):
        async def chat_with_retry(self, *, messages, **kwargs):
            if messages[-1]["role"] != "tool":
                return LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCallRequest(
                            id="search", name="knowledge_search", arguments={"query": "powershell"}
                        )
                    ],
                )
            hits = json.loads(messages[-1]["content"])["hits"]
            selected = next((hit for hit in hits if hit["metadata"]["caseId"] == "B"), hits[0])
            return LLMResponse(
                content=json.dumps(
                    {
                        "claims": [
                            {"text": selected["text"], "evidence_ids": [selected["evidenceId"]]}
                        ]
                    }
                )
            )

    loop = AgentLoop(
        bus=MessageBus(),
        provider=SearchingProvider(),
        workspace=tmp_path / "workspace",
        enforce_response_language=False,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    for case in ["A", "B"]:
        source = tmp_path / f"{case}.txt"
        source.write_text(f"powershell marker-{case}", encoding="utf-8")
        loop.knowledge_service.ingest_path(source, case_name=case)
    result = await loop._process_message(
        InboundMessage(
            channel="webui",
            sender_id="user",
            chat_id="one",
            content="powershell 분석",
            session_key_override="webui:one:case:A",
        )
    )
    assert "marker-A" in result.content and "marker-B" not in result.content
    await loop.close_mcp()
