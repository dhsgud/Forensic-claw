from __future__ import annotations

import json

import pytest

from forensic_claw.agent.tools.knowledge import KnowledgeIngestTool, KnowledgeSearchTool
from forensic_claw.config.schema import KnowledgeConfig
from forensic_claw.knowledge.service import KnowledgeService


@pytest.mark.asyncio
async def test_knowledge_ingest_tool_returns_ready_when_log_is_indexed(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("cmd.exe contacted 192.168.1.10\n", encoding="utf-8")
    service = KnowledgeService(
        tmp_path,
        KnowledgeConfig(neo4j={"enabled": False}, chunk_chars=1000, chunk_overlap_chars=0),
    )
    tool = KnowledgeIngestTool(service, workspace=tmp_path, allowed_dir=tmp_path)

    result = await tool.execute(path="events.log", case_name="Case Tool")

    assert "Knowledge ingest ready." in result
    assert "ingestedFiles: 1" in result


@pytest.mark.asyncio
async def test_knowledge_search_tool_returns_indexed_chunks_and_graph_hits(tmp_path):
    log = tmp_path / "events.log"
    log.write_text("chrome.exe opened https://example.org/path\n", encoding="utf-8")
    service = KnowledgeService(
        tmp_path,
        KnowledgeConfig(neo4j={"enabled": False}, chunk_chars=1000, chunk_overlap_chars=0),
    )
    service.ingest_path(log)
    tool = KnowledgeSearchTool(service, workspace=tmp_path)

    result = json.loads(await tool.execute(query="example.org"))

    assert result["hits"]
    assert "example.org" in result["hits"][0]["text"]
    assert any(item["value"] == "example.org" for item in result["graph"])
