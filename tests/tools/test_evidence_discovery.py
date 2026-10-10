import json
import sqlite3

import pytest

from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.knowledge.service import KnowledgeService


@pytest.mark.asyncio
@pytest.mark.parametrize("restricted", [False, True])
async def test_discovery_finds_local_history_without_reading_or_modifying_evidence(
    tmp_path, monkeypatch, restricted
):
    from forensic_claw.agent.tools.knowledge import KnowledgeDiscoverTool

    history = tmp_path / "Google/Chrome/User Data/Default/History"
    history.parent.mkdir(parents=True)
    with sqlite3.connect(history) as connection:
        connection.executescript("CREATE TABLE urls(id INTEGER); CREATE TABLE visits(id INTEGER);")
    original = history.read_bytes()
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    tool = KnowledgeDiscoverTool(
        service, workspace=service.workspace, allowed_dir=service.workspace if restricted else None
    )
    result = json.loads(await tool.execute(source="chrome_history"))
    assert (str(history.resolve()) in result["candidates"]) is not restricted
    assert history.read_bytes() == original
    assert service.status()["store"]["documents"] == 0


@pytest.mark.asyncio
async def test_discovery_respects_workspace_restriction_for_external_event_logs(
    tmp_path, monkeypatch
):
    from forensic_claw.agent.tools.knowledge import KnowledgeDiscoverTool

    event = tmp_path / "Windows/System32/winevt/Logs/System.evtx"
    event.parent.mkdir(parents=True)
    event.write_bytes(b"synthetic event log")
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))
    workspace = tmp_path / "workspace"
    service = KnowledgeService(workspace, KnowledgeConfig(vector=VectorConfig(enabled=False)))
    result = json.loads(
        await KnowledgeDiscoverTool(service, workspace=workspace, allowed_dir=workspace).execute(
            source="windows_events"
        )
    )
    assert result["candidates"] == []
    assert list(result["locations"].values()) == [str(workspace.resolve())]
