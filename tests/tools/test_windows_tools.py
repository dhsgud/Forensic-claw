from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.agent.tools.windows import (
    WindowsAmcacheAnalyzeTool,
    WindowsEventLogQueryTool,
    WindowsPrefetchAnalyzeTool,
    WindowsTimelineBuildTool,
)
from forensic_claw.bus.queue import MessageBus
from forensic_claw.forensics import CaseStore


@pytest.mark.asyncio
async def test_windows_tools_execute_and_update_case_store(tmp_path: Path) -> None:
    fixtures_root = Path(__file__).resolve().parents[1] / "fixtures" / "windows"
    eventlog_text = (fixtures_root / "evtx" / "security_4688.txt").read_text(encoding="utf-8")
    prefetch_path = fixtures_root / "prefetch" / "CALC.EXE-TEST.pf"
    amcache_path = fixtures_root / "amcache" / "Amcache.hve"

    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    async def fake_runner(**kwargs):
        assert kwargs["log_name"] == "Security"
        return eventlog_text

    eventlog_tool = WindowsEventLogQueryTool(workspace=tmp_path, query_runner=fake_runner)
    prefetch_tool = WindowsPrefetchAnalyzeTool(workspace=tmp_path)
    amcache_tool = WindowsAmcacheAnalyzeTool(workspace=tmp_path)
    timeline_tool = WindowsTimelineBuildTool(workspace=tmp_path)

    result = await eventlog_tool.execute(case_id=case.id, log_name="Security", event_ids=[4688])
    assert "timeline_entries=2" in result

    result = await prefetch_tool.execute(case_id=case.id, prefetch_path=str(prefetch_path))
    assert "timeline_entries=2" in result

    result = await amcache_tool.execute(case_id=case.id, hive_path=str(amcache_path))
    assert "timeline_entries=2" in result

    result = await timeline_tool.execute(case_id=case.id, merge_strategy="chronological")
    assert "entries=6" in result

    final_store = CaseStore(tmp_path)
    assert len(final_store.read_timeline(case.id)) == 6
    assert len(final_store.read_graph(case.id).report_sections) >= 4


def test_agent_loop_registers_windows_artifact_tools(tmp_path: Path) -> None:
    bus = MessageBus()
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"

    loop = AgentLoop(
        bus=bus,
        provider=provider,
        workspace=tmp_path,
        model="test-model",
    )

    assert isinstance(loop.tools.get("windows_eventlog_query"), WindowsEventLogQueryTool)
    assert isinstance(loop.tools.get("windows_prefetch_analyze"), WindowsPrefetchAnalyzeTool)
    assert isinstance(loop.tools.get("windows_amcache_analyze"), WindowsAmcacheAnalyzeTool)
    assert isinstance(loop.tools.get("windows_timeline_build"), WindowsTimelineBuildTool)
