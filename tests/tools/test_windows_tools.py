from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.agent.tools.shell import CommandCapture, ExecTool
from forensic_claw.agent.tools.windows import (
    WindowsAmcacheAnalyzeTool,
    WindowsEventLogQueryTool,
    WindowsPrefetchAnalyzeTool,
    WindowsTimelineBuildTool,
)
from forensic_claw.bus.queue import MessageBus
from forensic_claw.forensics import CaseStore


@pytest.mark.asyncio
async def test_windows_tools_execute_and_update_case_store(
    tmp_path: Path,
    prefetch_pecmd_runner,
) -> None:
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
    prefetch_tool = WindowsPrefetchAnalyzeTool(workspace=tmp_path, runner=prefetch_pecmd_runner)
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


@pytest.mark.asyncio
async def test_windows_prefetch_tool_accepts_directory_input_and_limits_recent_files(
    tmp_path: Path,
    prefetch_pecmd_runner,
) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "windows"
        / "prefetch"
        / "CALC.EXE-TEST.pf"
    )
    prefetch_dir = tmp_path / "prefetch"
    prefetch_dir.mkdir()

    for index, name in enumerate(
        (
            "OLDAPP.EXE-11111111.pf",
            "MIDAPP.EXE-22222222.pf",
            "NEWAPP.EXE-33333333.pf",
        )
    ):
        path = prefetch_dir / name
        path.write_bytes(fixture_path.read_bytes())
        ts = 1_700_000_000 + index
        os.utime(path, (ts, ts))

    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0002", title="Prefetch directory case")
    prefetch_tool = WindowsPrefetchAnalyzeTool(workspace=tmp_path, runner=prefetch_pecmd_runner)

    result = await prefetch_tool.execute(
        case_id=case.id,
        prefetch_path=str(prefetch_dir),
        max_files=2,
    )

    assert "files=2" in result
    assert "NEWAPP.EXE-33333333.pf" in result
    assert "MIDAPP.EXE-22222222.pf" in result
    assert "OLDAPP.EXE-11111111.pf" not in result

    final_store = CaseStore(tmp_path)
    assert len(final_store.list_evidence_ids(case.id)) == 2
    assert len(final_store.read_timeline(case.id)) == 4


@pytest.mark.asyncio
async def test_windows_prefetch_tool_uses_exec_fallback_for_inaccessible_directory(
    tmp_path: Path,
    prefetch_pecmd_runner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "windows"
        / "prefetch"
        / "CALC.EXE-TEST.pf"
    )
    prefetch_dir = tmp_path / "prefetch"
    prefetch_dir.mkdir()

    created: list[Path] = []
    for index, name in enumerate(
        (
            "OLDAPP.EXE-11111111.pf",
            "MIDAPP.EXE-22222222.pf",
            "NEWAPP.EXE-33333333.pf",
        )
    ):
        path = prefetch_dir / name
        path.write_bytes(fixture_path.read_bytes())
        ts = 1_700_000_000 + index
        os.utime(path, (ts, ts))
        created.append(path)

    original_glob = Path.glob
    original_iterdir = Path.iterdir

    def fake_glob(self: Path, pattern: str):
        if self == prefetch_dir and pattern == "*.pf":
            return iter(())
        return original_glob(self, pattern)

    def fake_iterdir(self: Path):
        if self == prefetch_dir:
            raise PermissionError("Access is denied")
        return original_iterdir(self)

    async def fake_capture(
        self: ExecTool,
        command: str,
        working_dir: str | None = None,
        timeout: int | None = None,
    ) -> CommandCapture:
        assert str(prefetch_dir) in command
        assert "-LiteralPath" in command
        return CommandCapture(
            stdout="\n".join((str(created[2]), str(created[1]))).encode("utf-8"),
            stderr=b"",
            exit_code=0,
            timed_out=False,
        )

    monkeypatch.setattr(Path, "glob", fake_glob)
    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    monkeypatch.setattr(ExecTool, "capture", fake_capture)

    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0003", title="Prefetch exec fallback case")
    prefetch_tool = WindowsPrefetchAnalyzeTool(workspace=tmp_path, runner=prefetch_pecmd_runner)

    result = await prefetch_tool.execute(
        case_id=case.id,
        prefetch_path=str(prefetch_dir),
        max_files=2,
    )

    assert "files=2" in result
    assert "NEWAPP.EXE-33333333.pf" in result
    assert "MIDAPP.EXE-22222222.pf" in result
    assert "OLDAPP.EXE-11111111.pf" not in result


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
