from __future__ import annotations

import pytest

from forensic_claw.agent.tools.shell import ExecTool

RAW_EVENTS = """Event[0]
  Log Name: System
  Source: EventLog
  Date: 2025-12-28T21:22:32.7910000Z
  Event ID: 6011
  Level: 정보
  Computer: WIN-TEST
  Description:
이 컴퓨터의 NetBIOS 이름이 WIN-TEST로 변경되었습니다.
"""


class _DummyProcess:
    pid = 1234
    returncode = 0


@pytest.mark.asyncio
async def test_exec_compacts_windows_event_log_output(monkeypatch) -> None:
    tool = ExecTool(timeout=5, elevate_on_windows=False)

    async def fake_spawn(command, cwd, env):
        return _DummyProcess()

    async def fake_collect(process, timeout_s):
        return RAW_EVENTS.encode("utf-8"), b"", False

    async def fake_finalize(process):
        return None

    monkeypatch.setattr(tool, "_spawn_process", fake_spawn)
    monkeypatch.setattr(tool, "_collect_output", fake_collect)
    monkeypatch.setattr(tool, "_finalize_process", fake_finalize)

    result = await tool.execute(command="Write-Output 'system logs'")

    assert "Windows Event Log Summary" in result
    assert "UTC 2025-12-28 21:22:32Z | KST 2025-12-29 06:22:32 UTC+09:00" in result
    assert "Exit code: 0" in result
    assert "Event[0]" not in result
