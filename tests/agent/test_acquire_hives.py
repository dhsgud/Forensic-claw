from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from forensic_claw.agent.tools import acquire_hives
from forensic_claw.agent.tools.acquire_hives import AcquireRegistryHivesTool


def test_metadata_and_schema(tmp_path):
    tool = AcquireRegistryHivesTool(workspace=tmp_path)
    assert tool.name == "acquire_registry_hives"
    enum = tool.parameters["properties"]["hives"]["items"]["enum"]
    assert set(enum) == {"SYSTEM", "SOFTWARE", "SAM", "SECURITY"}


def test_normalize_hives_dedup_and_default():
    assert AcquireRegistryHivesTool._normalize_hives(None) == ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
    assert AcquireRegistryHivesTool._normalize_hives([]) == ["SYSTEM", "SOFTWARE", "SAM", "SECURITY"]
    assert AcquireRegistryHivesTool._normalize_hives(["sam", "SAM", "bogus"]) == ["SAM"]
    assert AcquireRegistryHivesTool._normalize_hives(["software", "system"]) == ["SOFTWARE", "SYSTEM"]


def test_build_elevated_script_targets_correct_roots(tmp_path):
    out = tmp_path / "out"
    result = out / "_acquire_result.json"
    script = AcquireRegistryHivesTool._build_elevated_script(["SYSTEM", "SAM"], out, result)
    assert r"'SYSTEM'='HKLM\SYSTEM'" in script
    assert r"'SAM'='HKLM\SAM'" in script
    assert "reg.exe save" in script
    assert str(result) in script


@pytest.mark.asyncio
async def test_execute_is_windows_only(tmp_path, monkeypatch):
    # Force the non-Windows branch so no elevation is attempted on a dev machine.
    monkeypatch.setattr(acquire_hives.sys, "platform", "linux")
    tool = AcquireRegistryHivesTool(workspace=tmp_path)
    out = await tool.execute()
    assert "only available on Windows" in out


@pytest.mark.asyncio
async def test_execute_admin_path_uses_reg_save(tmp_path, monkeypatch):
    monkeypatch.setattr(acquire_hives.sys, "platform", "win32")
    monkeypatch.setattr(AcquireRegistryHivesTool, "_is_admin", staticmethod(lambda: True))

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        # Simulate reg.exe writing the destination hive file.
        dest = Path(cmd[3])
        dest.write_bytes(b"hive")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(acquire_hives.subprocess, "run", fake_run)

    tool = AcquireRegistryHivesTool(workspace=tmp_path)
    raw = await tool.execute(hives=["SYSTEM"])
    data = json.loads(raw)

    assert data["elevation"] == "already-elevated"
    assert data["ready"] is True
    assert data["acquired"][0]["name"] == "SYSTEM"
    assert data["acquired"][0]["ok"] is True
    assert calls and calls[0][:3] == ["reg.exe", "save", r"HKLM\SYSTEM"]
