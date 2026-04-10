"""Tests for cache-friendly prompt construction."""

from __future__ import annotations

from datetime import datetime as real_datetime
from importlib.resources import files as pkg_files
from pathlib import Path
import datetime as datetime_module

from forensic_claw.agent.context import ContextBuilder


class _FakeDatetime(real_datetime):
    current = real_datetime(2026, 2, 24, 13, 59)

    @classmethod
    def now(cls, tz=None):  # type: ignore[override]
        return cls.current


def _make_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True)
    return workspace


def test_bootstrap_files_are_backed_by_templates() -> None:
    template_dir = pkg_files("forensic_claw") / "templates"

    for filename in ContextBuilder.BOOTSTRAP_FILES:
        assert (template_dir / filename).is_file(), f"missing bootstrap template: {filename}"


def test_system_prompt_stays_stable_when_clock_changes(tmp_path, monkeypatch) -> None:
    """System prompt should not change just because wall clock minute changes."""
    monkeypatch.setattr(datetime_module, "datetime", _FakeDatetime)

    workspace = _make_workspace(tmp_path)
    builder = ContextBuilder(workspace)

    _FakeDatetime.current = real_datetime(2026, 2, 24, 13, 59)
    prompt1 = builder.build_system_prompt()

    _FakeDatetime.current = real_datetime(2026, 2, 24, 14, 0)
    prompt2 = builder.build_system_prompt()

    assert prompt1 == prompt2


def test_runtime_context_is_separate_untrusted_user_message(tmp_path) -> None:
    """Runtime metadata should be merged with the user message."""
    workspace = _make_workspace(tmp_path)
    builder = ContextBuilder(workspace)

    messages = builder.build_messages(
        history=[],
        current_message="Return exactly: OK",
        channel="cli",
        chat_id="direct",
    )

    assert messages[0]["role"] == "system"
    assert "## Current Session" not in messages[0]["content"]

    # Runtime context is now merged with user message into a single message
    assert messages[-1]["role"] == "user"
    user_content = messages[-1]["content"]
    assert isinstance(user_content, str)
    assert ContextBuilder._RUNTIME_CONTEXT_TAG in user_content
    assert "Current Time:" in user_content
    assert "Channel: cli" in user_content
    assert "Chat ID: direct" in user_content
    assert "Return exactly: OK" in user_content


def test_windows_runtime_descriptor_reports_x64_os_and_process(tmp_path, monkeypatch) -> None:
    workspace = _make_workspace(tmp_path)
    builder = ContextBuilder(workspace)

    monkeypatch.setattr("forensic_claw.agent.context.platform.system", lambda: "Windows")
    monkeypatch.setattr("forensic_claw.agent.context.platform.machine", lambda: "AMD64")
    monkeypatch.setattr("forensic_claw.agent.context.platform.python_version", lambda: "3.12.9")
    monkeypatch.setattr(ContextBuilder, "_python_bitness", staticmethod(lambda: 64))
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "AMD64")
    monkeypatch.delenv("PROCESSOR_ARCHITEW6432", raising=False)

    prompt = builder.build_system_prompt()

    assert "Windows OS x64, Python 3.12.9 (64-bit process, arch x64)" in prompt


def test_windows_runtime_descriptor_reports_x86_process_on_x64_os(tmp_path, monkeypatch) -> None:
    workspace = _make_workspace(tmp_path)
    builder = ContextBuilder(workspace)

    monkeypatch.setattr("forensic_claw.agent.context.platform.system", lambda: "Windows")
    monkeypatch.setattr("forensic_claw.agent.context.platform.machine", lambda: "x86")
    monkeypatch.setattr("forensic_claw.agent.context.platform.python_version", lambda: "3.11.8")
    monkeypatch.setattr(ContextBuilder, "_python_bitness", staticmethod(lambda: 32))
    monkeypatch.setenv("PROCESSOR_ARCHITECTURE", "x86")
    monkeypatch.setenv("PROCESSOR_ARCHITEW6432", "AMD64")

    prompt = builder.build_system_prompt()

    assert "Windows OS x64, Python 3.11.8 (32-bit process, arch x86)" in prompt
