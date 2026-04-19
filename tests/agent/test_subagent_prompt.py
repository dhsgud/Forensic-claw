from __future__ import annotations

from unittest.mock import MagicMock

from forensic_claw.agent.subagent import SubagentManager
from forensic_claw.bus.queue import MessageBus


def test_subagent_prompt_discourages_python_runtime_dependency(tmp_path) -> None:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"

    manager = SubagentManager(provider=provider, workspace=tmp_path, bus=MessageBus())

    prompt = manager._build_subagent_prompt()

    assert "prefer PowerShell commands over `cmd.exe`" in prompt
    assert "Do not assume `python` or `python.exe` exists on the host." in prompt
    assert "Prefer direct shell commands, PowerShell, existing tools, and bundled executables" in prompt
