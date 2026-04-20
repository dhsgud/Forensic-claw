import asyncio
import base64
import json
from pathlib import Path
from typing import Any

from forensic_claw.agent.tools.base import Tool
from forensic_claw.agent.tools.registry import ToolRegistry
from forensic_claw.agent.tools.shell import ExecTool, _WindowsElevatedBrokerSession


class SampleTool(Tool):
    @property
    def name(self) -> str:
        return "sample"

    @property
    def description(self) -> str:
        return "sample tool"

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "minLength": 2},
                "count": {"type": "integer", "minimum": 1, "maximum": 10},
                "mode": {"type": "string", "enum": ["fast", "full"]},
                "meta": {
                    "type": "object",
                    "properties": {
                        "tag": {"type": "string"},
                        "flags": {
                            "type": "array",
                            "items": {"type": "string"},
                        },
                    },
                    "required": ["tag"],
                },
            },
            "required": ["query", "count"],
        }

    async def execute(self, **kwargs: Any) -> str:
        return "ok"


def test_validate_params_missing_required() -> None:
    tool = SampleTool()
    errors = tool.validate_params({"query": "hi"})
    assert "missing required count" in "; ".join(errors)


def test_validate_params_type_and_range() -> None:
    tool = SampleTool()
    errors = tool.validate_params({"query": "hi", "count": 0})
    assert any("count must be >= 1" in e for e in errors)

    errors = tool.validate_params({"query": "hi", "count": "2"})
    assert any("count should be integer" in e for e in errors)


def test_validate_params_enum_and_min_length() -> None:
    tool = SampleTool()
    errors = tool.validate_params({"query": "h", "count": 2, "mode": "slow"})
    assert any("query must be at least 2 chars" in e for e in errors)
    assert any("mode must be one of" in e for e in errors)


def test_validate_params_nested_object_and_array() -> None:
    tool = SampleTool()
    errors = tool.validate_params(
        {
            "query": "hi",
            "count": 2,
            "meta": {"flags": [1, "ok"]},
        }
    )
    assert any("missing required meta.tag" in e for e in errors)
    assert any("meta.flags[0] should be string" in e for e in errors)


def test_validate_params_ignores_unknown_fields() -> None:
    tool = SampleTool()
    errors = tool.validate_params({"query": "hi", "count": 2, "extra": "x"})
    assert errors == []


async def test_registry_returns_validation_error() -> None:
    reg = ToolRegistry()
    reg.register(SampleTool())
    result = await reg.execute("sample", {"query": "hi"})
    assert "Invalid parameters" in result


def test_exec_extract_absolute_paths_keeps_full_windows_path() -> None:
    cmd = r"type C:\user\workspace\txt"
    paths = ExecTool._extract_absolute_paths(cmd)
    assert paths == [r"C:\user\workspace\txt"]


def test_exec_extract_absolute_paths_ignores_relative_posix_segments() -> None:
    cmd = ".venv/bin/python script.py"
    paths = ExecTool._extract_absolute_paths(cmd)
    assert "/bin/python" not in paths


def test_exec_extract_absolute_paths_captures_posix_absolute_paths() -> None:
    cmd = "cat /tmp/data.txt > /tmp/out.txt"
    paths = ExecTool._extract_absolute_paths(cmd)
    assert "/tmp/data.txt" in paths
    assert "/tmp/out.txt" in paths


def test_exec_extract_absolute_paths_captures_home_paths() -> None:
    cmd = "cat ~/.forensic-claw/config.json > ~/out.txt"
    paths = ExecTool._extract_absolute_paths(cmd)
    assert "~/.forensic-claw/config.json" in paths
    assert "~/out.txt" in paths


def test_exec_extract_absolute_paths_captures_quoted_paths() -> None:
    cmd = 'cat "/tmp/data.txt" "~/.forensic-claw/config.json"'
    paths = ExecTool._extract_absolute_paths(cmd)
    assert "/tmp/data.txt" in paths
    assert "~/.forensic-claw/config.json" in paths


def test_exec_normalizes_nested_powershell_command_on_windows(monkeypatch) -> None:
    tool = ExecTool(elevate_on_windows=False)
    monkeypatch.setattr("forensic_claw.agent.tools.shell.sys.platform", "win32")

    normalized = tool._normalize_command_for_execution(
        'powershell -Command "Get-ChildItem -Path \'C:\\Windows\\Prefetch\' -File"'
    )

    assert normalized == "Get-ChildItem -Path 'C:\\Windows\\Prefetch' -File"


def test_exec_describe_execution_shows_normalized_windows_command(monkeypatch) -> None:
    tool = ExecTool(elevate_on_windows=False)
    monkeypatch.setattr("forensic_claw.agent.tools.shell.sys.platform", "win32")
    monkeypatch.setattr(tool, "_preferred_windows_shell", lambda: "powershell.exe")

    plan = tool.describe_execution(
        command='powershell -Command "Get-ChildItem -Path \'C:\\Windows\\Prefetch\' -File"'
    )

    assert plan["command"] == "Get-ChildItem -Path 'C:\\Windows\\Prefetch' -File"


def test_exec_guard_blocks_home_path_outside_workspace(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command("cat ~/.forensic-claw/config.json", str(tmp_path))
    assert error == "Error: Command blocked by safety guard (path outside working dir)"


def test_exec_guard_blocks_quoted_home_path_outside_workspace(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command('cat "~/.forensic-claw/config.json"', str(tmp_path))
    assert error == "Error: Command blocked by safety guard (path outside working dir)"


def test_exec_guard_allows_prefetch_path_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-ChildItem -Path 'C:\\Windows\\Prefetch' -File | Select-Object -First 10 Name",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_evtx_path_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-WinEvent -Path 'C:\\Windows\\System32\\winevt\\Logs\\Security.evtx' -MaxEvents 5",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_registry_hive_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-Item 'C:\\Windows\\System32\\config\\SYSTEM'",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_blocks_nonforensic_destination_outside_workspace_when_copying_hive(
    tmp_path,
) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Copy-Item 'C:\\Windows\\System32\\config\\SYSTEM' 'C:\\Temp\\SYSTEM.copy'",
        str(tmp_path),
    )
    assert error == "Error: Command blocked by safety guard (path outside working dir)"


def test_exec_guard_allows_srum_path_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-Item 'C:\\Windows\\System32\\sru\\SRUDB.dat'",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_mft_path_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-Item 'C:\\$MFT'",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_usn_path_outside_workspace_for_forensics(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        "Get-Item 'C:\\$Extend\\$UsnJrnl:$J'",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_shimcache_registry_query(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        r"reg query HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_reg_save_for_core_registry_hives(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        r"reg save HKLM\SYSTEM C:\Temp\SYSTEM.hiv /y",
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_allows_reg_export_for_core_registry_hives(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        r'reg export "HKLM\SOFTWARE" C:\Temp\SOFTWARE.reg /y',
        str(tmp_path),
    )
    assert error is None


def test_exec_guard_blocks_reg_export_for_nonforensic_registry_root(tmp_path) -> None:
    tool = ExecTool(restrict_to_workspace=True, elevate_on_windows=False)
    error = tool._guard_command(
        r"reg export HKCU\Software C:\Temp\HKCU.reg /y",
        str(tmp_path),
    )
    assert error == "Error: Command blocked by safety guard (path outside working dir)"


# --- cast_params tests ---


class CastTestTool(Tool):
    """Minimal tool for testing cast_params."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    @property
    def name(self) -> str:
        return "cast_test"

    @property
    def description(self) -> str:
        return "test tool for casting"

    @property
    def parameters(self) -> dict[str, Any]:
        return self._schema

    async def execute(self, **kwargs: Any) -> str:
        return "ok"


def test_cast_params_string_to_int() -> None:
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"count": {"type": "integer"}},
        }
    )
    result = tool.cast_params({"count": "42"})
    assert result["count"] == 42
    assert isinstance(result["count"], int)


def test_cast_params_string_to_number() -> None:
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"rate": {"type": "number"}},
        }
    )
    result = tool.cast_params({"rate": "3.14"})
    assert result["rate"] == 3.14
    assert isinstance(result["rate"], float)


def test_cast_params_string_to_bool() -> None:
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"enabled": {"type": "boolean"}},
        }
    )
    assert tool.cast_params({"enabled": "true"})["enabled"] is True
    assert tool.cast_params({"enabled": "false"})["enabled"] is False
    assert tool.cast_params({"enabled": "1"})["enabled"] is True


def test_cast_params_array_items() -> None:
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {
                "nums": {"type": "array", "items": {"type": "integer"}},
            },
        }
    )
    result = tool.cast_params({"nums": ["1", "2", "3"]})
    assert result["nums"] == [1, 2, 3]


def test_cast_params_nested_object() -> None:
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {
                "config": {
                    "type": "object",
                    "properties": {
                        "port": {"type": "integer"},
                        "debug": {"type": "boolean"},
                    },
                },
            },
        }
    )
    result = tool.cast_params({"config": {"port": "8080", "debug": "true"}})
    assert result["config"]["port"] == 8080
    assert result["config"]["debug"] is True


def test_cast_params_bool_not_cast_to_int() -> None:
    """Booleans should not be silently cast to integers."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"count": {"type": "integer"}},
        }
    )
    result = tool.cast_params({"count": True})
    assert result["count"] is True
    errors = tool.validate_params(result)
    assert any("count should be integer" in e for e in errors)


def test_cast_params_preserves_empty_string() -> None:
    """Empty strings should be preserved for string type."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"name": {"type": "string"}},
        }
    )
    result = tool.cast_params({"name": ""})
    assert result["name"] == ""


def test_cast_params_bool_string_false() -> None:
    """Test that 'false', '0', 'no' strings convert to False."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"flag": {"type": "boolean"}},
        }
    )
    assert tool.cast_params({"flag": "false"})["flag"] is False
    assert tool.cast_params({"flag": "False"})["flag"] is False
    assert tool.cast_params({"flag": "0"})["flag"] is False
    assert tool.cast_params({"flag": "no"})["flag"] is False
    assert tool.cast_params({"flag": "NO"})["flag"] is False


def test_cast_params_bool_string_invalid() -> None:
    """Invalid boolean strings should not be cast."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"flag": {"type": "boolean"}},
        }
    )
    # Invalid strings should be preserved (validation will catch them)
    result = tool.cast_params({"flag": "random"})
    assert result["flag"] == "random"
    result = tool.cast_params({"flag": "maybe"})
    assert result["flag"] == "maybe"


def test_cast_params_invalid_string_to_int() -> None:
    """Invalid strings should not be cast to integer."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"count": {"type": "integer"}},
        }
    )
    result = tool.cast_params({"count": "abc"})
    assert result["count"] == "abc"  # Original value preserved
    result = tool.cast_params({"count": "12.5.7"})
    assert result["count"] == "12.5.7"


def test_cast_params_invalid_string_to_number() -> None:
    """Invalid strings should not be cast to number."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"rate": {"type": "number"}},
        }
    )
    result = tool.cast_params({"rate": "not_a_number"})
    assert result["rate"] == "not_a_number"


def test_validate_params_bool_not_accepted_as_number() -> None:
    """Booleans should not pass number validation."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"rate": {"type": "number"}},
        }
    )
    errors = tool.validate_params({"rate": False})
    assert any("rate should be number" in e for e in errors)


def test_cast_params_none_values() -> None:
    """Test None handling for different types."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "integer"},
                "items": {"type": "array"},
                "config": {"type": "object"},
            },
        }
    )
    result = tool.cast_params(
        {
            "name": None,
            "count": None,
            "items": None,
            "config": None,
        }
    )
    # None should be preserved for all types
    assert result["name"] is None
    assert result["count"] is None
    assert result["items"] is None
    assert result["config"] is None


def test_cast_params_single_value_not_auto_wrapped_to_array() -> None:
    """Single values should NOT be automatically wrapped into arrays."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"items": {"type": "array"}},
        }
    )
    # Non-array values should be preserved (validation will catch them)
    result = tool.cast_params({"items": 5})
    assert result["items"] == 5  # Not wrapped to [5]
    result = tool.cast_params({"items": "text"})
    assert result["items"] == "text"  # Not wrapped to ["text"]


# --- ExecTool enhancement tests ---


async def test_exec_always_returns_exit_code() -> None:
    """Exit code should appear in output even on success (exit 0)."""
    tool = ExecTool(elevate_on_windows=False)
    result = await tool.execute(command="echo hello")
    assert "Exit code: 0" in result
    assert "hello" in result


async def test_exec_head_tail_truncation() -> None:
    """Long output should preserve both head and tail."""
    tool = ExecTool(elevate_on_windows=False)
    # Generate output that exceeds _MAX_OUTPUT (10_000 chars)
    # Use python to generate output to avoid command line length limits
    result = await tool.execute(
        command="python -c \"print('A' * 6000 + '\\n' + 'B' * 6000)\""
    )
    assert "chars truncated" in result
    # Head portion should start with As
    assert result.startswith("A")
    # Tail portion should end with the exit code which comes after Bs
    assert "Exit code:" in result


async def test_exec_timeout_parameter() -> None:
    """LLM-supplied timeout should override the constructor default."""
    tool = ExecTool(timeout=60, elevate_on_windows=False)
    # A very short timeout should cause the command to be killed
    result = await tool.execute(command='python -c "import time; time.sleep(10)"', timeout=1)
    assert "timed out" in result
    assert "1 seconds" in result


async def test_exec_timeout_capped_at_max() -> None:
    """Timeout values above _MAX_TIMEOUT should be clamped."""
    tool = ExecTool(elevate_on_windows=False)
    # Should not raise — just clamp to 600
    result = await tool.execute(command="echo ok", timeout=9999)
    assert "Exit code: 0" in result


async def test_exec_decodes_cp949_stdout() -> None:
    """ExecTool should decode common Windows encodings like CP949."""
    tool = ExecTool(elevate_on_windows=False)
    result = await tool.execute(
        command='python -c "import sys; sys.stdout.buffer.write(\'안녕\'.encode(\'cp949\'))"'
    )
    assert "안녕" in result
    assert "Exit code: 0" in result


async def test_exec_reuses_windows_broker_after_first_elevation_prompt(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """Windows exec should bootstrap one elevated broker and reuse it for later commands."""
    tool = ExecTool(elevate_on_windows=True)
    launches = 0
    seen_commands: list[str] = []

    session_dir = tmp_path / "broker"
    session_dir.mkdir()
    ready_path = session_dir / "ready.json"
    ready_path.write_text("{}", encoding="utf-8")
    broker = _WindowsElevatedBrokerSession(
        session_dir=session_dir,
        shell_exe="powershell.exe",
        token="token",
        broker_script_path=session_dir / "broker.ps1",
        request_path=session_dir / "request.json",
        response_path=session_dir / "response.json",
        ready_path=ready_path,
        stop_path=session_dir / "stop.txt",
    )

    async def fake_launch(shell_exe, env):
        nonlocal launches
        launches += 1
        return broker

    async def fake_send(session, command, cwd, timeout):
        seen_commands.append(command)
        return command.encode("utf-8"), b"", 0, False

    monkeypatch.setattr("forensic_claw.agent.tools.shell.sys.platform", "win32")
    monkeypatch.setattr(tool, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(tool, "_preferred_windows_shell", lambda: "powershell.exe")
    monkeypatch.setattr(tool, "_launch_windows_broker", fake_launch)
    monkeypatch.setattr(tool, "_send_windows_broker_request", fake_send)
    monkeypatch.setattr(ExecTool, "_windows_broker", None)
    monkeypatch.setattr(ExecTool, "_windows_broker_lock", None)
    monkeypatch.setattr(ExecTool, "_windows_broker_atexit_registered", False)
    monkeypatch.setattr(ExecTool, "_windows_broker_disabled", False)

    first = await tool.execute(command="echo one")
    second = await tool.execute(command="echo two")

    assert launches == 1
    assert seen_commands == ["echo one", "echo two"]
    assert "echo one" in first
    assert "echo two" in second


async def test_exec_falls_back_to_direct_shell_when_windows_broker_fails(monkeypatch) -> None:
    tool = ExecTool(elevate_on_windows=True)
    broker_attempts = 0

    class _DummyProcess:
        pid = 4321
        returncode = 0

    async def fake_broker(command, cwd, timeout, env):
        nonlocal broker_attempts
        broker_attempts += 1
        raise RuntimeError("broker bootstrap failed")

    async def fake_spawn(command, cwd, env):
        return _DummyProcess()

    async def fake_collect(process, timeout_s):
        return b"fallback ok", b"", False

    async def fake_finalize(process):
        return None

    monkeypatch.setattr("forensic_claw.agent.tools.shell.sys.platform", "win32")
    monkeypatch.setattr(tool, "_is_windows_admin", lambda: False)
    monkeypatch.setattr(tool, "_execute_via_windows_broker", fake_broker)
    monkeypatch.setattr(tool, "_spawn_process", fake_spawn)
    monkeypatch.setattr(tool, "_collect_output", fake_collect)
    monkeypatch.setattr(tool, "_finalize_process", fake_finalize)
    monkeypatch.setattr(ExecTool, "_windows_broker", None)
    monkeypatch.setattr(ExecTool, "_windows_broker_lock", None)
    monkeypatch.setattr(ExecTool, "_windows_broker_atexit_registered", False)
    monkeypatch.setattr(ExecTool, "_windows_broker_disabled", False)

    first = await tool.execute(command="Write-Output 'fallback ok'")
    second = await tool.execute(command="Write-Output 'fallback ok'")

    assert broker_attempts == 1
    assert "fallback ok" in first
    assert "ran without elevation" in first
    assert "fallback ok" in second


def test_exec_broker_launcher_uses_runas_once_for_bootstrap(tmp_path: Path) -> None:
    """Broker bootstrap still uses RunAs, but only for the initial session startup."""
    session_dir = tmp_path / "broker"
    broker = _WindowsElevatedBrokerSession(
        session_dir=session_dir,
        shell_exe="powershell.exe",
        token="token",
        broker_script_path=session_dir / "broker.ps1",
        request_path=session_dir / "request.json",
        response_path=session_dir / "response.json",
        ready_path=session_dir / "ready.json",
        stop_path=session_dir / "stop.txt",
    )

    script = ExecTool._build_windows_broker_launcher_script(broker)

    assert "Start-Process -FilePath 'powershell.exe'" in script
    assert "-Verb RunAs" in script
    assert "-File'," in script


async def test_exec_reads_broker_response_with_utf8_bom(tmp_path: Path) -> None:
    """Broker responses written with UTF-8 BOM should still parse correctly."""
    tool = ExecTool(elevate_on_windows=True)
    session_dir = tmp_path / "broker"
    session_dir.mkdir()
    broker = _WindowsElevatedBrokerSession(
        session_dir=session_dir,
        shell_exe="powershell.exe",
        token="token",
        broker_script_path=session_dir / "broker.ps1",
        request_path=session_dir / "request.json",
        response_path=session_dir / "response.json",
        ready_path=session_dir / "ready.json",
        stop_path=session_dir / "stop.txt",
    )

    async def _write_bom_response() -> None:
        while not broker.request_path.exists():
            await asyncio.sleep(0.01)
        request = json.loads(broker.request_path.read_text(encoding="utf-8"))
        payload = {
            "requestId": request["requestId"],
            "stdoutBase64": base64.b64encode(b"ok").decode("ascii"),
            "stderrBase64": "",
            "exitCode": 0,
            "timedOut": False,
        }
        broker.response_path.write_text(json.dumps(payload), encoding="utf-8-sig")

    writer = asyncio.create_task(_write_bom_response())
    stdout, stderr, exit_code, timed_out = await tool._send_windows_broker_request(
        broker,
        "echo ok",
        "C:\\",
        5,
    )
    await writer

    assert stdout == b"ok"
    assert stderr == b""
    assert exit_code == 0
    assert timed_out is False


# --- _resolve_type and nullable param tests ---


def test_resolve_type_simple_string() -> None:
    """Simple string type passes through unchanged."""
    assert Tool._resolve_type("string") == "string"


def test_resolve_type_union_with_null() -> None:
    """Union type ['string', 'null'] resolves to 'string'."""
    assert Tool._resolve_type(["string", "null"]) == "string"


def test_resolve_type_only_null() -> None:
    """Union type ['null'] resolves to None (no non-null type)."""
    assert Tool._resolve_type(["null"]) is None


def test_resolve_type_none_input() -> None:
    """None input passes through as None."""
    assert Tool._resolve_type(None) is None


def test_validate_nullable_param_accepts_string() -> None:
    """Nullable string param should accept a string value."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"name": {"type": ["string", "null"]}},
        }
    )
    errors = tool.validate_params({"name": "hello"})
    assert errors == []


def test_validate_nullable_param_accepts_none() -> None:
    """Nullable string param should accept None."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"name": {"type": ["string", "null"]}},
        }
    )
    errors = tool.validate_params({"name": None})
    assert errors == []


def test_validate_nullable_flag_accepts_none() -> None:
    """OpenAI-normalized nullable params should still accept None locally."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"name": {"type": "string", "nullable": True}},
        }
    )
    errors = tool.validate_params({"name": None})
    assert errors == []


def test_cast_nullable_param_no_crash() -> None:
    """cast_params should not crash on nullable type (the original bug)."""
    tool = CastTestTool(
        {
            "type": "object",
            "properties": {"name": {"type": ["string", "null"]}},
        }
    )
    result = tool.cast_params({"name": "hello"})
    assert result["name"] == "hello"
    result = tool.cast_params({"name": None})
    assert result["name"] is None
