"""Shell execution tool."""

import asyncio
import atexit
import base64
import ctypes
import json
import locale
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from loguru import logger

from forensic_claw.agent.tools.base import Tool
from forensic_claw.utils.event_logs import compact_windows_event_log_output


@dataclass(frozen=True)
class _WindowsElevatedBrokerSession:
    session_dir: Path
    shell_exe: str
    token: str
    broker_script_path: Path
    request_path: Path
    response_path: Path
    ready_path: Path
    stop_path: Path


class ExecTool(Tool):
    """Tool to execute shell commands."""

    _MAX_TIMEOUT = 600
    _MAX_OUTPUT = 10_000
    _OUTPUT_ENCODINGS = (
        "utf-8-sig",
        "utf-8",
        "cp949",
    )
    _BROKER_STARTUP_TIMEOUT = 30
    _BROKER_RESPONSE_GRACE = 5
    _windows_broker: ClassVar[_WindowsElevatedBrokerSession | None] = None
    _windows_broker_lock: ClassVar[asyncio.Lock | None] = None
    _windows_broker_atexit_registered: ClassVar[bool] = False
    _windows_broker_disabled: ClassVar[bool] = False
    _WINDOWS_CONFIG_HIVE_BASENAMES: ClassVar[set[str]] = {
        "components",
        "default",
        "drivers",
        "sam",
        "security",
        "software",
        "system",
    }
    _PORTABLE_HIVE_BASENAMES: ClassVar[set[str]] = {
        "amcache.hve",
        "ntuser.dat",
        "usrclass.dat",
    }
    _FORENSIC_REGISTRY_ROOTS: ClassVar[tuple[str, ...]] = (
        r"hklm\sam",
        r"hkey_local_machine\sam",
        r"hklm\security",
        r"hkey_local_machine\security",
        r"hklm\software",
        r"hkey_local_machine\software",
        r"hklm\system",
        r"hkey_local_machine\system",
    )
    _NTFS_METADATA_BASENAMES: ClassVar[set[str]] = {
        "$mft",
        "$usnjrnl:$j",
    }

    def __init__(
        self,
        timeout: int = 60,
        working_dir: str | None = None,
        deny_patterns: list[str] | None = None,
        allow_patterns: list[str] | None = None,
        restrict_to_workspace: bool = False,
        path_append: str = "",
        elevate_on_windows: bool = True,
    ):
        self.timeout = timeout
        self.working_dir = working_dir
        self.deny_patterns = deny_patterns or [
            r"\brm\s+-[rf]{1,2}\b",          # rm -r, rm -rf, rm -fr
            r"\bdel\s+/[fq]\b",              # del /f, del /q
            r"\brmdir\s+/s\b",               # rmdir /s
            r"(?:^|[;&|]\s*)format\b",       # format (as standalone command only)
            r"\b(mkfs|diskpart)\b",          # disk operations
            r"\bdd\s+if=",                   # dd
            r">\s*/dev/sd",                  # write to disk
            r"\b(shutdown|reboot|poweroff)\b",  # system power
            r":\(\)\s*\{.*\};\s*:",          # fork bomb
        ]
        self.allow_patterns = allow_patterns or []
        self.restrict_to_workspace = restrict_to_workspace
        self.path_append = path_append
        self.elevate_on_windows = elevate_on_windows

    @property
    def name(self) -> str:
        return "exec"

    @property
    def description(self) -> str:
        return (
            "Execute a shell command and return its output. On Windows, pass raw PowerShell "
            "statements instead of wrapping them with powershell -Command or cmd /c."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "The shell command to execute",
                },
                "working_dir": {
                    "type": "string",
                    "description": "Optional working directory for the command",
                },
                "timeout": {
                    "type": "integer",
                    "description": (
                        "Timeout in seconds. Increase for long-running commands "
                        "like compilation or installation (default 60, max 600)."
                    ),
                    "minimum": 1,
                    "maximum": 600,
                },
            },
            "required": ["command"],
        }

    async def execute(
        self,
        command: str,
        working_dir: str | None = None,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> str:
        command = self._normalize_command_for_execution(command)
        cwd = working_dir or self.working_dir or os.getcwd()
        guard_error = self._guard_command(command, cwd)
        if guard_error:
            return guard_error

        effective_timeout = min(timeout or self.timeout, self._MAX_TIMEOUT)
        env = self._build_env()
        broker_fallback_note: str | None = None

        try:
            if self._should_use_windows_elevated_broker():
                try:
                    stdout, stderr, exit_code, timed_out = await self._execute_via_windows_broker(
                        command,
                        cwd,
                        effective_timeout,
                        env,
                    )
                except Exception as e:
                    self._disable_windows_broker()
                    logger.warning(
                        "Windows elevated broker unavailable, falling back to direct execution: {}",
                        e,
                    )
                    broker_fallback_note = (
                        f"Note: Windows elevation broker unavailable ({e}). "
                        "The command ran without elevation.\n\n"
                    )
                else:
                    if timed_out:
                        return f"Error: Command timed out after {effective_timeout} seconds"
                    return self._format_command_result(stdout, stderr, exit_code)

            process = await self._spawn_process(command, cwd, env)
            stdout, stderr, timed_out = await self._collect_output(process, effective_timeout)
            if timed_out:
                return f"Error: Command timed out after {effective_timeout} seconds"
            result = self._format_command_result(stdout, stderr, process.returncode)
            return f"{broker_fallback_note}{result}" if broker_fallback_note else result
        except Exception as e:
            return f"Error executing command: {e}"

    def describe_execution(
        self,
        *,
        command: str,
        working_dir: str | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Describe how this tool will launch a shell command."""
        command = self._normalize_command_for_execution(command)
        cwd = working_dir or self.working_dir or os.getcwd()
        effective_timeout = min(timeout or self.timeout, self._MAX_TIMEOUT)

        if sys.platform == "win32":
            shell_exe = self._preferred_windows_shell()
            wrapper = "PowerShell wrapper enables UTF-8 console I/O before running the command."
            elevated = self.elevate_on_windows and not self.__class__._windows_broker_disabled
            if elevated:
                wrapper += " On Windows, commands bootstrap one elevated broker session and reuse it for later commands."
            elif self.elevate_on_windows:
                wrapper += " Elevated broker is disabled for this process after a startup failure, so commands run without elevation."
            return {
                "command": command,
                "workingDir": cwd,
                "timeout": effective_timeout,
                "platform": "windows",
                "shell": Path(shell_exe).name or shell_exe,
                "shellPath": shell_exe,
                "elevated": elevated,
                "launcher": (
                    f"{shell_exe} -NoLogo -NoProfile -NonInteractive "
                    "-ExecutionPolicy Bypass -EncodedCommand <base64>"
                ),
                "wrapper": wrapper,
            }

        shell_exe = os.environ.get("SHELL") or "/bin/sh"
        return {
            "command": command,
            "workingDir": cwd,
            "timeout": effective_timeout,
            "platform": "posix",
            "shell": Path(shell_exe).name or shell_exe,
            "shellPath": shell_exe,
            "launcher": f"{shell_exe} -c <command>",
            "wrapper": "The system shell runs the command with stdout and stderr captured.",
        }

    @staticmethod
    def _postprocess_stdout(text: str) -> str:
        """Compact known verbose forensic outputs into a more LLM-friendly form."""
        compacted = compact_windows_event_log_output(text)
        return compacted or text

    def _format_command_result(self, stdout: bytes, stderr: bytes, exit_code: int | None) -> str:
        output_parts: list[str] = []

        if stdout:
            stdout_text = self._decode_output(stdout)
            output_parts.append(self._postprocess_stdout(stdout_text))

        if stderr:
            stderr_text = self._decode_output(stderr)
            if stderr_text.strip():
                output_parts.append(f"STDERR:\n{stderr_text}")

        output_parts.append(f"\nExit code: {exit_code if exit_code is not None else 1}")

        result = "\n".join(output_parts) if output_parts else "(no output)"
        if len(result) > self._MAX_OUTPUT:
            half = self._MAX_OUTPUT // 2
            result = (
                result[:half]
                + f"\n\n... ({len(result) - self._MAX_OUTPUT:,} chars truncated) ...\n\n"
                + result[-half:]
            )

        return result

    def _should_use_windows_elevated_broker(self) -> bool:
        return (
            sys.platform == "win32"
            and self.elevate_on_windows
            and not self.__class__._windows_broker_disabled
            and not self._is_windows_admin()
        )

    def _build_env(self) -> dict[str, str]:
        env = os.environ.copy()
        if self.path_append:
            env["PATH"] = env.get("PATH", "") + os.pathsep + self.path_append
        if sys.platform == "win32":
            env.setdefault("PYTHONIOENCODING", "utf-8")
            env.setdefault("PYTHONUTF8", "1")
        return env

    async def _spawn_process(
        self,
        command: str,
        cwd: str,
        env: dict[str, str],
    ) -> asyncio.subprocess.Process:
        if sys.platform == "win32":
            shell_exe = self._preferred_windows_shell()
            encoded_script = base64.b64encode(
                self._wrap_windows_command(command).encode("utf-16-le")
            ).decode("ascii")
            return await asyncio.create_subprocess_exec(
                shell_exe,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                creationflags=self._windows_creationflags(),
            )

        return await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )

    async def _collect_output(
        self,
        process: asyncio.subprocess.Process,
        timeout_s: int,
    ) -> tuple[bytes, bytes, bool]:
        communicate_task = asyncio.create_task(process.communicate())
        stdout = b""
        stderr = b""
        timed_out = False

        try:
            stdout, stderr = await asyncio.wait_for(
                asyncio.shield(communicate_task),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            timed_out = True
            await self._terminate_process(process)
            try:
                stdout, stderr = await asyncio.wait_for(communicate_task, timeout=5.0)
            except asyncio.TimeoutError:
                communicate_task.cancel()
                await asyncio.gather(communicate_task, return_exceptions=True)
            except Exception as e:
                logger.debug("Timed-out command cleanup ended with {}", e)
        finally:
            await self._finalize_process(process)

        return stdout or b"", stderr or b"", timed_out

    async def _terminate_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return

        if sys.platform == "win32" and await self._taskkill_tree(process.pid):
            return

        try:
            process.kill()
        except ProcessLookupError:
            return

    async def _taskkill_tree(self, pid: int) -> bool:
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/T",
                "/F",
                "/PID",
                str(pid),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=self._windows_creationflags(),
            )
            await asyncio.wait_for(killer.wait(), timeout=5.0)
            return killer.returncode == 0
        except Exception as e:
            logger.debug("taskkill cleanup failed for pid {}: {}", pid, e)
            return False

    async def _finalize_process(self, process: asyncio.subprocess.Process) -> None:
        try:
            await asyncio.wait_for(process.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.debug("Process {} did not exit during finalize window", process.pid)
        finally:
            if sys.platform != "win32":
                try:
                    os.waitpid(process.pid, os.WNOHANG)
                except (ProcessLookupError, ChildProcessError) as e:
                    logger.debug("Process already reaped or not found: {}", e)

    @classmethod
    def _decode_output(cls, data: bytes) -> str:
        encodings: list[str] = list(cls._OUTPUT_ENCODINGS)
        preferred = locale.getpreferredencoding(False)
        if preferred and preferred not in encodings:
            encodings.append(preferred)

        if data.startswith(b"\xef\xbb\xbf"):
            encodings.insert(0, "utf-8-sig")
        elif data.startswith((b"\xff\xfe", b"\xfe\xff")):
            encodings.insert(0, "utf-16")
        elif cls._looks_like_utf16_bytes(data):
            encodings.extend(["utf-16-le", "utf-16-be"])

        seen: set[str] = set()
        for encoding in encodings:
            key = encoding.lower()
            if key in seen:
                continue
            seen.add(key)
            try:
                return data.decode(encoding)
            except (LookupError, UnicodeDecodeError):
                continue

        return data.decode("utf-8", errors="replace")

    @staticmethod
    def _looks_like_utf16_bytes(data: bytes) -> bool:
        if len(data) < 8 or b"\x00" not in data:
            return False

        even_bytes = data[0::2]
        odd_bytes = data[1::2]
        even_null_ratio = even_bytes.count(0) / max(len(even_bytes), 1)
        odd_null_ratio = odd_bytes.count(0) / max(len(odd_bytes), 1)
        return even_null_ratio >= 0.6 or odd_null_ratio >= 0.6

    @staticmethod
    def _preferred_windows_shell() -> str:
        return shutil.which("pwsh") or shutil.which("powershell") or "powershell"

    @staticmethod
    def _wrap_windows_command(command: str) -> str:
        return (
            "$ErrorActionPreference = 'Continue'\n"
            "[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
            "$OutputEncoding = [Console]::OutputEncoding\n"
            f"{command}\n"
        )

    def _normalize_command_for_execution(self, command: str) -> str:
        normalized = command.strip()
        if sys.platform != "win32" or not normalized:
            return normalized

        unwrapped = self._unwrap_windows_powershell_command(normalized)
        return unwrapped if unwrapped is not None else normalized

    @staticmethod
    def _unwrap_windows_powershell_command(command: str) -> str | None:
        match = re.match(r'^\s*(?P<exe>"[^"]+"|\'[^\']+\'|\S+)\s+(?P<rest>.+)$', command)
        if not match:
            return None

        exe_token = match.group("exe").strip().strip("\"'")
        exe_name = Path(exe_token).name.lower()
        if exe_name not in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            return None

        rest = match.group("rest")
        body_match = re.search(r'(?i)(?:^|\s)-(?:command|c)\s+(?P<body>.+)$', rest)
        if not body_match:
            return None

        body = body_match.group("body").strip()
        if len(body) >= 2 and body[0] == body[-1] and body[0] in {'"', "'"}:
            body = body[1:-1]
        return body.strip() or None

    async def _execute_via_windows_broker(
        self,
        command: str,
        cwd: str,
        timeout: int,
        env: dict[str, str],
    ) -> tuple[bytes, bytes, int, bool]:
        async with self._get_windows_broker_lock():
            broker = await self._ensure_windows_broker(self._preferred_windows_shell(), env)
            return await self._send_windows_broker_request(broker, command, cwd, timeout)

    @classmethod
    def _get_windows_broker_lock(cls) -> asyncio.Lock:
        if cls._windows_broker_lock is None:
            cls._windows_broker_lock = asyncio.Lock()
        return cls._windows_broker_lock

    async def _ensure_windows_broker(
        self,
        shell_exe: str,
        env: dict[str, str],
    ) -> _WindowsElevatedBrokerSession:
        broker = self.__class__._windows_broker
        if broker is not None and self._windows_broker_is_available(broker):
            return broker

        if broker is not None:
            self._shutdown_windows_broker_session(broker)
            self.__class__._windows_broker = None

        broker = await self._launch_windows_broker(shell_exe, env)
        self.__class__._windows_broker = broker
        if not self.__class__._windows_broker_atexit_registered:
            atexit.register(self._shutdown_shared_windows_broker)
            self.__class__._windows_broker_atexit_registered = True
        return broker

    async def _launch_windows_broker(
        self,
        shell_exe: str,
        env: dict[str, str],
    ) -> _WindowsElevatedBrokerSession:
        session_dir = Path(tempfile.mkdtemp(prefix="forensic-claw-elevated-broker-"))
        broker = _WindowsElevatedBrokerSession(
            session_dir=session_dir,
            shell_exe=shell_exe,
            token=uuid.uuid4().hex,
            broker_script_path=session_dir / "broker.ps1",
            request_path=session_dir / "request.json",
            response_path=session_dir / "response.json",
            ready_path=session_dir / "ready.json",
            stop_path=session_dir / "stop.txt",
        )
        broker.broker_script_path.write_text(
            self._build_windows_broker_script(),
            encoding="utf-8",
        )

        launcher_script = self._build_windows_broker_launcher_script(broker)
        encoded_launcher = base64.b64encode(launcher_script.encode("utf-16-le")).decode("ascii")
        process = await asyncio.create_subprocess_exec(
            shell_exe,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded_launcher,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.working_dir or os.getcwd(),
            env=env,
            creationflags=self._windows_creationflags(),
        )
        stdout, stderr, timed_out = await self._collect_output(process, self._BROKER_STARTUP_TIMEOUT)
        if timed_out:
            self._cleanup_windows_broker_files(broker)
            raise RuntimeError("Timed out while starting the elevated Windows broker")
        if process.returncode != 0 or not broker.ready_path.is_file():
            self._cleanup_windows_broker_files(broker)
            detail = self._decode_output(stderr or stdout).strip() or "unknown error"
            raise RuntimeError(f"Failed to start elevated Windows broker: {detail}")
        return broker

    async def _send_windows_broker_request(
        self,
        broker: _WindowsElevatedBrokerSession,
        command: str,
        cwd: str,
        timeout: int,
    ) -> tuple[bytes, bytes, int, bool]:
        request_id = uuid.uuid4().hex
        request_payload = {
            "requestId": request_id,
            "token": broker.token,
            "commandBase64": base64.b64encode(command.encode("utf-8")).decode("ascii"),
            "cwd": cwd,
            "timeoutS": timeout,
        }

        for path in (broker.request_path, broker.response_path):
            try:
                path.unlink()
            except FileNotFoundError:
                pass

        tmp_request_path = broker.session_dir / f"{request_id}.json.tmp"
        tmp_request_path.write_text(
            json.dumps(request_payload, ensure_ascii=False),
            encoding="utf-8",
        )
        tmp_request_path.replace(broker.request_path)

        deadline = time.monotonic() + timeout + self._BROKER_RESPONSE_GRACE
        while time.monotonic() < deadline:
            if broker.response_path.is_file():
                payload = json.loads(broker.response_path.read_text(encoding="utf-8-sig"))
                broker.response_path.unlink(missing_ok=True)
                if payload.get("requestId") != request_id:
                    raise RuntimeError("Elevated broker returned a mismatched response")
                stdout = base64.b64decode(payload.get("stdoutBase64", "") or "")
                stderr = base64.b64decode(payload.get("stderrBase64", "") or "")
                exit_code = int(payload.get("exitCode", 1))
                timed_out = bool(payload.get("timedOut", False))
                return stdout, stderr, exit_code, timed_out
            await asyncio.sleep(0.1)

        self._shutdown_windows_broker_session(broker)
        self.__class__._windows_broker = None
        raise RuntimeError("Timed out waiting for the elevated Windows broker response")

    @classmethod
    def _build_windows_broker_launcher_script(cls, broker: _WindowsElevatedBrokerSession) -> str:
        shell_literal = cls._powershell_single_quote(broker.shell_exe)
        broker_path_literal = cls._powershell_single_quote(str(broker.broker_script_path))
        session_literal = cls._powershell_single_quote(str(broker.session_dir))
        token_literal = cls._powershell_single_quote(broker.token)
        ready_literal = cls._powershell_single_quote(str(broker.ready_path))
        return (
            "$ErrorActionPreference = 'Stop'\n"
            f"$readyPath = {ready_literal}\n"
            "$deadline = [DateTime]::UtcNow.AddSeconds(30)\n"
            "try {\n"
            f"    $proc = Start-Process -FilePath {shell_literal} "
            "-ArgumentList @("
            "'-NoLogo',"
            "'-NoProfile',"
            "'-NonInteractive',"
            "'-ExecutionPolicy',"
            "'Bypass',"
            "'-File',"
            f"{broker_path_literal},"
            "'-SessionDir',"
            f"{session_literal},"
            "'-Token',"
            f"{token_literal},"
            "'-ShellPath',"
            f"{shell_literal}"
            ") -Verb RunAs -PassThru -WindowStyle Hidden\n"
            "    while ([DateTime]::UtcNow -lt $deadline) {\n"
            "        if (Test-Path -LiteralPath $readyPath) { exit 0 }\n"
            "        $proc.Refresh()\n"
            "        if ($proc.HasExited) { exit $proc.ExitCode }\n"
            "        Start-Sleep -Milliseconds 200\n"
            "    }\n"
            "    Write-Error 'Timed out waiting for the elevated broker startup.'\n"
            "    exit 1\n"
            "} catch {\n"
            "    $_ | Out-String | Write-Error\n"
            "    exit 1\n"
            "}\n"
        )

    @staticmethod
    def _build_windows_broker_script() -> str:
        return r"""
param(
    [Parameter(Mandatory = $true)][string]$SessionDir,
    [Parameter(Mandatory = $true)][string]$Token,
    [Parameter(Mandatory = $true)][string]$ShellPath
)

$ErrorActionPreference = 'Continue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

function Write-ForensicClawBrokerJson {
    param(
        [Parameter(Mandatory = $true)]$Payload,
        [Parameter(Mandatory = $true)][string]$TargetPath
    )

    $tmpPath = $TargetPath + '.tmp'
    $json = $Payload | ConvertTo-Json -Compress
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText($tmpPath, $json, $utf8NoBom)
    Move-Item -LiteralPath $tmpPath -Destination $TargetPath -Force
}

function Invoke-ForensicClawCommand {
    param(
        [Parameter(Mandatory = $true)][string]$CommandBase64,
        [Parameter(Mandatory = $true)][string]$WorkingDir,
        [Parameter(Mandatory = $true)][int]$TimeoutS,
        [Parameter(Mandatory = $true)][string]$ShellPath,
        [Parameter(Mandatory = $true)][string]$SessionDir
    )

    $tempDir = Join-Path $SessionDir ('run-' + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    $stdoutPath = Join-Path $tempDir 'stdout.bin'
    $stderrPath = Join-Path $tempDir 'stderr.bin'
    $childPath = Join-Path $tempDir 'command.ps1'

    $workingDirLiteral = "'" + $WorkingDir.Replace("'", "''") + "'"
    $childTemplate = @'
$ErrorActionPreference = 'Continue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
Set-Location -LiteralPath __WORKING_DIR__
$commandText = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__COMMAND_BASE64__'))
& ([scriptblock]::Create($commandText))
if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE }
elseif ($?) { exit 0 } else { exit 1 }
'@
    $childScript = $childTemplate.Replace('__WORKING_DIR__', $workingDirLiteral).Replace('__COMMAND_BASE64__', $CommandBase64)
    Set-Content -LiteralPath $childPath -Value $childScript -Encoding utf8

    $process = Start-Process -FilePath $ShellPath `
        -ArgumentList @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $childPath) `
        -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $timedOut = $false
    try {
        Wait-Process -Id $process.Id -Timeout $TimeoutS -ErrorAction Stop
    } catch {
        $timedOut = $true
        taskkill /T /F /PID $process.Id | Out-Null
        try {
            Wait-Process -Id $process.Id -Timeout 5 -ErrorAction SilentlyContinue
        } catch {
        }
    }

    $process.Refresh()
    $stdoutBytes = if (Test-Path -LiteralPath $stdoutPath) { [System.IO.File]::ReadAllBytes($stdoutPath) } else { [byte[]]::new(0) }
    $stderrBytes = if (Test-Path -LiteralPath $stderrPath) { [System.IO.File]::ReadAllBytes($stderrPath) } else { [byte[]]::new(0) }
    $exitCode = if ($timedOut) { 1 } elseif ($process.HasExited) { $process.ExitCode } else { 1 }

    Remove-Item -LiteralPath $tempDir -Recurse -Force -ErrorAction SilentlyContinue

    return @{
        stdoutBase64 = [Convert]::ToBase64String($stdoutBytes)
        stderrBase64 = [Convert]::ToBase64String($stderrBytes)
        exitCode = $exitCode
        timedOut = $timedOut
    }
}

$requestPath = Join-Path $SessionDir 'request.json'
$responsePath = Join-Path $SessionDir 'response.json'
$readyPath = Join-Path $SessionDir 'ready.json'
$stopPath = Join-Path $SessionDir 'stop.txt'

$readyPayload = @{
    pid = $PID
    startedAt = (Get-Date).ToString('o')
    shellPath = $ShellPath
}
Write-ForensicClawBrokerJson -Payload $readyPayload -TargetPath $readyPath

while ($true) {
    if (Test-Path -LiteralPath $stopPath) {
        break
    }

    if (-not (Test-Path -LiteralPath $requestPath)) {
        Start-Sleep -Milliseconds 150
        continue
    }

    $request = $null
    try {
        $request = Get-Content -LiteralPath $requestPath -Raw | ConvertFrom-Json
    } catch {
        $response = @{
            requestId = ''
            stdoutBase64 = ''
            stderrBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($_ | Out-String)))
            exitCode = 1
            timedOut = $false
        }
        Write-ForensicClawBrokerJson -Payload $response -TargetPath $responsePath
        Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue
        continue
    }

    Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue

    try {
        if ([string]$request.token -ne $Token) {
            throw 'Invalid broker token'
        }
        $response = Invoke-ForensicClawCommand `
            -CommandBase64 ([string]$request.commandBase64) `
            -WorkingDir ([string]$request.cwd) `
            -TimeoutS ([int]$request.timeoutS) `
            -ShellPath $ShellPath `
            -SessionDir $SessionDir
        $response.requestId = [string]$request.requestId
    } catch {
        $response = @{
            requestId = [string]$request.requestId
            stdoutBase64 = ''
            stderrBase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(($_ | Out-String)))
            exitCode = 1
            timedOut = $false
        }
    }

    Write-ForensicClawBrokerJson -Payload $response -TargetPath $responsePath
}
"""

    @staticmethod
    def _windows_broker_is_available(broker: _WindowsElevatedBrokerSession) -> bool:
        return broker.session_dir.is_dir() and broker.ready_path.is_file()

    @classmethod
    def _shutdown_shared_windows_broker(cls) -> None:
        broker = cls._windows_broker
        if broker is None:
            return
        cls._shutdown_windows_broker_session(broker)
        cls._windows_broker = None

    @classmethod
    def _disable_windows_broker(cls) -> None:
        cls._shutdown_shared_windows_broker()
        cls._windows_broker_disabled = True

    @staticmethod
    def _shutdown_windows_broker_session(broker: _WindowsElevatedBrokerSession) -> None:
        try:
            broker.stop_path.write_text("stop\n", encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _cleanup_windows_broker_files(broker: _WindowsElevatedBrokerSession) -> None:
        ExecTool._shutdown_windows_broker_session(broker)
        try:
            shutil.rmtree(broker.session_dir, ignore_errors=True)
        except OSError:
            pass

    @staticmethod
    def _powershell_single_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    @staticmethod
    def _is_windows_admin() -> bool:
        if sys.platform != "win32":
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def _windows_creationflags() -> int:
        return getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0

    def _guard_command(self, command: str, cwd: str) -> str | None:
        """Best-effort safety guard for potentially destructive commands."""
        cmd = command.strip()
        lower = cmd.lower()

        for pattern in self.deny_patterns:
            if re.search(pattern, lower):
                return "Error: Command blocked by safety guard (dangerous pattern detected)"

        if self.allow_patterns:
            if not any(re.search(p, lower) for p in self.allow_patterns):
                return "Error: Command blocked by safety guard (not in allowlist)"

        from forensic_claw.security.network import contains_internal_url

        if contains_internal_url(cmd):
            return "Error: Command blocked by safety guard (internal/private URL detected)"

        if self.restrict_to_workspace:
            if "..\\" in cmd or "../" in cmd:
                return "Error: Command blocked by safety guard (path traversal detected)"

            cwd_path = Path(cwd).resolve()
            outside_paths: list[Path] = []
            for raw in self._extract_absolute_paths(cmd):
                if self._looks_like_windows_switch_token(raw, cmd):
                    continue
                try:
                    expanded = os.path.expandvars(raw.strip())
                    p = Path(expanded).expanduser().resolve()
                except Exception:
                    continue
                if p.is_absolute() and cwd_path not in p.parents and p != cwd_path:
                    outside_paths.append(p)

            for path in outside_paths:
                if self._is_allowed_forensic_path(path):
                    continue
                if self._is_allowed_forensic_registry_export(cmd, path, outside_paths):
                    continue
                return "Error: Command blocked by safety guard (path outside working dir)"

        return None

    @staticmethod
    def _is_allowed_forensic_path(path: Path) -> bool:
        normalized = str(path).replace("/", "\\").lower()
        basename = path.name.lower()

        if basename == "layout.ini" or path.suffix.lower() in {".evtx", ".pf"}:
            return True
        if basename in ExecTool._PORTABLE_HIVE_BASENAMES:
            return True
        if basename in ExecTool._NTFS_METADATA_BASENAMES:
            return True
        if "\\windows\\prefetch" in normalized:
            return True
        if "\\windows\\system32\\winevt\\logs\\" in normalized:
            return True
        if "\\windows\\system32\\sru\\" in normalized and basename == "srudb.dat":
            return True
        if (
            "\\windows\\system32\\config\\" in normalized
            and basename in ExecTool._WINDOWS_CONFIG_HIVE_BASENAMES
        ):
            return True
        return False

    @classmethod
    def _is_allowed_forensic_registry_export(
        cls,
        command: str,
        path: Path,
        outside_paths: list[Path],
    ) -> bool:
        if len(outside_paths) != 1 or outside_paths[0] != path:
            return False

        match = re.search(
            r"""(?ix)
            \breg(?:\.exe)?\s+
            (?P<verb>save|export)\s+
            (?P<key>"[^"]+"|'[^']+'|\S+)
            """,
            command,
        )
        if not match:
            return False

        key = match.group("key").strip().strip("\"'")
        normalized_key = key.replace("/", "\\").lower()
        return any(
            normalized_key == root or normalized_key.startswith(root + "\\")
            for root in cls._FORENSIC_REGISTRY_ROOTS
        )

    @staticmethod
    def _looks_like_windows_switch_token(token: str, command: str) -> bool:
        return (
            token.startswith("/")
            and "\\" in command
            and re.fullmatch(r"/[A-Za-z0-9?][A-Za-z0-9:-]*", token) is not None
        )

    @staticmethod
    def _extract_absolute_paths(command: str) -> list[str]:
        win_paths = re.findall(r"[A-Za-z]:\\[^\s\"'|><;]+", command)
        posix_paths = re.findall(r"(?:^|[\s|>'\"])(/[^\s\"'>;|<]+)", command)
        home_paths = re.findall(r"(?:^|[\s|>'\"])(~[^\s\"'>;|<]*)", command)
        return win_paths + posix_paths + home_paths
