"""Shell execution tool."""

import asyncio
import base64
import locale
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from loguru import logger

from forensic_claw.agent.tools.base import Tool
from forensic_claw.utils.event_logs import compact_windows_event_log_output


class ExecTool(Tool):
    """Tool to execute shell commands."""

    _MAX_TIMEOUT = 600
    _MAX_OUTPUT = 10_000
    _OUTPUT_ENCODINGS = (
        "utf-8-sig",
        "utf-8",
        "cp949",
    )

    def __init__(
        self,
        timeout: int = 60,
        working_dir: str | None = None,
        deny_patterns: list[str] | None = None,
        allow_patterns: list[str] | None = None,
        restrict_to_workspace: bool = False,
        path_append: str = "",
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

    @property
    def name(self) -> str:
        return "exec"

    @property
    def description(self) -> str:
        return "Execute a shell command and return its output. Use with caution."

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
        cwd = working_dir or self.working_dir or os.getcwd()
        guard_error = self._guard_command(command, cwd)
        if guard_error:
            return guard_error

        effective_timeout = min(timeout or self.timeout, self._MAX_TIMEOUT)
        env = self._build_env()

        try:
            process = await self._spawn_process(command, cwd, env)
            stdout, stderr, timed_out = await self._collect_output(process, effective_timeout)
            if timed_out:
                return f"Error: Command timed out after {effective_timeout} seconds"

            output_parts: list[str] = []

            if stdout:
                stdout_text = self._decode_output(stdout)
                output_parts.append(self._postprocess_stdout(stdout_text))

            if stderr:
                stderr_text = self._decode_output(stderr)
                if stderr_text.strip():
                    output_parts.append(f"STDERR:\n{stderr_text}")

            output_parts.append(f"\nExit code: {process.returncode}")

            result = "\n".join(output_parts) if output_parts else "(no output)"
            if len(result) > self._MAX_OUTPUT:
                half = self._MAX_OUTPUT // 2
                result = (
                    result[:half]
                    + f"\n\n... ({len(result) - self._MAX_OUTPUT:,} chars truncated) ...\n\n"
                    + result[-half:]
                )

            return result
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
        cwd = working_dir or self.working_dir or os.getcwd()
        effective_timeout = min(timeout or self.timeout, self._MAX_TIMEOUT)

        if sys.platform == "win32":
            shell_exe = self._preferred_windows_shell()
            return {
                "command": command,
                "workingDir": cwd,
                "timeout": effective_timeout,
                "platform": "windows",
                "shell": Path(shell_exe).name or shell_exe,
                "shellPath": shell_exe,
                "launcher": (
                    f"{shell_exe} -NoLogo -NoProfile -NonInteractive "
                    "-ExecutionPolicy Bypass -EncodedCommand <base64>"
                ),
                "wrapper": "PowerShell wrapper enables UTF-8 console I/O before running the command.",
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
            for raw in self._extract_absolute_paths(cmd):
                try:
                    expanded = os.path.expandvars(raw.strip())
                    p = Path(expanded).expanduser().resolve()
                except Exception:
                    continue
                if p.is_absolute() and cwd_path not in p.parents and p != cwd_path:
                    return "Error: Command blocked by safety guard (path outside working dir)"

        return None

    @staticmethod
    def _extract_absolute_paths(command: str) -> list[str]:
        win_paths = re.findall(r"[A-Za-z]:\\[^\s\"'|><;]+", command)
        posix_paths = re.findall(r"(?:^|[\s|>'\"])(/[^\s\"'>;|<]+)", command)
        home_paths = re.findall(r"(?:^|[\s|>'\"])(~[^\s\"'>;|<]*)", command)
        return win_paths + posix_paths + home_paths
