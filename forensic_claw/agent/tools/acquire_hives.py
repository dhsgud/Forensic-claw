"""Acquire locked Windows registry hives with on-demand UAC elevation.

The HKLM hives backing ``C:\\Windows\\System32\\config`` (SYSTEM, SOFTWARE,
SAM, SECURITY) cannot be read directly while Windows runs: they are held open
by the OS and require administrator + backup privilege. The ``RegBack`` folder
is unreliable (empty by default since Windows 10 1803). The standard live
acquisition is ``reg save HKLM\\<hive>``, which exports a readable copy of the
locked hive when run elevated. This tool runs that export, pausing to request a
UAC elevation prompt first when the process is not already elevated.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from loguru import logger

from forensic_claw.agent.tools.base import Tool

# Protected HKLM hives and the registry roots `reg save` exports them from.
_HIVES = {
    "SYSTEM": r"HKLM\SYSTEM",
    "SOFTWARE": r"HKLM\SOFTWARE",
    "SAM": r"HKLM\SAM",
    "SECURITY": r"HKLM\SECURITY",
}

# Win32 constants for ShellExecuteEx-based elevation.
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SW_HIDE = 0
ERROR_CANCELLED = 1223
INFINITE = 0xFFFFFFFF


class AcquireRegistryHivesTool(Tool):
    """Export locked HKLM registry hives, elevating via UAC when needed."""

    def __init__(self, workspace: Path, default_out: Path | None = None):
        self.workspace = Path(workspace)
        self.default_out = default_out or (self.workspace / "acquired_hives")

    @property
    def name(self) -> str:
        return "acquire_registry_hives"

    @property
    def description(self) -> str:
        return (
            "Acquire the locked Windows registry hives (SYSTEM, SOFTWARE, SAM, SECURITY) for "
            "offline forensic analysis. Those files in C:\\Windows\\System32\\config cannot be "
            "read or copied directly while Windows runs (the OS holds them open and they need "
            "administrator privileges), and the RegBack folder is usually empty on modern "
            "Windows. Use this tool whenever a normal file read or copy of those hives fails "
            "with an access-denied / permission error. If the app is not already elevated it "
            "pauses and shows a Windows UAC prompt to request administrator permission; once "
            "the user approves, it uses 'reg save' to export readable copies and returns their "
            "paths so they can then be ingested and analysed. Windows only."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "hives": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(_HIVES)},
                    "description": "Which hives to acquire. Defaults to all four.",
                },
                "output_dir": {
                    "type": ["string", "null"],
                    "description": (
                        "Destination directory for the exported hives. "
                        "Defaults to <workspace>/acquired_hives."
                    ),
                },
            },
        }

    @staticmethod
    def _normalize_hives(hives: list[str] | None) -> list[str]:
        names = [h.upper() for h in (hives or []) if isinstance(h, str) and h.upper() in _HIVES]
        # De-duplicate while preserving order; empty selection means "all".
        seen: set[str] = set()
        ordered = [n for n in names if not (n in seen or seen.add(n))]
        return ordered or list(_HIVES)

    async def execute(
        self,
        hives: list[str] | None = None,
        output_dir: str | None = None,
        **_: Any,
    ) -> Any:
        if sys.platform != "win32":
            return "Error: acquire_registry_hives is only available on Windows."

        names = self._normalize_hives(hives)
        out = Path(output_dir).expanduser() if output_dir else self.default_out
        try:
            out = out.resolve()
            out.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            return f"Error: cannot create output directory {out}: {exc}"

        try:
            result = await asyncio.to_thread(self._acquire, names, out)
        except PermissionError as exc:
            return f"Elevation declined: {exc}"
        except Exception as exc:
            logger.warning("Registry hive acquisition failed: {}", exc)
            return f"Error acquiring registry hives: {exc}"
        return json.dumps(result, ensure_ascii=False, indent=2)

    # --- synchronous workers (run off the event loop) ---

    def _acquire(self, names: list[str], out: Path) -> dict[str, Any]:
        if self._is_admin():
            saved = self._reg_save_inproc(names, out)
            mode = "already-elevated"
        else:
            saved = self._reg_save_elevated(names, out)
            mode = "uac-elevated"
        ok = [s for s in saved if s.get("ok")]
        return {
            "outputDir": str(out),
            "elevation": mode,
            "acquired": saved,
            "ready": len(ok) == len(names) and len(ok) > 0,
            "message": (
                f"Saved {len(ok)}/{len(names)} hive(s) to {out}. "
                "You can now ingest these copies for analysis."
                if ok
                else "No hives were saved. The UAC prompt may have been declined or the export failed."
            ),
        }

    @staticmethod
    def _is_admin() -> bool:
        import ctypes

        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _reg_save_inproc(self, names: list[str], out: Path) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for name in names:
            dest = out / name
            try:
                dest.unlink()
            except OSError:
                pass
            proc = subprocess.run(
                ["reg.exe", "save", _HIVES[name], str(dest), "/y"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            results.append(
                {
                    "name": name,
                    "path": str(dest),
                    "ok": dest.exists() and proc.returncode == 0,
                    "exitCode": proc.returncode,
                    "error": (proc.stderr or "").strip() or None,
                }
            )
        return results

    def _reg_save_elevated(self, names: list[str], out: Path) -> list[dict[str, Any]]:
        result_path = out / "_acquire_result.json"
        script_path = out / "_acquire_hives.ps1"
        try:
            result_path.unlink()
        except OSError:
            pass

        script = self._build_elevated_script(names, out, result_path)
        script_path.write_text(script, encoding="utf-8")
        self._run_elevated_powershell(script_path)

        if result_path.exists():
            try:
                data = json.loads(result_path.read_text(encoding="utf-8-sig"))
                if isinstance(data, dict):
                    data = [data]
                return [
                    {
                        "name": entry.get("name"),
                        "path": entry.get("path"),
                        "ok": bool(entry.get("ok")),
                        "exitCode": entry.get("exitCode"),
                    }
                    for entry in data
                ]
            except Exception as exc:
                logger.debug("Could not parse hive acquisition result: {}", exc)
        # Fall back to inferring from the on-disk output files.
        return [
            {"name": n, "path": str(out / n), "ok": (out / n).exists(), "exitCode": None}
            for n in names
        ]

    @staticmethod
    def _build_elevated_script(names: list[str], out: Path, result_path: Path) -> str:
        hive_list = ",".join(f"'{n}'" for n in names)
        map_entries = ";".join(f"'{n}'='{_HIVES[n]}'" for n in names)
        # Single-quoted here-strings keep backslashes/spaces in paths literal.
        return (
            "$ErrorActionPreference='Continue'\n"
            f"$out=@'\n{out}\n'@\n"
            f"$resultPath=@'\n{result_path}\n'@\n"
            f"$map=@{{{map_entries}}}\n"
            f"$names=@({hive_list})\n"
            "$res=@()\n"
            "foreach($n in $names){\n"
            "  $dest=Join-Path $out $n\n"
            "  Remove-Item -LiteralPath $dest -ErrorAction SilentlyContinue\n"
            "  & reg.exe save $map[$n] $dest /y *> $null\n"
            "  $res+=[pscustomobject]@{name=$n;path=$dest;ok=(Test-Path -LiteralPath $dest);exitCode=$LASTEXITCODE}\n"
            "}\n"
            "$res | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $resultPath -Encoding utf8\n"
        )

    @staticmethod
    def _run_elevated_powershell(script_path: Path) -> None:
        """Launch an elevated PowerShell running *script_path* and wait for it.

        Triggers a UAC prompt. Raises ``PermissionError`` if the user declines.
        """
        import ctypes
        from ctypes import wintypes

        class SHELLEXECUTEINFOW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE),
            ]

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(SHELLEXECUTEINFOW)]
        shell32.ShellExecuteExW.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        params = f'-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script_path}"'
        info = SHELLEXECUTEINFOW()
        info.cbSize = ctypes.sizeof(info)
        info.fMask = SEE_MASK_NOCLOSEPROCESS
        info.lpVerb = "runas"
        info.lpFile = "powershell.exe"
        info.lpParameters = params
        info.nShow = SW_HIDE

        if not shell32.ShellExecuteExW(ctypes.byref(info)):
            err = ctypes.get_last_error()
            if err == ERROR_CANCELLED:
                raise PermissionError("Administrator elevation was declined at the UAC prompt.")
            raise OSError(f"Failed to request elevation (ShellExecuteEx error {err}).")

        if not info.hProcess:
            raise OSError("Elevation did not return a process handle.")
        try:
            kernel32.WaitForSingleObject(info.hProcess, INFINITE)
        finally:
            kernel32.CloseHandle(info.hProcess)
