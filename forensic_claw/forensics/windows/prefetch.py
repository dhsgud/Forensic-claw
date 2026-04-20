"""Prefetch artifact parsing and case-store integration."""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable

from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.models import ArtifactUpdateResult, PrefetchArtifact

PECmdRunner = Callable[..., str]
_LAYOUT_ENCODINGS = ("utf-8-sig", "utf-16", "utf-8", "cp949")
_PECMD_OUTPUT_ENCODINGS = ("utf-8-sig", "utf-8", "cp949")


def _load_text_payload(path: Path) -> str:
    raw = path.read_bytes()
    for encoding in _LAYOUT_ENCODINGS:
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace")


def _bundled_pecmd_candidates() -> list[Path]:
    package_root = Path(__file__).resolve().parents[2]
    project_root = package_root.parent
    return [
        package_root / "forensic-tool" / "PECmd" / "PECmd.exe",
        project_root / "Forensics-tool" / "PECmd" / "PECmd.exe",
        project_root / "forensic-tool" / "PECmd" / "PECmd.exe",
    ]


def _bundled_dotnet_root_candidates() -> list[Path]:
    package_root = Path(__file__).resolve().parents[2]
    project_root = package_root.parent
    return [
        package_root / "forensic-tool" / "dotnet" / "win-x64",
        package_root / "forensic-tool" / "dotnet",
        project_root / "Forensics-tool" / "dotnet" / "win-x64",
        project_root / "Forensics-tool" / "dotnet",
        project_root / "forensic-tool" / "dotnet" / "win-x64",
        project_root / "forensic-tool" / "dotnet",
    ]


def _resolve_dotnet_root() -> Path | None:
    configured_root = os.environ.get("FORENSIC_CLAW_DOTNET_ROOT")
    if configured_root:
        candidate = Path(configured_root).expanduser()
        if (candidate / "dotnet.exe").is_file():
            return candidate

    configured_dotnet = os.environ.get("FORENSIC_CLAW_DOTNET_PATH")
    if configured_dotnet:
        candidate = Path(configured_dotnet).expanduser()
        if candidate.is_file():
            return candidate.parent

    for candidate in _bundled_dotnet_root_candidates():
        if (candidate / "dotnet.exe").is_file():
            return candidate

    if resolved := shutil.which("dotnet"):
        return Path(resolved).resolve().parent
    return None


def _resolve_pecmd_executable() -> str:
    for candidate in _bundled_pecmd_candidates():
        if candidate.is_file():
            return str(candidate)

    configured = os.environ.get("FORENSIC_CLAW_PECMD_PATH")
    if configured:
        candidate = Path(configured).expanduser()
        if candidate.exists():
            return str(candidate)

    for name in ("PECmd.exe", "PECmd"):
        if resolved := shutil.which(name):
            return resolved

    raise FileNotFoundError(
        "PECmd.exe not found. Bundle it under forensic_claw/forensic-tool/PECmd, add it to "
        "PATH, or set FORENSIC_CLAW_PECMD_PATH."
    )


def _pecmd_runtime_requirement(pecmd_path: str | Path) -> str | None:
    runtimeconfig = Path(pecmd_path).with_suffix(".runtimeconfig.json")
    if not runtimeconfig.is_file():
        return None
    try:
        payload = json.loads(runtimeconfig.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None

    framework = payload.get("runtimeOptions", {}).get("framework", {})
    name = framework.get("name")
    version = framework.get("version")
    if not isinstance(name, str) or not isinstance(version, str):
        return None
    return f"{name} {version}"


def _pecmd_runtime_install_hint() -> str:
    return (
        " Bundle a portable runtime under forensic_claw/forensic-tool/dotnet/win-x64 "
        "or set FORENSIC_CLAW_DOTNET_ROOT / FORENSIC_CLAW_DOTNET_PATH."
    )


def _build_pecmd_failure_detail(
    prefetch_path: Path,
    pecmd_path: str | Path,
    completed: subprocess.CompletedProcess[str],
) -> str:
    detail = completed.stderr.strip() or completed.stdout.strip() or "unknown error"
    lowered = detail.lower()
    runtime_requirement = _pecmd_runtime_requirement(pecmd_path)
    if ".net" in lowered or "framework" in lowered or "dotnet" in lowered:
        suffix = f" Required runtime: {runtime_requirement}." if runtime_requirement else ""
        return (
            f"PECmd failed for {prefetch_path}: missing .NET runtime or framework dependency."
            f"{suffix}{_pecmd_runtime_install_hint()} Original error: {detail}"
        )
    return f"PECmd failed for {prefetch_path}: {detail}"


def _decode_pecmd_output(data: bytes) -> str:
    for encoding in _PECMD_OUTPUT_ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def _build_pecmd_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("DOTNET_ROLL_FORWARD", "Major")

    dotnet_root = _resolve_dotnet_root()
    if dotnet_root is not None:
        env.setdefault("DOTNET_ROOT", str(dotnet_root))
        env.setdefault("DOTNET_MULTILEVEL_LOOKUP", "0")
    return env


def _run_pecmd_via_windows_wrapper(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    shell_exe = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
    with TemporaryDirectory(prefix="forensic-claw-pecmd-logs-") as tmp_dir:
        stdout_path = Path(tmp_dir) / "stdout.bin"
        stderr_path = Path(tmp_dir) / "stderr.bin"
        payload = {
            "filePath": command[0],
            "arguments": command[1:],
            "workingDir": str(cwd),
            "stdoutPath": str(stdout_path),
            "stderrPath": str(stderr_path),
        }
        encoded_payload = base64.b64encode(
            json.dumps(payload, ensure_ascii=False).encode("utf-8")
        ).decode("ascii")
        launcher_script = (
            "$ErrorActionPreference = 'Stop'\n"
            "$ProgressPreference = 'SilentlyContinue'\n"
            f"$payloadJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_payload}'))\n"
            "$payload = $payloadJson | ConvertFrom-Json\n"
            "$proc = Start-Process "
            "-FilePath ([string]$payload.filePath) "
            "-ArgumentList @($payload.arguments) "
            "-WorkingDirectory ([string]$payload.workingDir) "
            "-PassThru -Wait -WindowStyle Hidden "
            "-RedirectStandardOutput ([string]$payload.stdoutPath) "
            "-RedirectStandardError ([string]$payload.stderrPath)\n"
            "[byte[]]$stdoutBytes = @()\n"
            "if (Test-Path -LiteralPath $payload.stdoutPath) { "
            "$stdoutBytes = [System.IO.File]::ReadAllBytes([string]$payload.stdoutPath) }\n"
            "[byte[]]$stderrBytes = @()\n"
            "if (Test-Path -LiteralPath $payload.stderrPath) { "
            "$stderrBytes = [System.IO.File]::ReadAllBytes([string]$payload.stderrPath) }\n"
            "$response = @{\n"
            "  exitCode = $proc.ExitCode\n"
            "  stdoutBase64 = [Convert]::ToBase64String($stdoutBytes)\n"
            "  stderrBase64 = [Convert]::ToBase64String($stderrBytes)\n"
            "}\n"
            "$response | ConvertTo-Json -Compress\n"
        )
        encoded_script = base64.b64encode(launcher_script.encode("utf-16-le")).decode("ascii")
        wrapper = subprocess.run(
            [
                shell_exe,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded_script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            cwd=str(cwd),
            env=env,
        )
        if wrapper.returncode != 0:
            return subprocess.CompletedProcess(
                args=command,
                returncode=wrapper.returncode,
                stdout=wrapper.stdout,
                stderr=wrapper.stderr,
            )

        try:
            response = json.loads(wrapper.stdout.strip())
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"PECmd wrapper did not return valid JSON: {wrapper.stdout.strip() or wrapper.stderr.strip()}"
            ) from exc

        return subprocess.CompletedProcess(
            args=command,
            returncode=int(response.get("exitCode", 1)),
            stdout=_decode_pecmd_output(base64.b64decode(response.get("stdoutBase64", "") or "")),
            stderr=_decode_pecmd_output(base64.b64decode(response.get("stderrBase64", "") or "")),
        )


def _run_pecmd_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    if sys.platform == "win32":
        return _run_pecmd_via_windows_wrapper(command, cwd=cwd, env=env)

    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        cwd=str(cwd),
        env=env,
    )


def run_pecmd_prefetch(
    prefetch_path: Path,
    *,
    runner: PECmdRunner | None = None,
) -> str:
    if runner is not None:
        return str(runner(prefetch_path=prefetch_path))

    resolved_prefetch_path = prefetch_path.resolve(strict=False)
    pecmd = _resolve_pecmd_executable()
    with TemporaryDirectory(prefix="forensic-claw-pecmd-") as tmp_dir:
        output_dir = Path(tmp_dir)
        output_name = "pecmd-output.json"
        command = [
            pecmd,
            "-f",
            str(resolved_prefetch_path),
            "--json",
            str(output_dir),
            "--jsonf",
            output_name,
            "--dt",
            "o",
            "-q",
        ]
        completed = _run_pecmd_process(
            command,
            cwd=resolved_prefetch_path.parent,
            env=_build_pecmd_env(),
        )
        if completed.returncode != 0:
            raise RuntimeError(_build_pecmd_failure_detail(prefetch_path, pecmd, completed))

        output_path = output_dir / output_name
        if not output_path.is_file():
            detail = completed.stderr.strip() or completed.stdout.strip() or "no diagnostic output"
            raise FileNotFoundError(
                f"PECmd did not create JSON output for {prefetch_path}. Output: {detail}"
            )
        return output_path.read_text(encoding="utf-8", errors="replace")


def _parse_pecmd_records(text: str) -> list[dict[str, Any]]:
    stripped = text.strip()
    if not stripped:
        raise ValueError("PECmd output was empty")

    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            return [payload]

    if stripped.startswith("["):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

    records: list[dict[str, Any]] = []
    for raw_line in stripped.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        payload = json.loads(line)
        if isinstance(payload, dict):
            records.append(payload)
    if not records:
        raise ValueError("PECmd output did not contain any JSON records")
    return records


def _find_matching_record(records: list[dict[str, Any]], prefetch_path: Path) -> dict[str, Any]:
    normalized = prefetch_path.resolve(strict=False).as_posix().lower()
    filename = prefetch_path.name.lower()
    for record in records:
        source_filename = str(record.get("SourceFilename") or "").replace("\\", "/").lower()
        if source_filename.endswith(filename) or source_filename == normalized:
            return record
    return records[0]


def _split_csv_items(value: Any) -> list[str]:
    if not isinstance(value, str):
        return []
    parts = [item.strip() for item in value.split(",")]
    seen: set[str] = set()
    items: list[str] = []
    for part in parts:
        if not part or part in seen:
            continue
        seen.add(part)
        items.append(part)
    return items


def _collect_run_times(record: dict[str, Any]) -> list[str]:
    values = [record.get("LastRun")]
    values.extend(record.get(f"PreviousRun{index}") for index in range(7))

    seen: set[str] = set()
    run_times: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        run_times.append(cleaned)
    return run_times


def _auto_layout_path(prefetch_path: Path) -> Path | None:
    for name in ("Layout.ini", "layout.ini"):
        candidate = prefetch_path.parent / name
        if candidate.is_file():
            return candidate
    return None


def parse_layout_prefetch_entries(path: Path) -> list[str]:
    text = _load_text_payload(path)
    entries: list[str] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[") or line.startswith(";"):
            continue
        if not line.lower().endswith(".pf"):
            continue
        if line in seen:
            continue
        seen.add(line)
        entries.append(line)
    return entries


def _render_layout_prefetch_file(artifact: PrefetchArtifact) -> str:
    if artifact.layout_prefetch_entries:
        return "\n".join(artifact.layout_prefetch_entries) + "\n"
    return (
        "# Layout.ini parsed successfully, but no .pf entries were found.\n"
        f"# layout_prefetch_entry_count={artifact.layout_prefetch_entry_count}\n"
    )


def parse_prefetch_artifact(
    path: Path,
    *,
    layout_path: Path | None = None,
    runner: PECmdRunner | None = None,
) -> tuple[PrefetchArtifact, str]:
    raw_output = run_pecmd_prefetch(path, runner=runner)
    record = _find_matching_record(_parse_pecmd_records(raw_output), path)

    executable_name = record.get("ExecutableName")
    if not isinstance(executable_name, str) or not executable_name.strip():
        raise ValueError("PECmd output missing ExecutableName")

    run_count = record.get("RunCount")
    if isinstance(run_count, str) and run_count.strip():
        run_count = int(run_count)
    elif not isinstance(run_count, int):
        run_count = None

    resolved_layout = layout_path if layout_path and layout_path.is_file() else None
    layout_prefetch_entries = (
        parse_layout_prefetch_entries(resolved_layout) if resolved_layout is not None else []
    )

    artifact = PrefetchArtifact(
        executable_name=executable_name.strip(),
        run_count=run_count,
        last_run_times=_collect_run_times(record),
        referenced_files=_split_csv_items(record.get("FilesLoaded")),
        directories=_split_csv_items(record.get("Directories")),
        prefetch_hash=str(record["Hash"]).strip() if record.get("Hash") is not None else None,
        version=str(record["Version"]).strip() if record.get("Version") is not None else None,
        source_filename=(
            str(record["SourceFilename"]).strip()
            if record.get("SourceFilename") is not None
            else None
        ),
        layout_ini_path=str(resolved_layout) if resolved_layout is not None else None,
        layout_prefetch_entries=layout_prefetch_entries,
        layout_prefetch_entry_count=len(layout_prefetch_entries),
    )
    return artifact, raw_output


def _resolve_prefetch_input(
    store: CaseStore,
    *,
    case_id: str,
    source_id: str | None,
    prefetch_path: str | Path | None,
    layout_path: str | Path | None,
) -> tuple[Path, str | None, Path | None]:
    explicit_layout = Path(layout_path) if layout_path is not None else None
    if explicit_layout is not None and not explicit_layout.is_file():
        raise FileNotFoundError(f"Layout.ini not found: {explicit_layout}")

    if prefetch_path is not None:
        target_path = Path(prefetch_path)
        return target_path, None, explicit_layout or _auto_layout_path(target_path)
    if not source_id:
        raise ValueError("Either prefetch_path or source_id is required")

    source = store.load_source(case_id, source_id)
    target_path: Path | None = None
    resolved_layout = explicit_layout
    for candidate in store.get_source_file_paths(case_id, source_id):
        lowered_name = candidate.name.lower()
        if target_path is None and (candidate.suffix.lower() == ".pf" or lowered_name.endswith(".pf")):
            target_path = candidate
        if resolved_layout is None and lowered_name == "layout.ini":
            resolved_layout = candidate
    if target_path is not None:
        return target_path, source_id, resolved_layout or _auto_layout_path(target_path)
    if source.origin_path:
        target_path = Path(source.origin_path)
        return target_path, source_id, resolved_layout or _auto_layout_path(target_path)
    raise FileNotFoundError(f"No prefetch payload found for source {source_id}")


def analyze_prefetch_artifact(
    store: CaseStore,
    *,
    case_id: str,
    prefetch_path: str | Path | None = None,
    source_id: str | None = None,
    layout_path: str | Path | None = None,
    runner: PECmdRunner | None = None,
) -> ArtifactUpdateResult:
    target_path, existing_source_id, resolved_layout_path = _resolve_prefetch_input(
        store,
        case_id=case_id,
        source_id=source_id,
        prefetch_path=prefetch_path,
        layout_path=layout_path,
    )
    artifact, raw_output = parse_prefetch_artifact(
        target_path,
        layout_path=resolved_layout_path,
        runner=runner,
    )

    source = (
        store.load_source(case_id, existing_source_id)
        if existing_source_id
        else store.add_source(
            case_id,
            kind="prefetch",
            source_path=target_path,
            parser="windows_prefetch_analyze",
        )
    )
    summary = (
        f"{artifact.executable_name} execution artifact"
        + (f" | run_count={artifact.run_count}" if artifact.run_count is not None else "")
        + (
            f" | referenced_files={len(artifact.referenced_files)}"
            if artifact.referenced_files
            else ""
        )
        + (
            f" | layout_prefetch_entries={artifact.layout_prefetch_entry_count}"
            if artifact.layout_ini_path is not None
            else ""
        )
    )
    evidence_files: dict[str, str] = {
        "summary.json": json.dumps(
            {
                "executableName": artifact.executable_name,
                "runCount": artifact.run_count,
                "lastRunTimes": artifact.last_run_times,
                "referencedFiles": artifact.referenced_files,
                "directories": artifact.directories,
                "prefetchHash": artifact.prefetch_hash,
                "version": artifact.version,
                "sourceFilename": artifact.source_filename,
                "layoutIniPath": artifact.layout_ini_path,
                "layoutPrefetchEntries": artifact.layout_prefetch_entries,
                "layoutPrefetchEntryCount": artifact.layout_prefetch_entry_count,
                "parserBackend": "PECmd",
            },
            ensure_ascii=False,
            indent=2,
        ),
        "pecmd-output.jsonl": raw_output if raw_output.endswith("\n") else f"{raw_output}\n",
    }
    if artifact.layout_ini_path is not None:
        evidence_files["layout-prefetch-files.txt"] = _render_layout_prefetch_file(artifact)

    evidence = store.add_evidence(
        case_id,
        artifact_type="prefetch",
        title=f"Prefetch summary: {artifact.executable_name}",
        summary=summary,
        source_ids=[source.id or ""],
        produced_by="windows_prefetch_analyze",
        observed_at=artifact.last_run_times[0] if artifact.last_run_times else None,
        tags=["prefetch", artifact.executable_name.lower()],
        files=evidence_files,
    )
    timeline_entries = [
        store.add_timeline_entry(
            case_id,
            timestamp=timestamp,
            title=f"Prefetch execution: {artifact.executable_name}",
            description=summary,
            evidence_ids=[evidence.id or ""],
            source_ids=[source.id or ""],
            kind="prefetch",
        )
        for timestamp in artifact.last_run_times
    ]
    store.update_report_graph(
        case_id,
        report_section_id="windows-prefetch",
        report_section_title="Windows Prefetch",
        evidence_ids=[evidence.id or ""],
        source_ids=[source.id or ""],
        timeline_ids=[entry.id or "" for entry in timeline_entries],
    )
    return ArtifactUpdateResult(
        source=source,
        evidence=evidence,
        timeline_entries=timeline_entries,
        summary=summary,
    )
