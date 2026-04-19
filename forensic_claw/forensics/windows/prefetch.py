"""Prefetch artifact parsing and case-store integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.models import ArtifactUpdateResult, PrefetchArtifact


def _load_text_payload(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_key_value_text(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    current_list: list[str] | None = None
    current_key: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- ") and current_list is not None:
            current_list.append(line[2:].strip())
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        current_key = key.strip()
        value = value.strip()
        if not value:
            current_list = []
            data[current_key] = current_list
        else:
            current_list = None
            data[current_key] = value
    return data


def parse_prefetch_artifact(path: Path) -> PrefetchArtifact:
    text = _load_text_payload(path)
    try:
        payload = json.loads(text)
        if not isinstance(payload, dict):
            raise ValueError
    except ValueError:
        payload = _parse_key_value_text(text)

    executable_name = payload.get("executableName") or payload.get("ExecutableName")
    if not isinstance(executable_name, str) or not executable_name.strip():
        raise ValueError("Prefetch artifact missing executable name")

    run_count = payload.get("runCount") or payload.get("RunCount")
    if run_count is not None:
        run_count = int(run_count)
    last_run_times = payload.get("lastRunTimes") or payload.get("LastRunTimes") or []
    referenced_files = payload.get("referencedFiles") or payload.get("ReferencedFiles") or []
    return PrefetchArtifact(
        executable_name=executable_name.strip(),
        run_count=run_count,
        last_run_times=[str(item) for item in last_run_times],
        referenced_files=[str(item) for item in referenced_files],
    )


def _resolve_prefetch_input(
    store: CaseStore, *, case_id: str, source_id: str | None, prefetch_path: str | Path | None
) -> tuple[Path, str | None]:
    if prefetch_path is not None:
        return Path(prefetch_path), None
    if not source_id:
        raise ValueError("Either prefetch_path or source_id is required")

    source = store.load_source(case_id, source_id)
    for candidate in store.get_source_file_paths(case_id, source_id):
        if candidate.suffix.lower() == ".pf" or candidate.name.lower().endswith(".pf"):
            return candidate, source_id
    if source.origin_path:
        return Path(source.origin_path), source_id
    raise FileNotFoundError(f"No prefetch payload found for source {source_id}")


def analyze_prefetch_artifact(
    store: CaseStore,
    *,
    case_id: str,
    prefetch_path: str | Path | None = None,
    source_id: str | None = None,
) -> ArtifactUpdateResult:
    target_path, existing_source_id = _resolve_prefetch_input(
        store,
        case_id=case_id,
        source_id=source_id,
        prefetch_path=prefetch_path,
    )
    artifact = parse_prefetch_artifact(target_path)

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
    )
    evidence = store.add_evidence(
        case_id,
        artifact_type="prefetch",
        title=f"Prefetch summary: {artifact.executable_name}",
        summary=summary,
        source_ids=[source.id or ""],
        produced_by="windows_prefetch_analyze",
        observed_at=artifact.last_run_times[0] if artifact.last_run_times else None,
        tags=["prefetch", artifact.executable_name.lower()],
        files={
            "summary.json": json.dumps(
                {
                    "executableName": artifact.executable_name,
                    "runCount": artifact.run_count,
                    "lastRunTimes": artifact.last_run_times,
                    "referencedFiles": artifact.referenced_files,
                },
                ensure_ascii=False,
                indent=2,
            )
        },
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
