"""Amcache artifact parsing and case-store integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.models import AmcacheArtifact, ArtifactUpdateResult


def _load_text_payload(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _parse_key_value_text(text: str) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data


def parse_amcache_artifact(path: Path) -> list[AmcacheArtifact]:
    text = _load_text_payload(path)
    try:
        payload = json.loads(text)
    except ValueError:
        payload = _parse_key_value_text(text)

    if isinstance(payload, dict) and "entries" in payload:
        rows = payload["entries"]
    else:
        rows = [payload]

    artifacts: list[AmcacheArtifact] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        program_name = (
            row.get("programName")
            or row.get("ProgramName")
            or row.get("fileName")
            or row.get("FileName")
        )
        if not isinstance(program_name, str) or not program_name.strip():
            continue
        artifacts.append(
            AmcacheArtifact(
                program_name=program_name.strip(),
                path=row.get("path") or row.get("Path"),
                sha1=row.get("sha1") or row.get("SHA1"),
                first_seen=row.get("firstSeen") or row.get("FirstSeen"),
                modified_at=row.get("modifiedAt") or row.get("ModifiedAt"),
            )
        )
    if not artifacts:
        raise ValueError("Amcache artifact did not contain any entries")
    return artifacts


def _resolve_amcache_input(
    store: CaseStore, *, case_id: str, source_id: str | None, hive_path: str | Path | None
) -> tuple[Path, str | None]:
    if hive_path is not None:
        return Path(hive_path), None
    if not source_id:
        raise ValueError("Either hive_path or source_id is required")

    source = store.load_source(case_id, source_id)
    for candidate in store.get_source_file_paths(case_id, source_id):
        if candidate.suffix.lower() in {".hve", ".dat", ".json"}:
            return candidate, source_id
    if source.origin_path:
        return Path(source.origin_path), source_id
    raise FileNotFoundError(f"No Amcache payload found for source {source_id}")


def analyze_amcache_artifact(
    store: CaseStore,
    *,
    case_id: str,
    hive_path: str | Path | None = None,
    source_id: str | None = None,
) -> ArtifactUpdateResult:
    target_path, existing_source_id = _resolve_amcache_input(
        store,
        case_id=case_id,
        source_id=source_id,
        hive_path=hive_path,
    )
    artifacts = parse_amcache_artifact(target_path)

    source = (
        store.load_source(case_id, existing_source_id)
        if existing_source_id
        else store.add_source(
            case_id,
            kind="amcache",
            source_path=target_path,
            parser="windows_amcache_analyze",
        )
    )
    summary = f"{len(artifacts)} Amcache entr{'y' if len(artifacts) == 1 else 'ies'} analyzed"
    observed_at = next((artifact.first_seen for artifact in artifacts if artifact.first_seen), None)
    evidence = store.add_evidence(
        case_id,
        artifact_type="amcache",
        title="Amcache execution summary",
        summary=summary,
        source_ids=[source.id or ""],
        produced_by="windows_amcache_analyze",
        observed_at=observed_at,
        tags=["amcache"],
        files={
            "summary.json": json.dumps(
                {
                    "entries": [
                        {
                            "programName": artifact.program_name,
                            "path": artifact.path,
                            "sha1": artifact.sha1,
                            "firstSeen": artifact.first_seen,
                            "modifiedAt": artifact.modified_at,
                        }
                        for artifact in artifacts
                    ]
                },
                ensure_ascii=False,
                indent=2,
            )
        },
    )

    timeline_entries = []
    for artifact in artifacts:
        if artifact.first_seen:
            timeline_entries.append(
                store.add_timeline_entry(
                    case_id,
                    timestamp=artifact.first_seen,
                    title=f"Amcache first seen: {artifact.program_name}",
                    description=artifact.path or summary,
                    evidence_ids=[evidence.id or ""],
                    source_ids=[source.id or ""],
                    kind="amcache",
                )
            )
        if artifact.modified_at:
            timeline_entries.append(
                store.add_timeline_entry(
                    case_id,
                    timestamp=artifact.modified_at,
                    title=f"Amcache modified: {artifact.program_name}",
                    description=artifact.path or summary,
                    evidence_ids=[evidence.id or ""],
                    source_ids=[source.id or ""],
                    kind="amcache",
                )
            )

    store.update_report_graph(
        case_id,
        report_section_id="windows-amcache",
        report_section_title="Windows Amcache",
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
