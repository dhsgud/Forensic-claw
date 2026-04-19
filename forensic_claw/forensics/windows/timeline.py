"""Timeline building for Windows forensic artifacts."""

from __future__ import annotations

import json
from datetime import datetime

from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.models import TimelineBuildResult


def _parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def build_windows_timeline(
    store: CaseStore,
    *,
    case_id: str,
    evidence_ids: list[str] | None = None,
    source_ids: list[str] | None = None,
    merge_strategy: str = "chronological",
) -> TimelineBuildResult:
    if merge_strategy not in {"chronological", "dedupe"}:
        raise ValueError("merge_strategy must be 'chronological' or 'dedupe'")

    all_entries = store.read_timeline(case_id)
    normalized_evidence_ids = set(evidence_ids or [])
    normalized_source_ids = set(source_ids or [])

    entries = [
        entry
        for entry in all_entries
        if (
            not normalized_evidence_ids
            or normalized_evidence_ids.intersection(entry.evidence_ids)
            or normalized_source_ids.intersection(entry.source_ids)
        )
        and (
            not normalized_source_ids
            or normalized_source_ids.intersection(entry.source_ids)
            or normalized_evidence_ids.intersection(entry.evidence_ids)
        )
    ]

    entries.sort(key=lambda entry: (_parse_timestamp(entry.timestamp), entry.id or ""))
    if merge_strategy == "dedupe":
        deduped = []
        seen = set()
        for entry in entries:
            key = (entry.timestamp, entry.title, tuple(entry.evidence_ids), tuple(entry.source_ids))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(entry)
        entries = deduped

    if not entries:
        raise ValueError("No timeline entries matched the requested filters")

    merged_source_ids = sorted({source_id for entry in entries for source_id in entry.source_ids})
    merged_evidence_ids = sorted(
        {evidence_id for entry in entries for evidence_id in entry.evidence_ids}
    )
    if not merged_source_ids:
        for evidence_id in merged_evidence_ids:
            merged_source_ids.extend(
                store.load_evidence(case_id, evidence_id).derived_from_source_ids
            )
        merged_source_ids = sorted(dict.fromkeys(merged_source_ids))
    if not merged_source_ids:
        raise ValueError("Unable to determine source ids for merged timeline")

    payload = {
        "mergeStrategy": merge_strategy,
        "entryCount": len(entries),
        "entries": [entry.to_dict() for entry in entries],
    }
    summary = (
        f"Windows merged timeline with {len(entries)} entries "
        f"from {len(merged_source_ids)} source(s) and {len(merged_evidence_ids)} evidence item(s)"
    )
    evidence = store.add_evidence(
        case_id,
        artifact_type="timeline",
        title="Windows merged timeline",
        summary=summary,
        source_ids=merged_source_ids,
        produced_by="windows_timeline_build",
        observed_at=entries[0].timestamp,
        tags=["timeline", "windows"],
        files={"merged_timeline.json": json.dumps(payload, ensure_ascii=False, indent=2)},
    )
    store.update_report_graph(
        case_id,
        report_section_id="windows-timeline",
        report_section_title="Windows Timeline",
        evidence_ids=[evidence.id or ""],
        source_ids=merged_source_ids,
        timeline_ids=[entry.id or "" for entry in entries],
    )
    return TimelineBuildResult(evidence=evidence, entries=entries, summary=summary)
