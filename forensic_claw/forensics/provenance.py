"""Validation and merge helpers for forensic provenance data."""

from __future__ import annotations

from datetime import datetime

from forensic_claw.forensics.models import ReportGraph


def normalize_id_list(values: list[str] | None, *, field_name: str, required: bool = False) -> list[str]:
    normalized: list[str] = []
    for value in values or []:
        text = str(value).strip()
        if not text:
            continue
        if text not in normalized:
            normalized.append(text)
    if required and not normalized:
        raise ValueError(f"{field_name} must contain at least one id")
    return normalized


def ensure_sortable_timestamp(timestamp: str) -> str:
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp must be a sortable ISO 8601 value") from exc
    return timestamp


def merge_report_graph(
    graph: ReportGraph,
    *,
    report_section_id: str | None = None,
    report_section_title: str | None = None,
    evidence_ids: list[str] | None = None,
    source_ids: list[str] | None = None,
    timeline_ids: list[str] | None = None,
) -> ReportGraph:
    merged = ReportGraph.from_dict(graph.to_dict())
    normalized_evidence_ids = normalize_id_list(evidence_ids, field_name="evidence_ids")
    normalized_source_ids = normalize_id_list(source_ids, field_name="source_ids")
    normalized_timeline_ids = normalize_id_list(timeline_ids, field_name="timeline_ids")

    if report_section_title and not report_section_id:
        raise ValueError("report_section_id is required when report_section_title is provided")
    if report_section_id:
        section = _get_or_create_entry(merged.report_sections, report_section_id, "evidenceIds")
        if report_section_title:
            section["title"] = report_section_title
        _merge_list_field(section, "evidenceIds", normalized_evidence_ids)

    for evidence_id in normalized_evidence_ids:
        if normalized_source_ids:
            evidence_link = _get_or_create_entry(merged.evidence_links, evidence_id, "sourceIds")
            _merge_list_field(evidence_link, "sourceIds", normalized_source_ids)

        for timeline_id in normalized_timeline_ids:
            timeline_link = _get_or_create_entry(merged.timeline_links, timeline_id, "evidenceIds")
            _merge_list_field(timeline_link, "evidenceIds", [evidence_id])

    for source_id in normalized_source_ids:
        if normalized_timeline_ids:
            source_link = _get_or_create_entry(merged.source_links, source_id, "timelineIds")
            _merge_list_field(source_link, "timelineIds", normalized_timeline_ids)

    return merged


def _get_or_create_entry(rows: list[dict[str, object]], row_id: str, list_field: str) -> dict[str, object]:
    for row in rows:
        if row.get("id") == row_id:
            row.setdefault(list_field, [])
            return row

    row: dict[str, object] = {"id": row_id, list_field: []}
    rows.append(row)
    return row


def _merge_list_field(row: dict[str, object], field_name: str, values: list[str]) -> None:
    current = row.setdefault(field_name, [])
    if not isinstance(current, list):
        current = []
        row[field_name] = current
    for value in values:
        if value not in current:
            current.append(value)
