from __future__ import annotations

from forensic_claw.forensics.models import (
    CaseManifest,
    ReportGraph,
    SourceMetadata,
    TimelineEntry,
)


def test_case_manifest_round_trips_with_disk_aliases() -> None:
    manifest = CaseManifest(
        id="case-2026-0001",
        title="Windows execution trace case",
        status="draft",
        created_at="2026-04-10T10:00:00+09:00",
        updated_at="2026-04-10T10:30:00+09:00",
        summary="Prefetch and event log correlation case",
        tags=["prefetch", "eventlog"],
        primary_session_key="webui:browser-a:case:case-2026-0001",
        timezone="Asia/Seoul",
    )

    dumped = manifest.to_dict()

    assert dumped["createdAt"] == "2026-04-10T10:00:00+09:00"
    assert dumped["updatedAt"] == "2026-04-10T10:30:00+09:00"
    assert dumped["primarySessionKey"] == "webui:browser-a:case:case-2026-0001"
    assert CaseManifest.from_dict(dumped) == manifest


def test_source_metadata_round_trips_with_camel_case_fields() -> None:
    metadata = SourceMetadata(
        id="SRC-001",
        kind="eventlog",
        label="Security.evtx",
        origin_path="C:/Windows/System32/winevt/Logs/Security.evtx",
        acquired_at="2026-04-10T10:05:00+09:00",
        sha256="abc123",
        size=4096,
        parser="windows_eventlog_query",
        read_only=True,
        notes="collected from disk",
    )

    dumped = metadata.to_dict()

    assert dumped["originPath"] == "C:/Windows/System32/winevt/Logs/Security.evtx"
    assert dumped["acquiredAt"] == "2026-04-10T10:05:00+09:00"
    assert dumped["readOnly"] is True
    assert SourceMetadata.from_dict(dumped) == metadata


def test_timeline_entry_round_trips_links_when_serialized() -> None:
    entry = TimelineEntry(
        id="TLN-001",
        timestamp="2026-04-10T10:15:00+09:00",
        timezone="Asia/Seoul",
        title="Executable launched",
        description="calc.exe ran",
        evidence_ids=["EVD-001"],
        source_ids=["SRC-001"],
        kind="execution",
    )

    dumped = entry.to_dict()

    assert dumped["evidenceIds"] == ["EVD-001"]
    assert dumped["sourceIds"] == ["SRC-001"]
    assert TimelineEntry.from_dict(dumped) == entry


def test_report_graph_supplies_minimum_lists_when_optional_fields_are_missing() -> None:
    graph = ReportGraph.from_dict(
        {
            "reportSections": [{"id": "sec-1", "title": "Initial Execution"}],
            "evidenceLinks": [{"id": "EVD-001", "sourceIds": ["SRC-001"]}],
        }
    )

    dumped = graph.to_dict()

    assert dumped["reportSections"][0]["id"] == "sec-1"
    assert dumped["evidenceLinks"][0]["sourceIds"] == ["SRC-001"]
    assert dumped["sourceLinks"] == []
    assert dumped["timelineLinks"] == []
