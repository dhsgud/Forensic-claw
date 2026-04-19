from __future__ import annotations

import pytest

from forensic_claw.forensics import CaseStore


def test_add_evidence_rejects_unknown_source_ids_when_provenance_is_missing(tmp_path) -> None:
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    with pytest.raises(ValueError, match="Unknown source ids"):
        store.add_evidence(
            case.id,
            artifact_type="prefetch",
            title="Prefetch summary",
            source_ids=["SRC-404"],
        )


def test_add_timeline_entry_rejects_unparseable_timestamp_when_not_sortable(tmp_path) -> None:
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")
    source = store.add_source(
        case.id,
        kind="eventlog",
        content="EVTXDATA",
        filename="Security.evtx",
        parser="windows_eventlog_query",
    )

    with pytest.raises(ValueError, match="ISO 8601"):
        store.add_timeline_entry(
            case.id,
            timestamp="2026/04/10 10:15:00",
            title="Executable launched",
            source_ids=[source.id or ""],
        )


def test_update_report_graph_merges_links_without_dropping_existing_relationships(tmp_path) -> None:
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")
    source_one = store.add_source(
        case.id,
        kind="eventlog",
        content="EVTXDATA",
        filename="Security.evtx",
        parser="windows_eventlog_query",
    )
    source_two = store.add_source(
        case.id,
        kind="prefetch",
        content="PFDATA",
        filename="calc.pf",
        parser="windows_prefetch_analyze",
    )
    evidence_one = store.add_evidence(
        case.id,
        artifact_type="eventlog-finding",
        title="Event log trace",
        source_ids=[source_one.id or ""],
    )
    evidence_two = store.add_evidence(
        case.id,
        artifact_type="prefetch",
        title="Prefetch summary",
        source_ids=[source_two.id or ""],
    )
    timeline = store.add_timeline_entry(
        case.id,
        timestamp="2026-04-10T10:15:00+09:00",
        title="Executable launched",
        evidence_ids=[evidence_one.id or ""],
        source_ids=[source_one.id or ""],
        kind="execution",
    )

    store.update_report_graph(
        case.id,
        report_section_id="sec-1",
        report_section_title="Initial Execution",
        evidence_ids=[evidence_one.id or ""],
    )
    graph = store.update_report_graph(
        case.id,
        report_section_id="sec-1",
        report_section_title="Initial Execution",
        evidence_ids=[evidence_two.id or ""],
        source_ids=[source_two.id or ""],
        timeline_ids=[timeline.id or ""],
    )

    assert graph.report_sections == [
        {"id": "sec-1", "title": "Initial Execution", "evidenceIds": ["EVD-001", "EVD-002"]}
    ]
    assert graph.evidence_links == [
        {"id": "EVD-001", "sourceIds": ["SRC-001"]},
        {"id": "EVD-002", "sourceIds": ["SRC-002"]},
    ]
    assert graph.source_links == [
        {"id": "SRC-001", "timelineIds": ["TLN-001"]},
        {"id": "SRC-002", "timelineIds": ["TLN-001"]},
    ]
    assert graph.timeline_links == [{"id": "TLN-001", "evidenceIds": ["EVD-001", "EVD-002"]}]
