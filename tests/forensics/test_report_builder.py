from __future__ import annotations

from forensic_claw.forensics import CaseStore


def test_case_report_and_draft_are_generated_from_graph_and_references(tmp_path) -> None:
    store = CaseStore(tmp_path)
    case = store.create_case(
        case_id="case-2026-0001",
        title="Windows execution trace case",
        summary="Prefetch and event log correlation case",
    )

    source = store.add_source(
        case.id,
        kind="eventlog",
        content="EVTXDATA",
        filename="Security.evtx",
        parser="windows_eventlog_query",
    )
    evidence = store.add_evidence(
        case.id,
        artifact_type="prefetch",
        title="Prefetch summary",
        summary="calc.exe execution evidence",
        source_ids=[source.id or ""],
        produced_by="windows_prefetch_analyze",
        observed_at="2026-04-10T10:12:00+09:00",
    )
    entry = store.add_timeline_entry(
        case.id,
        timestamp="2026-04-10T10:15:00+09:00",
        title="Executable launched",
        description="calc.exe ran",
        evidence_ids=[evidence.id or ""],
        source_ids=[source.id or ""],
        kind="execution",
    )

    graph = store.update_report_graph(
        case.id,
        report_section_id="sec-1",
        report_section_title="Initial Execution",
        evidence_ids=[evidence.id or ""],
        source_ids=[source.id or ""],
        timeline_ids=[entry.id or ""],
    )

    report_text = store.read_report(case.id)
    draft_text = store.read_report_draft(case.id)

    assert "## Initial Execution" in report_text
    assert "## Observed" in report_text
    assert "## Inferred" in report_text
    assert "## Unknown" in report_text
    assert evidence.id in report_text
    assert source.id in report_text
    assert entry.id in report_text

    assert "# Windows execution trace case Draft" in draft_text
    assert evidence.id in draft_text
    assert source.id in draft_text
    assert entry.id in draft_text

    assert graph.report_sections == [{"id": "sec-1", "title": "Initial Execution", "evidenceIds": [evidence.id]}]
