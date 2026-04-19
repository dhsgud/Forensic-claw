from __future__ import annotations

from pathlib import Path

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.windows.eventlog import ingest_eventlog_query_output


def test_ingests_eventlog_query_output_into_case_store(tmp_path: Path) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2] / "fixtures" / "windows" / "evtx" / "security_4688.txt"
    )
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    result = ingest_eventlog_query_output(
        store,
        case_id=case.id,
        log_name="Security",
        query_output=fixture_path.read_text(encoding="utf-8"),
        event_ids=[4688],
        max_events=2,
    )

    assert result.source is not None
    assert result.source.kind == "eventlog"
    assert result.evidence.artifact_type == "eventlog-query"
    assert len(result.timeline_entries) == 2
    assert store.list_source_files(case.id, result.source.id or "") == ["security-events.txt"]
    assert "Events parsed: 2" in (result.evidence.summary or "")
    graph = store.read_graph(case.id)
    assert graph.report_sections[0]["id"] == "windows-eventlog"
    assert graph.timeline_links[0]["id"] == "TLN-001"
