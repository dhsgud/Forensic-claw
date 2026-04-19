from __future__ import annotations

from forensic_claw.forensics import CaseStore


def test_add_source_evidence_and_timeline_generate_case_wiki_notes(tmp_path) -> None:
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

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

    source_note = tmp_path / "wiki" / "cases" / case.id / "sources" / f"{source.id}.md"
    evidence_note = tmp_path / "wiki" / "cases" / case.id / "artifacts" / f"{evidence.id}.md"
    timeline_note = tmp_path / "wiki" / "cases" / case.id / "timelines" / "2026-04-10.md"

    assert source_note.is_file()
    assert evidence_note.is_file()
    assert timeline_note.is_file()

    source_text = source_note.read_text(encoding="utf-8")
    evidence_text = evidence_note.read_text(encoding="utf-8")
    timeline_text = timeline_note.read_text(encoding="utf-8")

    assert "## Observed" in source_text
    assert "## Inferred" in source_text
    assert "## Unknown" in source_text
    assert source.id in source_text

    assert "## Observed" in evidence_text
    assert "## Inferred" in evidence_text
    assert "## Unknown" in evidence_text
    assert evidence.id in evidence_text
    assert source.id in evidence_text

    assert "## Observed" in timeline_text
    assert "## Inferred" in timeline_text
    assert "## Unknown" in timeline_text
    assert entry.id in timeline_text
    assert evidence.id in timeline_text
