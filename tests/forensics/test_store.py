from __future__ import annotations

import pytest

from forensic_claw.forensics import (
    CaseStore,
    EvidenceMetadata,
    ReportGraph,
    SourceMetadata,
    TimelineEntry,
)


def test_creates_case_structure_when_case_is_created(tmp_path) -> None:
    store = CaseStore(tmp_path)

    manifest = store.create_case(
        case_id="case-2026-0001",
        title="Windows execution trace case",
        status="draft",
        created_at="2026-04-10T10:00:00+09:00",
        updated_at="2026-04-10T10:30:00+09:00",
        summary="Prefetch and event log correlation case",
        tags=["prefetch", "eventlog"],
        timezone="Asia/Seoul",
    )

    case_dir = tmp_path / "forensics" / "cases" / manifest.id

    assert case_dir.is_dir()
    assert (case_dir / "evidence").is_dir()
    assert (case_dir / "sources").is_dir()
    assert (case_dir / "timeline.jsonl").read_text(encoding="utf-8") == ""
    assert store.load_manifest(manifest.id) == manifest
    assert store.read_graph(manifest.id) == ReportGraph()
    assert store.read_report(manifest.id) == ""


def test_persists_case_artifacts_when_source_evidence_and_timeline_are_registered(tmp_path) -> None:
    store = CaseStore(tmp_path)
    manifest = store.create_case(
        case_id="case-2026-0001",
        title="Windows execution trace case",
        created_at="2026-04-10T10:00:00+09:00",
        updated_at="2026-04-10T10:30:00+09:00",
    )

    source = store.register_source(
        manifest.id,
        SourceMetadata(
            kind="eventlog",
            label="Security.evtx",
            origin_path="C:/Windows/System32/winevt/Logs/Security.evtx",
            acquired_at="2026-04-10T10:05:00+09:00",
            sha256="abc123",
            size=4096,
            parser="windows_eventlog_query",
            read_only=True,
            notes="collected from disk",
        ),
        raw_files={"Security.evtx": "EVTXDATA"},
    )
    evidence = store.register_evidence(
        manifest.id,
        EvidenceMetadata(
            artifact_type="prefetch",
            title="Prefetch summary",
            summary="calc.exe execution evidence",
            derived_from_source_ids=[source.id],
            produced_by="windows_prefetch_analyze",
            observed_at="2026-04-10T10:12:00+09:00",
            confidence=0.93,
            tags=["execution"],
        ),
        files={"prefetch.pf": "PFDATA"},
    )
    entry = store.append_timeline(
        manifest.id,
        TimelineEntry(
            timestamp="2026-04-10T10:15:00+09:00",
            timezone="Asia/Seoul",
            title="Executable launched",
            description="calc.exe ran",
            evidence_ids=[evidence.id],
            source_ids=[source.id],
            kind="execution",
        ),
    )

    graph = ReportGraph(
        report_sections=[
            {"id": "sec-1", "title": "Initial Execution", "evidenceIds": [evidence.id]}
        ],
        evidence_links=[{"id": evidence.id, "sourceIds": [source.id]}],
        source_links=[{"id": source.id, "timelineIds": [entry.id]}],
        timeline_links=[{"id": entry.id, "evidenceIds": [evidence.id]}],
    )

    store.write_graph(manifest.id, graph)
    store.write_report(manifest.id, "# Report\n\nInitial execution trace summary")

    assert source.id == "SRC-001"
    assert evidence.id == "EVD-001"
    assert entry.id == "TLN-001"
    assert store.load_source(manifest.id, source.id) == source
    assert store.load_evidence(manifest.id, evidence.id) == evidence
    assert store.read_timeline(manifest.id) == [entry]
    assert store.read_graph(manifest.id) == graph
    assert store.read_report(manifest.id) == "# Report\n\nInitial execution trace summary"
    assert store.list_source_files(manifest.id, source.id) == ["Security.evtx"]
    assert store.list_evidence_files(manifest.id, evidence.id) == ["prefetch.pf"]


def test_returns_minimum_graph_and_report_when_files_are_empty(tmp_path) -> None:
    store = CaseStore(tmp_path)
    manifest = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")
    case_dir = tmp_path / "forensics" / "cases" / manifest.id

    (case_dir / "graph.json").write_text("", encoding="utf-8")
    (case_dir / "report.md").write_text("", encoding="utf-8")

    assert store.read_graph(manifest.id) == ReportGraph()
    assert store.read_report(manifest.id) == ""


def test_rejects_path_traversal_when_case_or_file_targets_escape_root(tmp_path) -> None:
    store = CaseStore(tmp_path)
    manifest = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    with pytest.raises(FileNotFoundError):
        store.load_manifest("../escape")

    with pytest.raises(ValueError):
        store.register_source(
            manifest.id,
            SourceMetadata(kind="eventlog", label="Security.evtx"),
            raw_files={"../escape.txt": "bad"},
        )

    with pytest.raises(ValueError):
        store.register_evidence(
            manifest.id,
            EvidenceMetadata(artifact_type="prefetch", title="Prefetch summary"),
            files={"../../escape.txt": "bad"},
        )
