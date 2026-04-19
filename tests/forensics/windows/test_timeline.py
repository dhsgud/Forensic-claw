from __future__ import annotations

from pathlib import Path

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.windows.amcache import analyze_amcache_artifact
from forensic_claw.forensics.windows.eventlog import ingest_eventlog_query_output
from forensic_claw.forensics.windows.prefetch import analyze_prefetch_artifact
from forensic_claw.forensics.windows.timeline import build_windows_timeline


def test_builds_merged_windows_timeline_from_eventlog_prefetch_and_amcache(tmp_path: Path) -> None:
    fixtures_root = Path(__file__).resolve().parents[2] / "fixtures" / "windows"
    eventlog_text = (fixtures_root / "evtx" / "security_4688.txt").read_text(encoding="utf-8")
    prefetch_path = fixtures_root / "prefetch" / "CALC.EXE-TEST.pf"
    amcache_path = fixtures_root / "amcache" / "Amcache.hve"

    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")
    ingest_eventlog_query_output(
        store, case_id=case.id, log_name="Security", query_output=eventlog_text
    )
    analyze_prefetch_artifact(store, case_id=case.id, prefetch_path=prefetch_path)
    analyze_amcache_artifact(store, case_id=case.id, hive_path=amcache_path)

    result = build_windows_timeline(store, case_id=case.id, merge_strategy="chronological")

    assert result.evidence.artifact_type == "timeline"
    assert len(result.entries) == 6
    assert result.entries[0].timestamp == "2026-04-08T12:00:00+09:00"
    assert store.list_evidence_files(case.id, result.evidence.id or "") == ["merged_timeline.json"]
    graph = store.read_graph(case.id)
    assert any(section["id"] == "windows-timeline" for section in graph.report_sections)
