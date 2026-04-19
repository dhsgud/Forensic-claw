from __future__ import annotations

from pathlib import Path

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.windows.prefetch import analyze_prefetch_artifact


def test_analyzes_prefetch_artifact_and_appends_timeline_entries(tmp_path: Path) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "windows"
        / "prefetch"
        / "CALC.EXE-TEST.pf"
    )
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    result = analyze_prefetch_artifact(store, case_id=case.id, prefetch_path=fixture_path)

    assert result.source is not None
    assert result.source.kind == "prefetch"
    assert result.evidence.artifact_type == "prefetch"
    assert len(result.timeline_entries) == 2
    assert result.timeline_entries[0].title == "Prefetch execution: CALC.EXE"
    assert store.list_evidence_files(case.id, result.evidence.id or "") == ["summary.json"]
