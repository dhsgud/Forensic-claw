from __future__ import annotations

import json
import subprocess
from pathlib import Path

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.windows.prefetch import (
    _build_pecmd_failure_detail,
    _bundled_pecmd_candidates,
    _resolve_pecmd_executable,
    analyze_prefetch_artifact,
)


def test_analyzes_prefetch_artifact_and_appends_timeline_entries(
    tmp_path: Path,
    prefetch_pecmd_runner,
) -> None:
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "windows"
        / "prefetch"
        / "CALC.EXE-TEST.pf"
    )
    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    result = analyze_prefetch_artifact(
        store,
        case_id=case.id,
        prefetch_path=fixture_path,
        runner=prefetch_pecmd_runner,
    )

    assert result.source is not None
    assert result.source.kind == "prefetch"
    assert result.evidence.artifact_type == "prefetch"
    assert len(result.timeline_entries) == 2
    assert result.timeline_entries[0].title == "Prefetch execution: CALC.EXE"
    assert store.list_evidence_files(case.id, result.evidence.id or "") == [
        "layout-prefetch-files.txt",
        "pecmd-output.jsonl",
        "summary.json",
    ]

    summary_path = (
        store.case_dir(case.id) / "evidence" / (result.evidence.id or "") / "files" / "summary.json"
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["parserBackend"] == "PECmd"
    assert summary["layoutPrefetchEntryCount"] == 2
    assert summary["layoutPrefetchEntries"] == [
        r"C:\Windows\Prefetch\CALC.EXE-TEST.pf",
        r"C:\Windows\Prefetch\NOTEPAD.EXE-12345678.pf",
    ]
    assert "layout_prefetch_entries=2" in result.summary


def test_records_zero_layout_prefetch_entries_without_failing(
    tmp_path: Path,
    prefetch_pecmd_runner,
) -> None:
    fixture_dir = Path(__file__).resolve().parents[2] / "fixtures" / "windows" / "prefetch"
    fixture_path = fixture_dir / "CALC.EXE-TEST.pf"
    layout_path = tmp_path / "Layout.ini"
    layout_path.write_text(
        "[OptimalLayoutFile]\nVersion=1\nC:\\WINDOWS\\SYSTEM32\\NTOSKRNL.EXE\n",
        encoding="utf-8",
    )

    store = CaseStore(tmp_path)
    case = store.create_case(case_id="case-2026-0002", title="Windows layout zero-entry case")

    result = analyze_prefetch_artifact(
        store,
        case_id=case.id,
        prefetch_path=fixture_path,
        layout_path=layout_path,
        runner=prefetch_pecmd_runner,
    )

    summary_path = (
        store.case_dir(case.id) / "evidence" / (result.evidence.id or "") / "files" / "summary.json"
    )
    layout_summary_path = (
        store.case_dir(case.id)
        / "evidence"
        / (result.evidence.id or "")
        / "files"
        / "layout-prefetch-files.txt"
    )
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    layout_summary = layout_summary_path.read_text(encoding="utf-8")

    assert summary["layoutIniPath"] == str(layout_path)
    assert summary["layoutPrefetchEntries"] == []
    assert summary["layoutPrefetchEntryCount"] == 0
    assert "layout_prefetch_entries=0" in result.summary
    assert "no .pf entries were found" in layout_summary
    assert "layout_prefetch_entry_count=0" in layout_summary


def test_prefetch_parser_resolves_bundled_pecmd_when_present(monkeypatch) -> None:
    monkeypatch.delenv("FORENSIC_CLAW_PECMD_PATH", raising=False)
    monkeypatch.setattr("forensic_claw.forensics.windows.prefetch.shutil.which", lambda _: None)

    resolved = Path(_resolve_pecmd_executable())

    assert resolved == _bundled_pecmd_candidates()[0]
    assert resolved.is_file()


def test_prefetch_failure_mentions_missing_dotnet_runtime(tmp_path: Path) -> None:
    pecmd_path = tmp_path / "PECmd.exe"
    pecmd_path.write_bytes(b"MZ")
    runtimeconfig = tmp_path / "PECmd.runtimeconfig.json"
    runtimeconfig.write_text(
        json.dumps(
            {
                "runtimeOptions": {
                    "framework": {
                        "name": "Microsoft.NETCore.App",
                        "version": "9.0.0",
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    completed = subprocess.CompletedProcess(
        args=[str(pecmd_path)],
        returncode=1,
        stdout="",
        stderr="You must install .NET to run this application.",
    )

    detail = _build_pecmd_failure_detail(
        Path(r"C:\Windows\Prefetch\TEST.EXE-12345678.pf"),
        pecmd_path,
        completed,
    )

    assert "missing .NET runtime or framework dependency" in detail
    assert "Microsoft.NETCore.App 9.0.0" in detail
