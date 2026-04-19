from __future__ import annotations

import json

from forensic_claw.forensics.ids import (
    next_case_id,
    next_evidence_id,
    next_source_id,
    next_timeline_id,
)


def test_returns_next_case_id_when_existing_cases_match_year(tmp_path) -> None:
    cases_root = tmp_path / "forensics" / "cases"
    (cases_root / "case-2026-0001").mkdir(parents=True)
    (cases_root / "case-2026-0009").mkdir()
    (cases_root / "case-2025-0010").mkdir()
    (cases_root / "notes").mkdir()

    assert next_case_id(cases_root, year=2026) == "case-2026-0010"
    assert next_case_id(cases_root, year=2027) == "case-2027-0001"


def test_returns_next_source_and_evidence_ids_when_case_contains_directories(tmp_path) -> None:
    case_dir = tmp_path / "forensics" / "cases" / "case-2026-0001"
    (case_dir / "sources" / "SRC-001").mkdir(parents=True)
    (case_dir / "sources" / "SRC-010").mkdir()
    (case_dir / "sources" / "notes").mkdir()
    (case_dir / "evidence" / "EVD-001").mkdir(parents=True)
    (case_dir / "evidence" / "EVD-002").mkdir()

    assert next_source_id(case_dir) == "SRC-011"
    assert next_evidence_id(case_dir) == "EVD-003"


def test_returns_next_timeline_id_when_jsonl_contains_existing_entries(tmp_path) -> None:
    timeline_path = tmp_path / "forensics" / "cases" / "case-2026-0001" / "timeline.jsonl"
    timeline_path.parent.mkdir(parents=True)
    timeline_path.write_text(
        "\n".join(
            [
                json.dumps({"id": "TLN-001", "title": "one"}, ensure_ascii=False),
                json.dumps({"id": "TLN-009", "title": "two"}, ensure_ascii=False),
                "not-json",
            ]
        ),
        encoding="utf-8",
    )

    assert next_timeline_id(timeline_path) == "TLN-010"
