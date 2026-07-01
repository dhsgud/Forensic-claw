"""Tests for the forensics case store and context assembly (P1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from forensic_claw.forensics import CaseStore, derive_case_id
from forensic_claw.utils.hashing import calculate_file_hashes


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_derive_case_id_slugifies_free_form_name():
    assert derive_case_id("2026 정보유출 사건 #1") == "2026-정보유출-사건-1"


def test_derive_case_id_rejects_empty():
    with pytest.raises(ValueError):
        derive_case_id("///")


def test_ensure_case_creates_folder_and_manifest(tmp_path: Path):
    store = CaseStore(tmp_path)
    manifest = store.ensure_case(case_name="Test Case", investigator_name="홍길동")

    case_id = manifest["caseId"]
    assert case_id == "Test-Case"
    case_dir = tmp_path / "forensics" / "cases" / case_id
    assert (case_dir / "manifest.json").is_file()
    assert (case_dir / "evidence").is_dir()
    assert (case_dir / "sources").is_dir()
    assert manifest["caseName"] == "Test Case"
    assert manifest["investigatorName"] == "홍길동"
    assert manifest["status"] == "open"
    assert manifest["createdAt"] and manifest["updatedAt"]


def test_ensure_case_is_idempotent_and_stable(tmp_path: Path):
    store = CaseStore(tmp_path)
    first = store.ensure_case(case_name="같은 사건", investigator_name="A")
    created_at = first["createdAt"]

    second = store.ensure_case(case_name="같은 사건", investigator_name="A")
    assert second["caseId"] == first["caseId"]
    # createdAt is preserved (folder was not recreated).
    assert second["createdAt"] == created_at


def test_ensure_case_updates_investigator(tmp_path: Path):
    store = CaseStore(tmp_path)
    store.ensure_case(case_name="사건", investigator_name="처음")
    updated = store.ensure_case(case_name="사건", investigator_name="변경")
    assert updated["investigatorName"] == "변경"


def test_collect_context_reads_evidence_sources_and_graph(tmp_path: Path):
    store = CaseStore(tmp_path)
    manifest = store.ensure_case(case_name="Case X", investigator_name="수사관")
    case_id = manifest["caseId"]
    case_dir = store.case_dir(case_id)

    evidence_file = case_dir / "evidence" / "art01" / "files" / "system.log"
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    evidence_file.write_text("suspicious login from 10.0.0.5\n", encoding="utf-8")
    _write_json(case_dir / "evidence" / "art01" / "metadata.json", {"label": "이벤트 로그"})

    source_file = case_dir / "sources" / "src01" / "raw" / "History"
    source_file.parent.mkdir(parents=True, exist_ok=True)
    source_file.write_bytes(b"\x00chrome-history")
    _write_json(case_dir / "sources" / "src01" / "metadata.json", {"kind": "chrome_history"})

    _write_json(case_dir / "graph.json", {"nodes": [{"id": "n1"}], "edges": []})

    context = store.collect_context(case_id)
    assert context is not None
    assert context.case_name == "Case X"
    assert context.investigator_name == "수사관"

    assert len(context.evidence) == 1
    item = context.evidence[0]
    assert item.id == "art01"
    assert item.files == ["system.log"]
    expected = calculate_file_hashes(evidence_file)
    assert item.hashes["system.log"]["sha256"] == expected["sha256"]

    assert len(context.sources) == 1
    assert context.sources[0].files == ["History"]

    assert context.graph == {"nodes": [{"id": "n1"}], "edges": []}

    rows = context.integrity_rows()
    assert rows[0]["evidenceId"] == "art01"
    assert rows[0]["file"] == "system.log"
    assert rows[0]["sha256"] == expected["sha256"]


def test_collect_context_prefers_recorded_hashes(tmp_path: Path):
    store = CaseStore(tmp_path)
    manifest = store.ensure_case(case_name="Case Y", investigator_name="수사관")
    case_id = manifest["caseId"]
    case_dir = store.case_dir(case_id)

    evidence_file = case_dir / "evidence" / "a" / "files" / "data.bin"
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    evidence_file.write_bytes(b"real-content")
    _write_json(
        case_dir / "evidence" / "a" / "metadata.json",
        {"hashes": {"data.bin": {"sha256": "recorded-at-acquisition"}}},
    )

    context = store.collect_context(case_id)
    assert context is not None
    # Acquisition-time hash is trusted over a fresh computation.
    assert context.evidence[0].hashes["data.bin"]["sha256"] == "recorded-at-acquisition"


def test_collect_context_missing_case_returns_none(tmp_path: Path):
    store = CaseStore(tmp_path)
    assert store.collect_context("does-not-exist") is None
