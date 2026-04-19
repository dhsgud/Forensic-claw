from __future__ import annotations

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.hashes import sha256_bytes


def test_add_source_computes_stable_hash_and_copies_file_when_policy_is_copy(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    input_dir = tmp_path / "inputs"
    input_dir.mkdir()
    source_path = input_dir / "Security.evtx"
    source_bytes = b"EVTXDATA"
    source_path.write_bytes(source_bytes)

    store = CaseStore(workspace)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    first = store.add_source(
        case.id,
        kind="eventlog",
        source_path=source_path,
        parser="windows_eventlog_query",
    )
    second = store.add_source(
        case.id,
        kind="eventlog",
        source_path=source_path,
        parser="windows_eventlog_query",
    )

    expected_hash = sha256_bytes(source_bytes)

    assert first.id == "SRC-001"
    assert second.id == "SRC-002"
    assert first.sha256 == expected_hash
    assert second.sha256 == expected_hash
    assert first.size == len(source_bytes)
    assert second.size == len(source_bytes)
    assert first.origin_path == str(source_path.resolve(strict=False))
    assert first.storage_policy == "copy"
    assert second.storage_policy == "copy"
    assert store.list_source_files(case.id, first.id) == ["Security.evtx"]
    assert store.list_source_files(case.id, second.id) == ["Security.evtx"]


def test_add_source_keeps_reference_only_when_policy_is_reference(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    input_dir = tmp_path / "inputs"
    input_dir.mkdir()
    source_path = input_dir / "Security.evtx"
    source_path.write_bytes(b"EVTXDATA")

    store = CaseStore(workspace)
    case = store.create_case(case_id="case-2026-0001", title="Windows execution trace case")

    source = store.add_source(
        case.id,
        kind="eventlog",
        source_path=source_path,
        parser="windows_eventlog_query",
        policy="reference",
    )

    assert source.storage_policy == "reference"
    assert source.origin_path == str(source_path.resolve(strict=False))
    assert store.list_source_files(case.id, source.id or "") == []
