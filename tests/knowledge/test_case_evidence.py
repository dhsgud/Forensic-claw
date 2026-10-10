import json
from concurrent.futures import ThreadPoolExecutor

from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.forensics.case import CaseStore
from forensic_claw.knowledge.service import KnowledgeService


def test_ingestion_registers_case_material_and_scoped_integrity_checked_hits(tmp_path):
    workspace = tmp_path / "workspace"
    service = KnowledgeService(workspace, KnowledgeConfig(vector=VectorConfig(enabled=False)))
    first = tmp_path / "a.log"
    first.write_text("2026-05-07 powershell.exe connected to 10.0.0.5\n", encoding="utf-8")
    second = tmp_path / "b.log"
    second.write_text("2026-05-08 powershell.exe connected to 10.0.0.6\n", encoding="utf-8")
    assert service.ingest_path(first, case_name="Case A").ready
    assert service.ingest_path(second, case_name="Case B").ready
    hits = service.search("powershell", case_id="Case-A")["hits"]
    assert hits and all(hit["metadata"]["caseId"] == "Case-A" for hit in hits)
    assert all(hit["hash_verified"] is True and hit["timestamp"] for hit in hits)
    context = CaseStore(workspace).collect_context("Case-A")
    assert len(context.sources) == len(context.evidence) == 1
    assert context.graph and (context.root / "wiki" / "evidence.md").is_file()
    assert (context.root / "timeline.jsonl").is_file()
    source = context.root / "sources" / context.sources[0].id / "raw" / context.sources[0].files[0]
    source.write_text("tampered", encoding="utf-8")
    result = service.search("powershell", case_id="Case-A")
    assert not result["hits"]
    assert result["rejected"] and result["rejected"][0]["grade"] == "UNVERIFIED"


def test_case_context_detects_tampering_instead_of_reusing_recorded_hashes(tmp_path):
    store = CaseStore(tmp_path)
    store.ensure_case(case_name="case")
    item = store.case_dir("case") / "evidence" / "e1"
    file = item / "files" / "data.txt"
    file.parent.mkdir(parents=True)
    file.write_text("changed", encoding="utf-8")
    (item / "metadata.json").write_text(
        json.dumps({"hashes": {"data.txt": {"sha256": "a" * 64}}}), encoding="utf-8"
    )
    context = store.collect_context("case")
    assert context.evidence[0].verification["data.txt"]["ok"] is False
    assert context.evidence[0].hashes["data.txt"]["sha256"] != "a" * 64


def test_ingestion_preserves_explicit_case_identity_when_display_name_differs(tmp_path):
    service = KnowledgeService(tmp_path, KnowledgeConfig(vector=VectorConfig(enabled=False)))
    file = tmp_path / "case.log"
    file.write_text("powershell evidence", encoding="utf-8")
    assert service.ingest_path(file, case_name="사건 표시명", case_id="case-42").ready
    assert service.search("powershell", case_id="case-42")["hits"]
    assert CaseStore(tmp_path).collect_context("case-42").case_name == "사건 표시명"


def test_acquisition_creates_distinct_snapshot_when_only_wal_changes(tmp_path):
    source = tmp_path / "History"
    source.write_bytes(b"main database")
    wal = tmp_path / "History-wal"
    wal.write_bytes(b"first transaction")
    store = CaseStore(tmp_path / "workspace")
    first, metadata = store.acquire_source(source, case_name="case")
    wal.write_bytes(b"second transaction")
    second, _ = store.acquire_source(source, case_name="case")
    assert first != second
    assert first.with_name("History-wal").read_bytes() == b"first transaction"
    assert second.with_name("History-wal").read_bytes() == b"second transaction"
    assert metadata["hashes"]["History-wal"]["sha256"]


def test_concurrent_ingestion_keeps_every_evidence_reference_in_case_index(tmp_path):
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    files = [tmp_path / f"{index}.log" for index in range(5)]
    for index, file in enumerate(files):
        file.write_text(f"powershell.exe connected to 10.0.0.{index}", encoding="utf-8")
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda file: service.ingest_path(file, case_name="case"), files))
    assert all(result.ready for result in results)
    context = CaseStore(service.workspace).collect_context("case")
    wiki = (context.root / "wiki" / "evidence.md").read_text(encoding="utf-8")
    assert len(context.evidence) == len(context.sources) == 5
    assert all(item.id in wiki for item in context.evidence)
    graph_evidence = {edge["metadata"].get("evidenceId") for edge in context.graph["edges"]}
    assert graph_evidence == {item.id for item in context.evidence}
