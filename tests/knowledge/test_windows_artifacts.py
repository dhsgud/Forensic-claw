import sqlite3
import subprocess
from contextlib import closing

from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.forensics.artifacts import read_artifact
from forensic_claw.knowledge.service import KnowledgeService
from forensic_claw.utils.hashing import calculate_file_hashes


def test_event_xml_is_registered_with_exact_record_time_and_source_references(tmp_path):
    file = tmp_path / "events.xml"
    file.write_text(
        '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Security"/><EventID>4688</EventID><TimeCreated SystemTime="2026-05-07T01:00:00Z"/><EventRecordID>123</EventRecordID></System><EventData><Data Name="NewProcessName">C:\\tools\\powershell.exe</Data></EventData></Event></Events>',
        encoding="utf-8",
    )
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    assert service.ingest_path(file, case_name="case").ready
    hits = service.search("4688", case_id="case")["hits"]
    assert hits[0]["metadata"]["eventTimestamp"] == "2026-05-07T01:00:00+00:00"
    assert hits[0]["metadata"]["recordId"] == "123"
    timeline = (service.workspace / "forensics/cases/case/timeline.jsonl").read_text(
        encoding="utf-8"
    )
    assert '"timestampKind": "event_time"' in timeline and "2026-05-07" in timeline


def test_chrome_history_preserves_multiple_visits_instead_of_only_latest_visit(tmp_path):
    file = tmp_path / "History"
    with closing(sqlite3.connect(file)) as conn:
        conn.executescript(
            'CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER); INSERT INTO urls VALUES(1,"https://example.org","Example",2,13300000000000000); INSERT INTO visits VALUES(1,1,13200000000000000,0,1); INSERT INTO visits VALUES(2,1,13300000000000000,1,1);'
        )
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )

    assert service.ingest_path(file, case_name="case").ready
    hits = service.search("example.org", case_id="case")["hits"]
    assert {hit["metadata"]["visitId"] for hit in hits} == {1, 2}
    assert (
        len(
            (service.workspace / "forensics/cases/case/timeline.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        )
        == 2
    )


def test_live_chrome_wal_is_preserved_and_searchable_without_modifying_snapshot(tmp_path):
    source = tmp_path / "History"
    with closing(sqlite3.connect(source)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            'CREATE TABLE urls(id INTEGER,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER); CREATE TABLE visits(id INTEGER,url INTEGER,visit_time INTEGER,from_visit INTEGER,transition INTEGER); INSERT INTO urls VALUES(1,"https://example.org","Example",1,13300000000000000); INSERT INTO visits VALUES(1,1,13300000000000000,0,1);'
        )
        conn.commit()
        expected_wal = calculate_file_hashes(source.with_name("History-wal"))
        service = KnowledgeService(
            tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
        )
        result = service.ingest_path(source, case_name="case")
        assert result.ready, result.errors
        hits = service.search("example.org", case_id="case")["hits"]
        assert hits and hits[0]["hash_verified"] is True
        from pathlib import Path

        preserved = Path(hits[0]["sourcePath"]).with_name("History-wal")
        assert calculate_file_hashes(preserved) == expected_wal


def test_sysmon_relationship_is_observed_from_record_and_not_invented_from_mentions(tmp_path):
    file = tmp_path / "sysmon.xml"
    file.write_text(
        '<Events><Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>3</EventID><TimeCreated SystemTime="2026-05-07T00:00:00Z"/><EventRecordID>1</EventRecordID></System><EventData><Data Name="ProcessGuid">{one}</Data><Data Name="Image">C:\\tools\\app.exe</Data><Data Name="DestinationIp">10.0.0.5</Data></EventData></Event></Events>',
        encoding="utf-8",
    )
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    assert service.ingest_path(file, case_name="case").ready
    view = service.search("app.exe", case_id="case")["graphView"]
    edges = [edge for edge in view["edges"] if edge["type"] == "CONNECTED_TO"]
    assert len(edges) == 1 and edges[0]["metadata"]["recordId"] == "1"
    assert edges[0]["metadata"]["basis"] == "recorded_event"


def test_evtx_reader_preserves_source_and_returns_native_process_records(tmp_path, monkeypatch):
    source = tmp_path / "quoted'event.evtx"
    source.write_bytes(b"ElfFile-boundary-fixture")
    baseline = source.read_bytes()
    xml = b'<Events><Event><System><EventID>4688</EventID><EventRecordID>42</EventRecordID><TimeCreated SystemTime="2026-05-07T00:00:00Z"/></System></Event></Events>'

    def native_reader(command, **kwargs):
        return subprocess.CompletedProcess(command, 0, stdout=xml, stderr=b"")

    monkeypatch.setattr(subprocess, "run", native_reader)
    records = read_artifact(source)
    assert records[0][1]["recordId"] == "42"
    assert records[0][1]["eventTimestamp"] == "2026-05-07T00:00:00+00:00"
    assert source.read_bytes() == baseline
