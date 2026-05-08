from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from forensic_claw.config.schema import KnowledgeConfig
from forensic_claw.knowledge.service import KnowledgeService


def _config() -> KnowledgeConfig:
    return KnowledgeConfig(neo4j={"enabled": False}, chunk_chars=1000, chunk_overlap_chars=0)


def _write_chrome_history(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.executescript(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            );
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER,
                from_visit INTEGER,
                transition INTEGER
            );
            """
        )
        chrome_time = int(
            (
                datetime(2026, 5, 7, tzinfo=UTC)
                - datetime(1601, 1, 1, tzinfo=UTC)
            ).total_seconds()
            * 1_000_000
        )
        conn.execute(
            "INSERT INTO urls VALUES (?, ?, ?, ?, ?)",
            (1, "https://example.com/search?q=malware", "Example Search", 3, chrome_time),
        )
        conn.execute("INSERT INTO visits VALUES (?, ?, ?, ?, ?)", (1, 1, chrome_time, 0, 0))


def test_ingest_path_indexes_large_text_log_and_graph_entities_when_log_contains_iocs(tmp_path):
    log = tmp_path / "security.log"
    log.write_text(
        "\n".join(
            [
                "2026-05-07 powershell.exe connected to 10.0.0.5",
                "downloaded https://evil.example/a.exe into C:\\Users\\alice\\Downloads\\a.exe",
                "registry touched HKEY_LOCAL_MACHINE\\Software\\Run",
            ]
        ),
        encoding="utf-8",
    )
    service = KnowledgeService(tmp_path, _config())

    result = service.ingest_path(log, case_name="Case A", investigator_name="Investigator Kim")

    assert result.ready is True
    assert result.ingested_files == 1
    assert result.chunks >= 1
    search = service.search("powershell 10.0.0.5")
    assert search["hits"]
    assert "powershell.exe" in search["hits"][0]["text"]
    graph = service.store.graph_search("10.0.0.5")
    assert graph[0]["kind"] == "IP"


def test_ingest_path_extracts_chrome_history_rows_when_file_is_history_database(tmp_path):
    history = tmp_path / "History"
    _write_chrome_history(history)

    service = KnowledgeService(tmp_path, _config())

    result = service.ingest_path(history)

    assert result.ready is True
    assert result.ingested_files == 1
    search = service.search("malware example")
    assert search["hits"]
    assert "Chrome History URL" in search["hits"][0]["text"]
    domains = service.store.graph_search("example.com")
    assert any(item["kind"] == "Domain" and item["value"] == "example.com" for item in domains)


def test_prepare_chrome_history_discovers_local_profile_without_explicit_path(tmp_path, monkeypatch):
    history = tmp_path / "Google" / "Chrome" / "User Data" / "Default" / "History"
    _write_chrome_history(history)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    service = KnowledgeService(tmp_path / "workspace", _config())

    result = service.prepare_chrome_history()

    assert result.ready is True
    assert result.ingested_files == 1
    assert service.search("malware")["hits"]
