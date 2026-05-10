from __future__ import annotations

from forensic_claw.config.schema import HelixConfig, KnowledgeConfig
from forensic_claw.knowledge.helix_backend import HelixKnowledgeBackend
from forensic_claw.knowledge.service import KnowledgeService


class FakeHelixClient:
    def __init__(self, search_response=None):
        self.calls: list[tuple[str, dict]] = []
        self.search_response = search_response or {
            "hits": [{"content": "powershell.exe connected to 10.0.0.5", "source_path": "security.log"}],
            "graph": [{"kind": "IP", "value": "10.0.0.5"}],
        }
        self.graph_response = {
            "nodes": [
                {
                    "entity_id": "ip:10.0.0.5",
                    "kind": "IP",
                    "value": "10.0.0.5",
                }
            ],
            "edges": [
                {
                    "relationship_id": "rel-1",
                    "source_id": "source:security.log",
                    "target_id": "ip:10.0.0.5",
                    "rel_type": "MENTIONS",
                }
            ],
        }

    def query(self, name: str, payload: dict):
        self.calls.append((name, payload))
        if name == "SearchEvidenceHybrid":
            return self.search_response
        if name == "GetEvidenceGraph":
            return self.graph_response
        return [{"ok": True}]


def _helix_config() -> KnowledgeConfig:
    return KnowledgeConfig(
        backend="helix",
        helix={"enabled": True},
        neo4j={"enabled": False},
        chunk_chars=1000,
        chunk_overlap_chars=0,
    )


def test_helix_backend_syncs_source_chunks_entities_and_relationships(tmp_path):
    log = tmp_path / "security.log"
    log.write_text("powershell.exe connected to 10.0.0.5", encoding="utf-8")
    client = FakeHelixClient()
    service = KnowledgeService(tmp_path, _helix_config())
    service.helix = HelixKnowledgeBackend(
        service.config.helix,
        client_factory=lambda _config: client,
    )

    result = service.ingest_path(log, case_name="Case A", investigator_name="Investigator Kim")

    assert result.ready is True
    assert result.helix["state"] == "synced"
    query_names = [name for name, _payload in client.calls]
    assert "UpsertEvidenceSource" in query_names
    assert "UpsertEvidenceChunk" in query_names
    assert "UpsertEvidenceEntity" in query_names
    assert "UpsertEvidenceRelationship" in query_names
    source_payload = next(payload for name, payload in client.calls if name == "UpsertEvidenceSource")
    relationship_payload = next(
        payload for name, payload in client.calls if name == "UpsertEvidenceRelationship"
    )
    assert source_payload["source_path"] == str(log.resolve())
    assert "rel_type" in relationship_payload
    assert "type" not in relationship_payload


def test_knowledge_search_uses_helix_when_backend_is_configured(tmp_path):
    client = FakeHelixClient()
    service = KnowledgeService(tmp_path, _helix_config())
    service.helix = HelixKnowledgeBackend(
        service.config.helix,
        client_factory=lambda _config: client,
    )

    result = service.search("powershell 10.0.0.5")

    assert result["helix"]["state"] == "queried"
    assert result["hits"][0]["text"] == "powershell.exe connected to 10.0.0.5"
    assert result["graphView"]["nodes"][0]["id"] == "ip:10.0.0.5"
    assert result["graphView"]["edges"][0]["label"] == "MENTIONS"
    assert client.calls == [
        (
            "SearchEvidenceHybrid",
            {
                "query": "powershell 10.0.0.5",
                "keywords": "powershell 10.0.0.5",
                "limit": 8,
                "include_graph": True,
            },
        ),
        ("GetEvidenceGraph", {"query": "powershell 10.0.0.5", "limit": 8}),
    ]


def test_helix_status_uses_http_introspection_without_sdk(monkeypatch):
    calls = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b'{"schema":{"schema":{"nodes":[],"edges":[],"vectors":[]},"queries":[]}}'

    def fake_urlopen(request, *, timeout):
        calls.append({"url": request.full_url, "method": request.get_method(), "timeout": timeout})
        return FakeResponse()

    monkeypatch.setattr("forensic_claw.knowledge.helix_backend.urlopen", fake_urlopen)
    backend = HelixKnowledgeBackend(
        HelixConfig(enabled=True, port=7777, request_timeout_seconds=3),
    )

    status = backend.status()

    assert status["enabled"] is True
    assert status["state"] == "connected"
    assert status["transport"] == "http"
    assert status["baseUrl"] == "http://127.0.0.1:7777"
    assert calls == [
        {
            "url": "http://127.0.0.1:7777/introspect",
            "method": "GET",
            "timeout": 3.0,
        }
    ]
