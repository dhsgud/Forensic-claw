from __future__ import annotations

from urllib.error import URLError

from forensic_claw.config.schema import Config
from forensic_claw.runtime.knowledge_settings import RuntimeKnowledgeSettings


class FakeHelixResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"schema":{"schema":{"nodes":[],"edges":[],"vectors":[]},"queries":[]}}'


def test_helix_connection_test_returns_connected_when_introspection_succeeds(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def fake_urlopen(request, *, timeout):
        calls.append({"url": request.full_url, "method": request.get_method(), "timeout": timeout})
        return FakeHelixResponse()

    monkeypatch.setattr("forensic_claw.knowledge.helix_backend.urlopen", fake_urlopen)
    config = Config()
    settings = RuntimeKnowledgeSettings(config)

    result = settings.test_connection(
        backend="helix",
        helix_enabled=True,
        helix_local=True,
        helix_port=7777,
    )

    assert result["enabled"] is True
    assert result["state"] == "connected"
    assert result["baseUrl"] == "http://127.0.0.1:7777"
    assert result["statusQuery"] == "introspect"
    assert calls == [
        {
            "url": "http://127.0.0.1:7777/introspect",
            "method": "GET",
            "timeout": 10.0,
        }
    ]
    assert config.knowledge.backend == "sqlite"
    assert config.knowledge.helix.enabled is False


def test_helix_connection_test_returns_unavailable_when_database_is_unreachable(monkeypatch) -> None:
    def fake_urlopen(_request, *, timeout):
        raise URLError("connection refused")

    monkeypatch.setattr("forensic_claw.knowledge.helix_backend.urlopen", fake_urlopen)
    settings = RuntimeKnowledgeSettings(Config())

    result = settings.test_connection(
        backend="helix",
        helix_enabled=True,
        helix_local=True,
        helix_port=6969,
    )

    assert result["enabled"] is True
    assert result["state"] == "unavailable"
    assert result["baseUrl"] == "http://127.0.0.1:6969"
    assert "connection refused" in result["error"]


def test_snapshot_hides_neo4j_settings_and_sqlite_test_reports_local_graph_index() -> None:
    settings = RuntimeKnowledgeSettings(Config())

    snapshot = settings.snapshot()
    result = settings.test_connection(backend="sqlite")

    assert "neo4j" not in snapshot
    assert snapshot["local"]["state"] == "available"
    assert result == {
        "enabled": True,
        "backend": "sqlite",
        "state": "available",
        "storeDir": "knowledge",
    }
