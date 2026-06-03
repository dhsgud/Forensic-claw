from __future__ import annotations

import sys
import types

import pytest

from forensic_claw.config.schema import Config
from forensic_claw.runtime.knowledge_settings import RuntimeKnowledgeSettings


class _FakeEmbeddingItem:
    def __init__(self, embedding: list[float]) -> None:
        self.embedding = embedding


class _FakeResponse:
    def __init__(self, vectors: list[list[float]]) -> None:
        self.data = [_FakeEmbeddingItem(v) for v in vectors]


class _FakeEmbeddings:
    def __init__(self, handler) -> None:
        self._handler = handler

    def create(self, **kwargs):
        return self._handler(**kwargs)


class _FakeClient:
    def __init__(self, handler, **_kwargs) -> None:
        self.embeddings = _FakeEmbeddings(handler)


def _install_fake_openai(monkeypatch, handler) -> None:
    fake_module = types.SimpleNamespace(OpenAI=lambda **kw: _FakeClient(handler, **kw))
    monkeypatch.setitem(sys.modules, "openai", fake_module)


def _vector_config(**overrides):
    config = Config()
    for key, value in overrides.items():
        setattr(config.knowledge.vector, key, value)
    return config


def test_snapshot_reports_local_index_available_and_hides_legacy_backends() -> None:
    settings = RuntimeKnowledgeSettings(Config())

    snapshot = settings.snapshot()

    assert snapshot["backend"] == "sqlite"
    assert snapshot["local"]["state"] == "available"
    assert snapshot["vector"]["enabled"] is True
    assert "helix" not in snapshot
    assert "neo4j" not in snapshot


def test_test_connection_reports_disabled_when_vector_disabled() -> None:
    settings = RuntimeKnowledgeSettings(Config())

    result = settings.test_connection(vector_enabled=False)

    assert result["enabled"] is False
    assert result["state"] == "disabled"


def test_test_connection_reports_not_configured_when_model_missing() -> None:
    settings = RuntimeKnowledgeSettings(Config())

    result = settings.test_connection(vector_enabled=True, vector_model="", vector_api_base="")

    assert result["enabled"] is True
    assert result["state"] == "not_configured"


def test_test_connection_reports_ready_when_embedding_endpoint_responds(monkeypatch) -> None:
    calls: list[dict[str, object]] = []

    def handler(**kwargs):
        calls.append(kwargs)
        return _FakeResponse([[0.1, 0.2, 0.3]])

    _install_fake_openai(monkeypatch, handler)
    settings = RuntimeKnowledgeSettings(Config())

    result = settings.test_connection(
        vector_enabled=True,
        vector_model="nomic-embed-text",
        vector_api_base="http://127.0.0.1:1234/v1",
    )

    assert result["state"] == "ready"
    assert result["dimensions"] == 3
    assert result["model"] == "nomic-embed-text"
    assert calls and calls[0]["model"] == "nomic-embed-text"


def test_test_connection_reports_unavailable_when_endpoint_fails(monkeypatch) -> None:
    def handler(**_kwargs):
        raise RuntimeError("connection refused")

    _install_fake_openai(monkeypatch, handler)
    settings = RuntimeKnowledgeSettings(Config())

    result = settings.test_connection(
        vector_enabled=True,
        vector_model="nomic-embed-text",
        vector_api_base="http://127.0.0.1:1234/v1",
    )

    assert result["state"] == "unavailable"
    assert "error" in result


def test_apply_persists_vector_settings_and_returns_snapshot(tmp_path) -> None:
    config_path = tmp_path / "config.json"
    config = _vector_config()
    settings = RuntimeKnowledgeSettings(config, config_path=config_path)

    snapshot = settings.apply(
        vector_enabled=True,
        vector_model="nomic-embed-text",
        vector_api_base="http://127.0.0.1:1234/v1",
        vector_dimensions=768,
    )

    assert snapshot["vector"]["model"] == "nomic-embed-text"
    assert snapshot["vector"]["dimensions"] == 768
    assert config.knowledge.vector.api_base == "http://127.0.0.1:1234/v1"
    assert config_path.exists()


def test_apply_rejects_non_sqlite_backend() -> None:
    settings = RuntimeKnowledgeSettings(Config())

    with pytest.raises(ValueError):
        settings.apply(backend="helix")
