"""Runtime knowledge, HelixDB, and Neo4j settings support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensic_claw.config.loader import save_config
from forensic_claw.config.schema import Config
from forensic_claw.knowledge.helix_backend import HelixKnowledgeBackend
from forensic_claw.knowledge.neo4j_sink import Neo4jSink
from forensic_claw.knowledge.service import KnowledgeService


class RuntimeKnowledgeSettings:
    """Own knowledge/Neo4j config updates for a running process."""

    def __init__(
        self,
        config: Config,
        *,
        config_path: Path | None = None,
        service: KnowledgeService | None = None,
    ) -> None:
        self.config = config
        self.config_path = config_path
        self.service = service

    def snapshot(self) -> dict[str, Any]:
        knowledge = self.config.knowledge
        neo4j = knowledge.neo4j
        helix = knowledge.helix
        status = self.service.status() if self.service else {
            "neo4j": Neo4jSink(neo4j).status(),
            "helix": HelixKnowledgeBackend(helix).status(),
        }
        return {
            "enabled": knowledge.enabled,
            "backend": knowledge.backend,
            "storeDir": knowledge.store_dir,
            "chunkChars": knowledge.chunk_chars,
            "chunkOverlapChars": knowledge.chunk_overlap_chars,
            "maxFileBytes": knowledge.max_file_bytes,
            "maxChromeRows": knowledge.max_chrome_rows,
            "neo4j": {
                "enabled": neo4j.enabled,
                "uri": neo4j.uri,
                "username": neo4j.username,
                "database": neo4j.database,
                "passwordConfigured": bool(neo4j.password),
                "status": status.get("neo4j", status),
            },
            "helix": {
                "enabled": helix.enabled,
                "local": helix.local,
                "port": helix.port,
                "apiEndpoint": helix.api_endpoint,
                "fallbackToSqlite": helix.fallback_to_sqlite,
                "status": status.get("helix", {}),
            },
        }

    def apply(
        self,
        *,
        enabled: bool | None = None,
        backend: str | None = None,
        store_dir: str | None = None,
        neo4j_enabled: bool | None = None,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        password_supplied: bool = False,
        database: str | None = None,
        helix_enabled: bool | None = None,
        helix_local: bool | None = None,
        helix_port: int | None = None,
        helix_api_endpoint: str | None = None,
        helix_fallback_to_sqlite: bool | None = None,
    ) -> dict[str, Any]:
        """Persist knowledge and Neo4j settings."""
        updated = self.config.model_copy(deep=True)
        knowledge = updated.knowledge
        neo4j = knowledge.neo4j
        helix = knowledge.helix

        if enabled is not None:
            knowledge.enabled = enabled
        if backend is not None:
            normalized_backend = backend.strip().lower()
            if normalized_backend not in {"sqlite", "helix"}:
                raise ValueError("Knowledge backend must be either 'sqlite' or 'helix'.")
            knowledge.backend = normalized_backend
        if store_dir is not None:
            normalized = store_dir.strip()
            if not normalized:
                raise ValueError("Knowledge store directory must not be empty.")
            knowledge.store_dir = normalized
        if neo4j_enabled is not None:
            neo4j.enabled = neo4j_enabled
        if uri is not None:
            normalized_uri = uri.strip()
            if not normalized_uri:
                raise ValueError("Neo4j URI must not be empty.")
            neo4j.uri = normalized_uri
        if username is not None:
            neo4j.username = username.strip()
        if password_supplied:
            neo4j.password = password or ""
        if database is not None:
            neo4j.database = database.strip() or "neo4j"
        if helix_enabled is not None:
            helix.enabled = helix_enabled
        if helix_local is not None:
            helix.local = helix_local
        if helix_port is not None:
            helix.port = int(helix_port)
        if helix_api_endpoint is not None:
            helix.api_endpoint = helix_api_endpoint.strip()
        if helix_fallback_to_sqlite is not None:
            helix.fallback_to_sqlite = helix_fallback_to_sqlite

        self.config.knowledge = knowledge
        save_config(self.config, self.config_path)
        if self.service:
            self.service.reconfigure(self.config.knowledge)
        return self.snapshot()

    def test_connection(
        self,
        *,
        enabled: bool | None = None,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        password_supplied: bool = False,
        database: str | None = None,
        backend: str | None = None,
        helix_enabled: bool | None = None,
        helix_local: bool | None = None,
        helix_port: int | None = None,
        helix_api_endpoint: str | None = None,
    ) -> dict[str, Any]:
        """Probe the selected knowledge backend using supplied values without persisting them."""
        selected_backend = (backend or self.config.knowledge.backend or "sqlite").strip().lower()
        if selected_backend == "helix":
            helix = self.config.knowledge.helix.model_copy(deep=True)
            if helix_enabled is not None:
                helix.enabled = helix_enabled
            if helix_local is not None:
                helix.local = helix_local
            if helix_port is not None:
                helix.port = int(helix_port)
            if helix_api_endpoint is not None:
                helix.api_endpoint = helix_api_endpoint.strip()
            return HelixKnowledgeBackend(helix).status()

        neo4j = self.config.knowledge.neo4j.model_copy(deep=True)
        if enabled is not None:
            neo4j.enabled = enabled
        if uri is not None and uri.strip():
            neo4j.uri = uri.strip()
        if username is not None:
            neo4j.username = username.strip()
        if password_supplied:
            neo4j.password = password or ""
        if database is not None:
            neo4j.database = database.strip() or "neo4j"
        return Neo4jSink(neo4j).status()


def build_default_knowledge_settings(
    config: Config,
    service: KnowledgeService | None,
) -> RuntimeKnowledgeSettings:
    """Small helper for tests and CLI setup."""
    return RuntimeKnowledgeSettings(config, service=service)
