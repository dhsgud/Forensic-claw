"""Runtime knowledge and Neo4j settings support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensic_claw.config.loader import save_config
from forensic_claw.config.schema import Config
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
        status = self.service.status() if self.service else {"neo4j": Neo4jSink(neo4j).status()}
        return {
            "enabled": knowledge.enabled,
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
        }

    def apply(
        self,
        *,
        enabled: bool | None = None,
        store_dir: str | None = None,
        neo4j_enabled: bool | None = None,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        password_supplied: bool = False,
        database: str | None = None,
    ) -> dict[str, Any]:
        """Persist knowledge and Neo4j settings."""
        updated = self.config.model_copy(deep=True)
        knowledge = updated.knowledge
        neo4j = knowledge.neo4j

        if enabled is not None:
            knowledge.enabled = enabled
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
    ) -> dict[str, Any]:
        """Probe Neo4j using supplied form values without persisting them."""
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
