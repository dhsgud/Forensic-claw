"""Runtime knowledge and semantic (vector) settings support."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensic_claw.config.loader import save_config
from forensic_claw.config.schema import Config
from forensic_claw.knowledge.embeddings import Embedder
from forensic_claw.knowledge.service import KnowledgeService


class RuntimeKnowledgeSettings:
    """Own knowledge and semantic-search config updates for a running process."""

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
        vector = knowledge.vector
        status = self.service.status() if self.service else {"store": {}, "vector": {}}
        return {
            "enabled": knowledge.enabled,
            "backend": knowledge.backend,
            "storeDir": knowledge.store_dir,
            "chunkChars": knowledge.chunk_chars,
            "chunkOverlapChars": knowledge.chunk_overlap_chars,
            "maxFileBytes": knowledge.max_file_bytes,
            "maxChromeRows": knowledge.max_chrome_rows,
            "local": {
                "enabled": knowledge.enabled,
                "state": "available",
                "status": status.get("store", {}),
            },
            "vector": {
                "enabled": vector.enabled,
                "model": vector.model,
                "apiBase": vector.api_base,
                "dimensions": vector.dimensions,
                "status": status.get("vector", {}),
            },
        }

    def apply(
        self,
        *,
        enabled: bool | None = None,
        backend: str | None = None,
        store_dir: str | None = None,
        vector_enabled: bool | None = None,
        vector_model: str | None = None,
        vector_api_base: str | None = None,
        vector_dimensions: int | None = None,
    ) -> dict[str, Any]:
        """Persist knowledge and semantic-search settings."""
        updated = self.config.model_copy(deep=True)
        knowledge = updated.knowledge
        vector = knowledge.vector

        if enabled is not None:
            knowledge.enabled = enabled
        if backend is not None:
            normalized_backend = backend.strip().lower()
            if normalized_backend != "sqlite":
                raise ValueError("Knowledge backend must be 'sqlite'.")
            knowledge.backend = normalized_backend
        if store_dir is not None:
            normalized = store_dir.strip()
            if not normalized:
                raise ValueError("Knowledge store directory must not be empty.")
            knowledge.store_dir = normalized
        if vector_enabled is not None:
            vector.enabled = vector_enabled
        if vector_model is not None:
            vector.model = vector_model.strip()
        if vector_api_base is not None:
            vector.api_base = vector_api_base.strip()
        if vector_dimensions is not None:
            vector.dimensions = max(0, int(vector_dimensions))

        self.config.knowledge = knowledge
        save_config(self.config, self.config_path)
        if self.service:
            self.service.reconfigure(self.config.knowledge)
        return self.snapshot()

    def test_connection(
        self,
        *,
        enabled: bool | None = None,
        backend: str | None = None,
        vector_enabled: bool | None = None,
        vector_model: str | None = None,
        vector_api_base: str | None = None,
        vector_dimensions: int | None = None,
    ) -> dict[str, Any]:
        """Probe semantic search using supplied values without persisting them."""
        vector = self.config.knowledge.vector
        embedder = Embedder(
            enabled=vector.enabled if vector_enabled is None else bool(vector_enabled),
            model=(vector.model if vector_model is None else vector_model).strip(),
            api_base=(vector.api_base if vector_api_base is None else vector_api_base).strip(),
            dimensions=vector.dimensions if vector_dimensions is None else int(vector_dimensions),
            timeout=vector.request_timeout_seconds,
        )

        if not embedder.enabled:
            return {"enabled": False, "backend": "sqlite", "state": "disabled", "model": embedder.model}
        if not embedder.ready:
            return {
                "enabled": True,
                "backend": "sqlite",
                "state": "not_configured",
                "model": embedder.model,
                "apiBase": embedder.api_base,
            }

        vectors = embedder.embed_one("forensic-claw embedding probe")
        if vectors is None:
            return {
                "enabled": True,
                "backend": "sqlite",
                "state": "unavailable",
                "model": embedder.model,
                "apiBase": embedder.api_base,
                "error": "Embedding endpoint did not return a vector.",
            }
        return {
            "enabled": True,
            "backend": "sqlite",
            "state": "ready",
            "model": embedder.model,
            "apiBase": embedder.api_base,
            "dimensions": len(vectors),
        }


def build_default_knowledge_settings(
    config: Config,
    service: KnowledgeService | None,
) -> RuntimeKnowledgeSettings:
    """Small helper for tests and CLI setup."""
    return RuntimeKnowledgeSettings(config, service=service)
