"""Knowledge backend selection.

This is the single seam where storage backends are chosen. Adding a new backend
(e.g. Neo4j for richer multi-hop graph queries) means implementing
``KnowledgeBackend`` and adding one branch here plus a ``backend`` literal in
``KnowledgeConfig``; nothing in the ingestion pipeline changes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensic_claw.knowledge.base import KnowledgeBackend
from forensic_claw.knowledge.store import SqliteKnowledgeBackend


def create_backend(config: Any, workspace: Path) -> KnowledgeBackend:
    """Build the storage backend named by ``config.backend``."""
    backend = str(getattr(config, "backend", "sqlite") or "sqlite").strip().lower()
    store_dir = getattr(config, "store_dir", "knowledge")

    if backend == "sqlite":
        return SqliteKnowledgeBackend(workspace, store_dir)

    # Future: elif backend == "neo4j": return Neo4jKnowledgeBackend(...)
    raise ValueError(f"Unknown knowledge backend: {backend!r}")
