"""Backend-neutral knowledge records and the pluggable backend interface.

The ingestion/extraction pipeline in :mod:`forensic_claw.knowledge.service` is
storage-agnostic: it produces these records and hands them to a
:class:`KnowledgeBackend`. Today the only implementation is the SQLite backend
in :mod:`forensic_claw.knowledge.store`; a future Neo4j backend only needs to
implement this interface and be wired into
:func:`forensic_claw.knowledge.factory.create_backend`.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any


def entity_id(kind: str, value: str) -> str:
    """Build a stable entity id from observable graph data."""
    raw = f"{kind.strip().lower()}:{value.strip().lower()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def relationship_id(source_id: str, rel_type: str, target_id: str, document_id: str | None) -> str:
    """Build a stable relationship id."""
    raw = f"{source_id}:{rel_type}:{target_id}:{document_id or ''}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class DocumentRecord:
    """Stored source document metadata."""

    id: str
    source_path: str
    kind: str
    sha256: str
    size_bytes: int
    metadata: dict[str, Any]


@dataclass(frozen=True)
class SearchHit:
    """One RAG search hit."""

    chunk_id: str
    document_id: str
    source_path: str
    kind: str
    rank: float
    text: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ChunkRecord:
    """Stored chunk content for backend synchronization."""

    id: str
    document_id: str
    chunk_index: int
    text: str
    metadata: dict[str, Any]


# One chunk to persist: (text, metadata, embedding-or-None).
ChunkInput = tuple[str, dict[str, Any], list[float] | None]


class KnowledgeBackend(ABC):
    """Storage and query layer for ingested evidence.

    Implementations own persistence and retrieval only. All file parsing,
    chunking, and entity extraction happens upstream in ``KnowledgeService``.
    """

    #: Short backend identifier surfaced in status/search payloads.
    name: str = "abstract"

    @abstractmethod
    def replace_document(
        self,
        *,
        source_path: str,
        kind: str,
        sha256: str,
        size_bytes: int,
        mtime: float,
        metadata: dict[str, Any] | None = None,
    ) -> DocumentRecord:
        """Replace any previous ingest for the same source path."""

    @abstractmethod
    def add_chunks(self, document: DocumentRecord, chunks: Iterable[ChunkInput]) -> int:
        """Store chunks (with optional embeddings) and index them for search."""

    @abstractmethod
    def upsert_entity(
        self,
        *,
        kind: str,
        value: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a graph entity, returning its id."""

    @abstractmethod
    def upsert_relationship(
        self,
        *,
        source_id: str,
        target_id: str,
        rel_type: str,
        document_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a graph relationship, returning its id."""

    @abstractmethod
    def search(
        self,
        query: str,
        *,
        query_embedding: list[float] | None = None,
        limit: int = 8,
        include_graph: bool = True,
    ) -> dict[str, Any]:
        """Return ``{"hits": [...], "graph": [...], "graphView": {...}}``.

        When ``query_embedding`` is provided the backend may blend keyword and
        vector results; otherwise it falls back to keyword search.
        """

    @abstractmethod
    def graph_view(self, query: str, *, limit: int = 80) -> dict[str, list[dict[str, Any]]]:
        """Return ``{"nodes": [...], "edges": [...]}`` near matching entities."""

    @abstractmethod
    def graph_for_document(self, document_id: str) -> dict[str, list[dict[str, Any]]]:
        """Return entities/relationships attached to one document."""

    @abstractmethod
    def chunks_for_document(self, document_id: str) -> list[ChunkRecord]:
        """Return stored chunks for one document in ingestion order."""

    @abstractmethod
    def stats(self) -> dict[str, Any]:
        """Return backend counts and readiness details."""

    def iter_documents(self) -> Iterable[DocumentRecord]:
        """Iterate stored documents (used for backend-to-backend migration).

        Optional: backends that cannot enumerate documents may leave this
        unimplemented.
        """
        raise NotImplementedError

    def close(self) -> None:
        """Release backend resources. Default is a no-op."""
        return None
