"""SQLite-backed local RAG and graph store."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(data: dict[str, Any] | None) -> str:
    return json.dumps(data or {}, ensure_ascii=False, sort_keys=True)


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


class KnowledgeStore:
    """Persistent local RAG index with a small graph mirror."""

    def __init__(self, workspace: Path, store_dir: str = "knowledge"):
        self.root = workspace / store_dir
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "rag.sqlite"
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def initialize(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS documents (
                    id TEXT PRIMARY KEY,
                    source_path TEXT NOT NULL UNIQUE,
                    kind TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    metadata_json TEXT NOT NULL,
                    ingested_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS chunks (
                    id TEXT PRIMARY KEY,
                    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                    chunk_index INTEGER NOT NULL,
                    text TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
                USING fts5(
                    text,
                    chunk_id UNINDEXED,
                    document_id UNINDEXED,
                    source_path UNINDEXED,
                    tokenize='unicode61'
                );

                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    UNIQUE(kind, value)
                );

                CREATE TABLE IF NOT EXISTS relationships (
                    id TEXT PRIMARY KEY,
                    source_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
                    target_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
                    type TEXT NOT NULL,
                    document_id TEXT REFERENCES documents(id) ON DELETE CASCADE,
                    metadata_json TEXT NOT NULL
                );
                """
            )

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
        doc_id = uuid.uuid4().hex
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT id FROM documents WHERE source_path = ?",
                (source_path,),
            ).fetchone()
            if existing:
                self._delete_fts_for_document(conn, existing["id"])
                conn.execute("DELETE FROM documents WHERE id = ?", (existing["id"],))

            conn.execute(
                """
                INSERT INTO documents (
                    id, source_path, kind, sha256, size_bytes, mtime, metadata_json, ingested_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (doc_id, source_path, kind, sha256, size_bytes, mtime, _json(metadata), _now()),
            )
        return DocumentRecord(
            id=doc_id,
            source_path=source_path,
            kind=kind,
            sha256=sha256,
            size_bytes=size_bytes,
            metadata=metadata or {},
        )

    @staticmethod
    def _delete_fts_for_document(conn: sqlite3.Connection, document_id: str) -> None:
        rows = conn.execute(
            "SELECT rowid FROM chunks_fts WHERE document_id = ?",
            (document_id,),
        ).fetchall()
        for row in rows:
            conn.execute("DELETE FROM chunks_fts WHERE rowid = ?", (row["rowid"],))

    def add_chunks(
        self,
        document: DocumentRecord,
        chunks: Iterable[tuple[str, dict[str, Any]]],
    ) -> int:
        """Store chunks and index them in FTS."""
        count = 0
        with self._connect() as conn:
            for index, (text, metadata) in enumerate(chunks):
                cleaned = text.strip()
                if not cleaned:
                    continue
                chunk_id = uuid.uuid4().hex
                conn.execute(
                    """
                    INSERT INTO chunks (id, document_id, chunk_index, text, metadata_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (chunk_id, document.id, index, cleaned, _json(metadata)),
                )
                conn.execute(
                    """
                    INSERT INTO chunks_fts (text, chunk_id, document_id, source_path)
                    VALUES (?, ?, ?, ?)
                    """,
                    (cleaned, chunk_id, document.id, document.source_path),
                )
                count += 1
        return count

    def upsert_entity(
        self,
        *,
        kind: str,
        value: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a graph entity."""
        clean_kind = kind.strip()
        clean_value = value.strip()
        if not clean_kind or not clean_value:
            raise ValueError("entity kind and value are required")
        eid = entity_id(clean_kind, clean_value)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO entities (id, kind, value, metadata_json, first_seen_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(kind, value) DO UPDATE SET
                    metadata_json = excluded.metadata_json
                """,
                (eid, clean_kind, clean_value, _json(metadata), _now()),
            )
        return eid

    def upsert_relationship(
        self,
        *,
        source_id: str,
        target_id: str,
        rel_type: str,
        document_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Create or update a graph relationship."""
        rid = relationship_id(source_id, rel_type, target_id, document_id)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO relationships (
                    id, source_id, target_id, type, document_id, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    metadata_json = excluded.metadata_json
                """,
                (rid, source_id, target_id, rel_type, document_id, _json(metadata)),
            )
        return rid

    def search(self, query: str, *, limit: int = 8) -> list[SearchHit]:
        """Search indexed chunks using SQLite FTS, with a LIKE fallback."""
        tokens = self._fts_tokens(query)
        if not tokens:
            return []
        fts_query = " OR ".join(tokens[:12])
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    """
                    SELECT
                        f.chunk_id,
                        f.document_id,
                        f.source_path,
                        d.kind,
                        c.text,
                        c.metadata_json,
                        bm25(chunks_fts) AS rank
                    FROM chunks_fts f
                    JOIN chunks c ON c.id = f.chunk_id
                    JOIN documents d ON d.id = f.document_id
                    WHERE chunks_fts MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (fts_query, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                like = f"%{query.strip()}%"
                rows = conn.execute(
                    """
                    SELECT
                        c.id AS chunk_id,
                        c.document_id,
                        d.source_path,
                        d.kind,
                        c.text,
                        c.metadata_json,
                        0.0 AS rank
                    FROM chunks c
                    JOIN documents d ON d.id = c.document_id
                    WHERE c.text LIKE ?
                    LIMIT ?
                    """,
                    (like, limit),
                ).fetchall()

        return [
            SearchHit(
                chunk_id=row["chunk_id"],
                document_id=row["document_id"],
                source_path=row["source_path"],
                kind=row["kind"],
                rank=float(row["rank"]),
                text=row["text"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )
            for row in rows
        ]

    @staticmethod
    def _fts_tokens(query: str) -> list[str]:
        raw = query.strip()
        if not raw:
            return []
        tokens = []
        for token in raw.replace("\\", " ").replace("/", " ").split():
            cleaned = "".join(ch for ch in token if ch.isalnum() or ch in "_-.:")
            cleaned = cleaned.strip(".:-_")
            if cleaned:
                escaped = cleaned.replace('"', '""')
                tokens.append(f'"{escaped}"')
        return tokens

    def graph_search(self, query: str, *, limit: int = 12) -> list[dict[str, Any]]:
        """Find graph entities related to a query."""
        terms = [term.strip() for term in query.split() if term.strip()]
        if not terms:
            return []
        where = " OR ".join(["e.value LIKE ?" for _ in terms])
        params = [f"%{term}%" for term in terms]
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT e.id, e.kind, e.value, e.metadata_json, COUNT(r.id) AS degree
                FROM entities e
                LEFT JOIN relationships r ON r.source_id = e.id OR r.target_id = e.id
                WHERE {where}
                GROUP BY e.id, e.kind, e.value, e.metadata_json
                ORDER BY degree DESC, e.kind, e.value
                LIMIT ?
                """,
                [*params, limit],
            ).fetchall()
        return [
            {
                "id": row["id"],
                "kind": row["kind"],
                "value": row["value"],
                "degree": int(row["degree"] or 0),
                "metadata": json.loads(row["metadata_json"] or "{}"),
            }
            for row in rows
        ]

    def graph_for_document(self, document_id: str) -> dict[str, list[dict[str, Any]]]:
        """Return local graph rows for one document."""
        with self._connect() as conn:
            relationships = conn.execute(
                """
                SELECT id, source_id, target_id, type, document_id, metadata_json
                FROM relationships
                WHERE document_id = ?
                """,
                (document_id,),
            ).fetchall()
            entity_ids = {
                rel["source_id"] for rel in relationships
            } | {
                rel["target_id"] for rel in relationships
            }
            entities = []
            if entity_ids:
                placeholders = ",".join("?" for _ in entity_ids)
                entities = conn.execute(
                    f"""
                    SELECT id, kind, value, metadata_json
                    FROM entities
                    WHERE id IN ({placeholders})
                    """,
                    list(entity_ids),
                ).fetchall()

        return {
            "entities": [
                {
                    "id": row["id"],
                    "kind": row["kind"],
                    "value": row["value"],
                    "metadata": json.loads(row["metadata_json"] or "{}"),
                }
                for row in entities
            ],
            "relationships": [
                {
                    "id": row["id"],
                    "source_id": row["source_id"],
                    "target_id": row["target_id"],
                    "type": row["type"],
                    "document_id": row["document_id"],
                    "metadata": json.loads(row["metadata_json"] or "{}"),
                }
                for row in relationships
            ],
        }

    def chunks_for_document(self, document_id: str) -> list[ChunkRecord]:
        """Return stored chunks for one document in ingestion order."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, document_id, chunk_index, text, metadata_json
                FROM chunks
                WHERE document_id = ?
                ORDER BY chunk_index
                """,
                (document_id,),
            ).fetchall()
        return [
            ChunkRecord(
                id=row["id"],
                document_id=row["document_id"],
                chunk_index=int(row["chunk_index"]),
                text=row["text"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )
            for row in rows
        ]

    def stats(self) -> dict[str, int | str]:
        """Return store statistics."""
        with self._connect() as conn:
            return {
                "dbPath": str(self.db_path),
                "documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
                "chunks": conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "entities": conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
                "relationships": conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
            }
