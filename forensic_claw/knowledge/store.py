"""SQLite-backed knowledge backend: keyword (FTS5) + vector (sqlite-vec) + graph.

This is the default, fully native backend. It needs no external server: FTS5 is
built into SQLite and semantic search uses the embeddable ``sqlite-vec``
extension. If the extension cannot be loaded (e.g. a Python build without
loadable-extension support), the backend transparently degrades to keyword-only
search.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from forensic_claw.knowledge.base import (
    ChunkInput,
    ChunkRecord,
    DocumentRecord,
    KnowledgeBackend,
    SearchHit,
    entity_id,
    relationship_id,
)

__all__ = [
    "SqliteKnowledgeBackend",
    "KnowledgeStore",
    "DocumentRecord",
    "ChunkRecord",
    "SearchHit",
    "entity_id",
    "relationship_id",
]

# Reciprocal-rank-fusion constant; dampens the contribution of lower ranks.
_RRF_K = 60


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(data: dict[str, Any] | None) -> str:
    return json.dumps(data or {}, ensure_ascii=False, sort_keys=True)


def _load_sqlite_vec(conn: sqlite3.Connection) -> bool:
    """Load the sqlite-vec extension into ``conn``. Return True on success."""
    try:
        import sqlite_vec
    except Exception as exc:  # pragma: no cover - dependency missing
        logger.warning("sqlite-vec unavailable; semantic search disabled: {}", exc)
        return False
    try:
        conn.enable_load_extension(True)
        sqlite_vec.load(conn)
        conn.enable_load_extension(False)
        return True
    except Exception as exc:
        logger.warning("Could not load sqlite-vec; semantic search disabled: {}", exc)
        return False


def _serialize_vector(vector: list[float]) -> bytes:
    import sqlite_vec

    return sqlite_vec.serialize_float32([float(x) for x in vector])


class SqliteKnowledgeBackend(KnowledgeBackend):
    """Persistent local RAG index with a graph mirror and optional vectors."""

    name = "sqlite"

    def __init__(self, workspace: Path, store_dir: str = "knowledge"):
        self.root = workspace / store_dir
        self.root.mkdir(parents=True, exist_ok=True)
        self.db_path = self.root / "rag.sqlite"
        self._vec_available = False
        self.initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        self._vec_available = _load_sqlite_vec(conn)
        return conn

    @property
    def vector_enabled(self) -> bool:
        """Whether semantic (vector) search is usable in this environment."""
        return self._vec_available

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

                CREATE TABLE IF NOT EXISTS vec_meta (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    dim INTEGER NOT NULL
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

    # ----- vector helpers -------------------------------------------------

    def _vec_dim(self, conn: sqlite3.Connection) -> int | None:
        row = conn.execute("SELECT dim FROM vec_meta WHERE id = 1").fetchone()
        return int(row["dim"]) if row else None

    def _ensure_vec_table(self, conn: sqlite3.Connection, dim: int) -> bool:
        """Create the vec0 table on first use; refuse mismatched dimensions."""
        if not self._vec_available or dim <= 0:
            return False
        existing = self._vec_dim(conn)
        if existing is None:
            conn.execute(
                f"CREATE VIRTUAL TABLE IF NOT EXISTS chunks_vec "
                f"USING vec0(chunk_id TEXT PRIMARY KEY, embedding float[{dim}])"
            )
            conn.execute("INSERT OR REPLACE INTO vec_meta (id, dim) VALUES (1, ?)", (dim,))
            return True
        if existing != dim:
            logger.warning(
                "Embedding dimension changed ({} -> {}); skipping vector index for this chunk",
                existing,
                dim,
            )
            return False
        return True

    def _has_vec_table(self, conn: sqlite3.Connection) -> bool:
        if not self._vec_available:
            return False
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('table','virtual') AND name = 'chunks_vec'"
        ).fetchone()
        if row is not None:
            return True
        # vec0 virtual tables register their shadow tables; check meta as a proxy.
        return self._vec_dim(conn) is not None

    # ----- documents / chunks --------------------------------------------

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
                self._delete_chunks_for_document(conn, existing["id"])
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

    def _delete_chunks_for_document(self, conn: sqlite3.Connection, document_id: str) -> None:
        rows = conn.execute(
            "SELECT id FROM chunks WHERE document_id = ?",
            (document_id,),
        ).fetchall()
        chunk_ids = [row["id"] for row in rows]
        fts_rows = conn.execute(
            "SELECT rowid FROM chunks_fts WHERE document_id = ?",
            (document_id,),
        ).fetchall()
        for row in fts_rows:
            conn.execute("DELETE FROM chunks_fts WHERE rowid = ?", (row["rowid"],))
        if chunk_ids and self._has_vec_table(conn):
            placeholders = ",".join("?" for _ in chunk_ids)
            try:
                conn.execute(
                    f"DELETE FROM chunks_vec WHERE chunk_id IN ({placeholders})",
                    chunk_ids,
                )
            except sqlite3.OperationalError:
                pass
        # chunks rows cascade with the document delete.

    def add_chunks(self, document: DocumentRecord, chunks: Iterable[ChunkInput]) -> int:
        """Store chunks (with optional embeddings) and index them for search."""
        count = 0
        with self._connect() as conn:
            for index, item in enumerate(chunks):
                text, metadata, embedding = self._normalize_chunk_item(item)
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
                if embedding and self._ensure_vec_table(conn, len(embedding)):
                    conn.execute(
                        "INSERT INTO chunks_vec (chunk_id, embedding) VALUES (?, ?)",
                        (chunk_id, _serialize_vector(embedding)),
                    )
                count += 1
        return count

    @staticmethod
    def _normalize_chunk_item(item: Any) -> ChunkInput:
        """Accept (text, metadata) or (text, metadata, embedding)."""
        if len(item) == 3:
            text, metadata, embedding = item
            return text, metadata or {}, embedding
        text, metadata = item
        return text, metadata or {}, None

    # ----- graph ----------------------------------------------------------

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

    # ----- search ---------------------------------------------------------

    def search(
        self,
        query: str,
        *,
        query_embedding: list[float] | None = None,
        limit: int = 8,
        include_graph: bool = True,
    ) -> dict[str, Any]:
        """Hybrid keyword + vector search with a graph mirror."""
        hits = self._search_hits(query, query_embedding=query_embedding, limit=limit)
        graph = self.graph_search(query, limit=limit) if include_graph else []
        graph_view = (
            self.graph_view(query, limit=max(limit * 6, 24))
            if include_graph
            else {"nodes": [], "edges": []}
        )
        return {
            "hits": [
                {
                    "sourcePath": hit.source_path,
                    "kind": hit.kind,
                    "rank": hit.rank,
                    "text": hit.text,
                    "metadata": hit.metadata,
                }
                for hit in hits
            ],
            "graph": graph,
            "graphView": graph_view,
        }

    def _search_hits(
        self,
        query: str,
        *,
        query_embedding: list[float] | None,
        limit: int,
    ) -> list[SearchHit]:
        keyword_ids = self._keyword_chunk_ids(query, limit=limit)
        vector_ids: list[str] = []
        if query_embedding:
            vector_ids = self._vector_chunk_ids(query_embedding, limit=limit)

        if not vector_ids:
            # Keyword-only: preserve original BM25 ordering and rank.
            return self._fetch_hits(keyword_ids, limit=limit)

        fused = self._reciprocal_rank_fusion(keyword_ids, vector_ids)
        ordered = sorted(fused.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        ranks = {cid: score for cid, score in ordered}
        hits = self._fetch_hits([cid for cid, _ in ordered], limit=limit, ranks=ranks)
        return hits

    def _keyword_chunk_ids(self, query: str, *, limit: int) -> list[str]:
        tokens = self._fts_tokens(query)
        if not tokens:
            return []
        fts_query = " OR ".join(tokens[:12])
        with self._connect() as conn:
            try:
                rows = conn.execute(
                    """
                    SELECT f.chunk_id AS chunk_id, bm25(chunks_fts) AS rank
                    FROM chunks_fts f
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
                    SELECT c.id AS chunk_id
                    FROM chunks c
                    WHERE c.text LIKE ?
                    LIMIT ?
                    """,
                    (like, limit),
                ).fetchall()
        return [row["chunk_id"] for row in rows]

    def _vector_chunk_ids(self, query_embedding: list[float], *, limit: int) -> list[str]:
        with self._connect() as conn:
            if not self._has_vec_table(conn):
                return []
            dim = self._vec_dim(conn)
            if dim is None or len(query_embedding) != dim:
                return []
            try:
                rows = conn.execute(
                    """
                    SELECT chunk_id
                    FROM chunks_vec
                    WHERE embedding MATCH ? AND k = ?
                    ORDER BY distance
                    """,
                    (_serialize_vector(query_embedding), limit),
                ).fetchall()
            except sqlite3.OperationalError as exc:
                logger.warning("Vector search failed; using keyword results only: {}", exc)
                return []
        return [row["chunk_id"] for row in rows]

    @staticmethod
    def _reciprocal_rank_fusion(*rank_lists: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        for ranked in rank_lists:
            for position, chunk_id in enumerate(ranked):
                scores[chunk_id] = scores.get(chunk_id, 0.0) + 1.0 / (_RRF_K + position + 1)
        return scores

    def _fetch_hits(
        self,
        chunk_ids: list[str],
        *,
        limit: int,
        ranks: dict[str, float] | None = None,
    ) -> list[SearchHit]:
        if not chunk_ids:
            return []
        placeholders = ",".join("?" for _ in chunk_ids)
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT c.id AS chunk_id, c.document_id, d.source_path, d.kind,
                       c.text, c.metadata_json
                FROM chunks c
                JOIN documents d ON d.id = c.document_id
                WHERE c.id IN ({placeholders})
                """,
                chunk_ids,
            ).fetchall()
        by_id = {row["chunk_id"]: row for row in rows}
        hits: list[SearchHit] = []
        for position, chunk_id in enumerate(chunk_ids):
            row = by_id.get(chunk_id)
            if row is None:
                continue
            rank = ranks[chunk_id] if ranks and chunk_id in ranks else float(position)
            hits.append(
                SearchHit(
                    chunk_id=row["chunk_id"],
                    document_id=row["document_id"],
                    source_path=row["source_path"],
                    kind=row["kind"],
                    rank=rank,
                    text=row["text"],
                    metadata=json.loads(row["metadata_json"] or "{}"),
                )
            )
            if len(hits) >= limit:
                break
        return hits

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

    def graph_view(self, query: str, *, limit: int = 80) -> dict[str, list[dict[str, Any]]]:
        """Return nodes and edges near graph entities that match a query."""
        seeds = self.graph_search(query, limit=max(1, min(limit, 24)))
        if not seeds:
            return {"nodes": [], "edges": []}

        seed_ids = [item["id"] for item in seeds if item.get("id")]
        if not seed_ids:
            return {"nodes": [], "edges": []}
        placeholders = ",".join("?" for _ in seed_ids)
        with self._connect() as conn:
            relationships = conn.execute(
                f"""
                SELECT id, source_id, target_id, type, document_id, metadata_json
                FROM relationships
                WHERE source_id IN ({placeholders}) OR target_id IN ({placeholders})
                LIMIT ?
                """,
                [*seed_ids, *seed_ids, limit],
            ).fetchall()
            entity_ids = set(seed_ids)
            for rel in relationships:
                entity_ids.add(rel["source_id"])
                entity_ids.add(rel["target_id"])

            entity_placeholders = ",".join("?" for _ in entity_ids)
            entities = conn.execute(
                f"""
                SELECT id, kind, value, metadata_json
                FROM entities
                WHERE id IN ({entity_placeholders})
                """,
                list(entity_ids),
            ).fetchall()

        return {
            "nodes": [
                {
                    "id": row["id"],
                    "label": row["value"],
                    "kind": row["kind"],
                    "group": row["kind"],
                    "metadata": json.loads(row["metadata_json"] or "{}"),
                }
                for row in entities
            ],
            "edges": [
                {
                    "id": row["id"],
                    "source": row["source_id"],
                    "target": row["target_id"],
                    "label": row["type"],
                    "type": row["type"],
                    "metadata": json.loads(row["metadata_json"] or "{}"),
                }
                for row in relationships
            ],
        }

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
            entity_ids = {rel["source_id"] for rel in relationships} | {
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

    def iter_documents(self) -> Iterable[DocumentRecord]:
        """Iterate stored documents for backend-to-backend migration."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, source_path, kind, sha256, size_bytes, metadata_json
                FROM documents
                ORDER BY ingested_at
                """
            ).fetchall()
        for row in rows:
            yield DocumentRecord(
                id=row["id"],
                source_path=row["source_path"],
                kind=row["kind"],
                sha256=row["sha256"],
                size_bytes=int(row["size_bytes"]),
                metadata=json.loads(row["metadata_json"] or "{}"),
            )

    def stats(self) -> dict[str, Any]:
        """Return store statistics."""
        with self._connect() as conn:
            embedded = 0
            if self._has_vec_table(conn):
                try:
                    embedded = conn.execute("SELECT COUNT(*) FROM chunks_vec").fetchone()[0]
                except sqlite3.OperationalError:
                    embedded = 0
            return {
                "dbPath": str(self.db_path),
                "documents": conn.execute("SELECT COUNT(*) FROM documents").fetchone()[0],
                "chunks": conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0],
                "entities": conn.execute("SELECT COUNT(*) FROM entities").fetchone()[0],
                "relationships": conn.execute("SELECT COUNT(*) FROM relationships").fetchone()[0],
                "embeddedChunks": embedded,
                "vectorAvailable": self._vec_available,
            }


# Backwards-compatible alias for the previous class name.
KnowledgeStore = SqliteKnowledgeBackend
