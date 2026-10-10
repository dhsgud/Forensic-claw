"""Local evidence ingestion service for RAG and graph search."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from contextlib import closing
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import chardet
from loguru import logger

from forensic_claw.forensics.artifacts import read_artifact
from forensic_claw.forensics.case import CaseStore
from forensic_claw.forensics.trust import EvidenceObject
from forensic_claw.knowledge.base import ChunkInput, DocumentRecord
from forensic_claw.knowledge.embeddings import create_embedder
from forensic_claw.knowledge.factory import create_backend

_DEFAULT_PATTERNS = (
    "*.log",
    "*.txt",
    "*.csv",
    "*.json",
    "*.jsonl",
    "*.ndjson",
    "History",
    "History.sqlite",
    "*.sqlite",
    "*.sqlite3",
    "*.db",
    "*.xml",
    "*.evtx",
    "*.reg",
    "SYSTEM",
    "SOFTWARE",
    "SAM",
    "SECURITY",
    "NTUSER.DAT",
)
_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "__pycache__",
    ".ruff_cache",
    ".pytest_cache",
    "knowledge",
}
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)

_IP_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
_URL_RE = re.compile(r"https?://[^\s\"'<>()]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[a-z]:\\[^\r\n\t<>\"|?*]+")
_REGISTRY_RE = re.compile(r"(?i)\bHKEY_[A-Z_]+\\[^\s]+")
_EXECUTABLE_RE = re.compile(r"(?i)\b[\w.-]+\.(?:exe|dll|ps1|bat|cmd|msi|scr|sys)\b")


@dataclass
class KnowledgeIngestResult:
    """Summary of one ingestion run."""

    ok: bool
    ready: bool
    scanned_files: int = 0
    ingested_files: int = 0
    skipped_files: int = 0
    chunks: int = 0
    entities: int = 0
    relationships: int = 0
    embedded_chunks: int = 0
    errors: list[str] = field(default_factory=list)
    vector: dict[str, Any] = field(default_factory=dict)


class KnowledgeService:
    """Ingest local artifacts into a RAG index and graph store."""

    def __init__(self, workspace: Path, config: Any):
        self.workspace = workspace
        self.config = config
        self.enabled = bool(getattr(config, "enabled", True))
        self.backend = create_backend(config, workspace)
        self.embedder = create_embedder(config)
        self.model_security_proxy = None
        logger.debug(
            "KnowledgeService initialized: workspace={} enabled={} backend={} vectorReady={}",
            workspace,
            self.enabled,
            self.backend.name,
            self.embedder.ready,
        )

    def set_embedding_endpoint(
        self,
        *,
        api_base: str | None,
        api_key: str | None = None,
        model: str | None = None,
        security_proxy: Any = None,
    ) -> None:
        """Point semantic search at the active LLM endpoint when none is set.

        The knowledge ``vector.api_base``/``vector.model`` config wins when
        present; otherwise the running provider's endpoint is injected so that
        embeddings reuse the same local server as chat.
        """
        if api_base and not self.embedder.api_base:
            self.embedder.api_base = api_base.strip()
        if model and not self.embedder.model:
            self.embedder.model = model.strip()
        if api_key:
            self.embedder.api_key = api_key
        self.model_security_proxy = security_proxy
        self.embedder.security_proxy = security_proxy
        self.embedder._client = None
        logger.debug(
            "Knowledge embedding endpoint set: ready={} model={} apiBase={}",
            self.embedder.ready,
            self.embedder.model,
            self.embedder.api_base,
        )

    def status(self) -> dict[str, Any]:
        """Return local RAG and graph backend readiness."""
        return {
            "enabled": self.enabled,
            "backend": self.backend.name,
            "store": self.backend.stats(),
            "vector": self._vector_status(),
        }

    def reconfigure(self, config: Any) -> None:
        """Apply updated knowledge settings to future ingest/search operations."""
        self.config = config
        self.enabled = bool(getattr(config, "enabled", True))
        self.backend = create_backend(config, self.workspace)
        self.embedder = create_embedder(config)
        self.embedder.security_proxy = self.model_security_proxy
        logger.info(
            "KnowledgeService reconfigured: enabled={} backend={} vectorReady={}",
            self.enabled,
            self.backend.name,
            self.embedder.ready,
        )

    def _vector_status(self) -> dict[str, Any]:
        available = getattr(self.backend, "vector_enabled", False)
        if not self.embedder.enabled:
            state = "disabled"
        elif not available:
            state = "unavailable"
        elif not self.embedder.ready:
            state = "not_configured"
        else:
            state = "ready"
        return {
            "enabled": self.embedder.enabled,
            "available": bool(available),
            "configured": self.embedder.ready,
            "model": self.embedder.model,
            "state": state,
        }

    def ingest_path(
        self,
        path: str | Path,
        *,
        recursive: bool = True,
        file_globs: list[str] | None = None,
        max_files: int | None = None,
        case_name: str | None = None,
        case_id: str | None = None,
        investigator_name: str | None = None,
    ) -> KnowledgeIngestResult:
        """Ingest a file or directory."""
        if not self.enabled:
            logger.warning("Knowledge ingest skipped because knowledge service is disabled")
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=["Knowledge RAG is disabled in config."],
                vector=self._vector_status(),
            )

        target = Path(path).expanduser()
        if not target.is_absolute():
            target = self.workspace / target
        target = target.resolve()
        if not target.exists():
            logger.warning("Knowledge ingest target not found: {}", target)
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=[f"Path not found: {target}"],
                vector=self._vector_status(),
            )

        result = KnowledgeIngestResult(ok=True, ready=False)
        logger.info(
            "Knowledge ingest started: target={} recursive={} backend={} maxFiles={}",
            target,
            recursive,
            self.backend.name,
            max_files,
        )

        for file_path in self._iter_files(
            target, recursive=recursive, file_globs=file_globs, max_files=max_files
        ):
            result.scanned_files += 1
            try:
                one = self._ingest_file(
                    file_path,
                    case_name=case_name or case_id,
                    case_id=case_id,
                    investigator_name=investigator_name,
                )
                if one is None:
                    result.skipped_files += 1
                    logger.debug("Knowledge ingest skipped non-text file: {}", file_path)
                    continue
                result.ingested_files += 1
                result.chunks += int(one.get("chunks", 0))
                result.entities += int(one.get("entities", 0))
                result.relationships += int(one.get("relationships", 0))
                result.embedded_chunks += int(one.get("embeddedChunks", 0))
            except Exception as exc:
                logger.exception("Knowledge ingest failed for file: {}", file_path)
                result.errors.append(f"{file_path}: {exc}")

        if not result.scanned_files:
            result.errors.append(f"No ingestible files found under: {target}")
        result.ready = result.ok and result.ingested_files > 0
        result.vector = self._vector_status()
        logger.info(
            "Knowledge ingest finished: target={} ready={} scanned={} ingested={} skipped={} "
            "chunks={} entities={} relationships={} embedded={} errors={}",
            target,
            result.ready,
            result.scanned_files,
            result.ingested_files,
            result.skipped_files,
            result.chunks,
            result.entities,
            result.relationships,
            result.embedded_chunks,
            len(result.errors),
        )
        return result

    def search(
        self, query: str, *, limit: int = 8, include_graph: bool = True, case_id: str | None = None
    ) -> dict[str, Any]:
        """Retrieve RAG chunks and graph hints for a question."""
        query_embedding = self.embedder.embed_one(query) if self.embedder.ready else None
        logger.debug(
            "Knowledge search started: backend={} queryLength={} limit={} includeGraph={} vector={}",
            self.backend.name,
            len(query),
            limit,
            include_graph,
            query_embedding is not None,
        )
        data = self.backend.search(
            query,
            query_embedding=query_embedding,
            limit=limit,
            include_graph=include_graph,
            case_id=case_id,
        )
        valid, rejected = self.verify_hits(data.get("hits", []))
        if case_id and include_graph:
            nodes, edges = {}, {}
            for document_id in {hit["metadata"].get("documentId") for hit in valid}:
                if not document_id:
                    continue
                graph = self.backend.graph_for_document(document_id)
                for node in graph.get("entities", []):
                    nodes[node["id"]] = {
                        "id": node["id"],
                        "label": node["value"],
                        "kind": node["kind"],
                        "metadata": node["metadata"],
                    }
                for edge in graph.get("relationships", []):
                    edges[edge["id"]] = {
                        "id": edge["id"],
                        "source": edge["source_id"],
                        "target": edge["target_id"],
                        "type": edge["type"],
                        "label": edge["type"],
                        "metadata": edge["metadata"],
                    }
            data["graph"] = list(nodes.values())
            data["graphView"] = {"nodes": list(nodes.values()), "edges": list(edges.values())}
        logger.debug(
            "Knowledge search completed: hits={} graphItems={} graphNodes={} graphEdges={}",
            len(data.get("hits", [])),
            len(data.get("graph", [])),
            len(data.get("graphView", {}).get("nodes", [])),
            len(data.get("graphView", {}).get("edges", [])),
        )
        return {
            "query": query,
            "backend": self.backend.name,
            "vector": query_embedding is not None,
            "hits": valid,
            "rejected": rejected,
            "graph": data.get("graph", []),
            "graphView": data.get("graphView", {"nodes": [], "edges": []}),
        }

    def verify_hits(
        self, hits: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Recheck current source bytes, including sidecars, before publishing claims."""
        valid, rejected = [], []
        hashes = {}
        for hit in hits:
            source = hit["sourcePath"]
            if source not in hashes:
                try:
                    hashes[source] = self._sha256(Path(source))
                except OSError:
                    hashes[source] = None
            hit["hash_verified"] = bool(hit.get("sha256")) and hashes[source] == hit.get("sha256")
            components = hit.get("metadata", {}).get("hashes", {})
            if not isinstance(components, dict):
                hit["hash_verified"] = False
                components = {}
            for name, expected in components.items():
                if not isinstance(expected, dict):
                    hit["hash_verified"] = False
                    break
                component = Path(source).parent / name
                if not component.resolve().is_relative_to(Path(source).parent.resolve()):
                    hit["hash_verified"] = False
                    break
                component_key = str(component)
                if component_key not in hashes:
                    try:
                        hashes[component_key] = self._sha256(component)
                    except OSError:
                        hashes[component_key] = None
                if hashes[component_key] != expected.get("sha256"):
                    hit["hash_verified"] = False
            item = EvidenceObject.from_hit(hit)
            if item.eligible:
                valid.append(hit)
            else:
                rejected.append(
                    {
                        "evidenceId": item.id,
                        "sourcePath": item.source,
                        "grade": "UNVERIFIED" if not item.hash_verified else "FLAGGED",
                        "issues": item.issues,
                    }
                )
        return valid, rejected

    def discover_chrome_history(
        self, *, max_files: int = 20, allowed_dir: Path | None = None
    ) -> list[Path]:
        """Find Chrome History SQLite databases in likely local locations."""
        candidates: list[Path] = []
        seen: set[Path] = set()
        for root in self._chrome_history_roots():
            if allowed_dir and not root.resolve().is_relative_to(allowed_dir.resolve()):
                continue
            if not root.exists():
                continue
            for path in self._walk_history_files(root):
                resolved = path.resolve()
                if allowed_dir and not resolved.is_relative_to(allowed_dir.resolve()):
                    continue
                if resolved in seen:
                    continue
                seen.add(resolved)
                if self._is_chrome_history(resolved):
                    candidates.append(resolved)
                    if len(candidates) >= max_files:
                        return candidates
        return candidates

    def prepare_chrome_history(
        self,
        *,
        case_name: str | None = None,
        case_id: str | None = None,
        investigator_name: str | None = None,
        max_files: int = 20,
        allowed_dir: Path | None = None,
    ) -> KnowledgeIngestResult:
        """Discover Chrome History databases and ingest them."""
        paths = self.discover_chrome_history(max_files=max_files, allowed_dir=allowed_dir)
        if not paths:
            logger.warning("Chrome History preparation found no databases")
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=[
                    "No Chrome History database found in local Chrome profile paths or workspace."
                ],
                vector=self._vector_status(),
            )

        result = KnowledgeIngestResult(ok=True, ready=False)
        logger.info("Chrome History preparation started: files={}", len(paths))
        for path in paths:
            one = self.ingest_path(
                path,
                recursive=False,
                case_name=case_name,
                case_id=case_id,
                investigator_name=investigator_name,
            )
            result.scanned_files += one.scanned_files
            result.ingested_files += one.ingested_files
            result.skipped_files += one.skipped_files
            result.chunks += one.chunks
            result.entities += one.entities
            result.relationships += one.relationships
            result.embedded_chunks += one.embedded_chunks
            result.errors.extend(one.errors)

        result.ready = result.ingested_files > 0
        result.ok = result.ready
        result.vector = self._vector_status()
        logger.info(
            "Chrome History preparation finished: ready={} scanned={} ingested={} errors={}",
            result.ready,
            result.scanned_files,
            result.ingested_files,
            len(result.errors),
        )
        return result

    def _chrome_history_roots(self) -> list[Path]:
        roots: list[Path] = []
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            roots.append(Path(local_app_data) / "Google" / "Chrome" / "User Data")
        else:
            user_profile = os.environ.get("USERPROFILE")
            if user_profile:
                roots.append(
                    Path(user_profile) / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
                )
        roots.append(self.workspace)

        deduped: list[Path] = []
        seen: set[Path] = set()
        for root in roots:
            resolved = root.expanduser().resolve(strict=False)
            if resolved not in seen:
                seen.add(resolved)
                deduped.append(resolved)
        return deduped

    def _walk_history_files(self, root: Path) -> Iterable[Path]:
        for current, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
            for filename in sorted(filenames):
                if filename in {"History", "History.sqlite"}:
                    yield Path(current) / filename

    def _iter_files(
        self,
        target: Path,
        *,
        recursive: bool,
        file_globs: list[str] | None,
        max_files: int | None,
    ) -> Iterable[Path]:
        if target.is_file():
            yield target
            return

        patterns = tuple(file_globs or _DEFAULT_PATTERNS)
        yielded = 0
        if recursive:
            walker = os.walk(target)
        else:
            walker = (
                (str(target), [], [item.name for item in target.iterdir() if item.is_file()]),
            )

        for root, dirnames, filenames in walker:
            dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
            for filename in sorted(filenames):
                if not any(fnmatch.fnmatch(filename, pattern) for pattern in patterns):
                    continue
                yield Path(root) / filename
                yielded += 1
                if max_files and yielded >= max_files:
                    return

    def _embed_chunks(
        self, chunks: list[tuple[str, dict[str, Any]]]
    ) -> tuple[list[ChunkInput], int]:
        """Attach embeddings to chunks; degrade to no-embedding on failure."""
        if not chunks:
            return [], 0
        if not self.embedder.ready:
            return [(text, metadata, None) for text, metadata in chunks], 0
        vectors = self.embedder.embed([text for text, _ in chunks])
        if vectors is None:
            return [(text, metadata, None) for text, metadata in chunks], 0
        prepared: list[ChunkInput] = [
            (text, metadata, vectors[index]) for index, (text, metadata) in enumerate(chunks)
        ]
        return prepared, len(vectors)

    def _ingest_file(
        self,
        path: Path,
        *,
        case_name: str | None,
        investigator_name: str | None,
        case_id: str | None = None,
    ) -> dict[str, Any] | None:
        size = path.stat().st_size
        max_size = int(getattr(self.config, "max_file_bytes", 256 * 1024 * 1024))
        if size > max_size:
            logger.warning(
                "Knowledge file exceeds max size: path={} size={} max={}", path, size, max_size
            )
            raise ValueError(f"file exceeds maxFileBytes ({size} > {max_size})")

        logger.debug("Knowledge file ingest started: path={} size={}", path, size)
        provenance = {"timestamp": datetime.now(UTC).isoformat(), "timestampKind": "acquired_at"}
        if case_name:
            path, provenance = CaseStore(self.workspace).acquire_source(
                path, case_name=case_name, investigator_name=investigator_name, case_id=case_id
            )
        baseline = self._sha256(path)
        if self._is_chrome_history(path):
            logger.info("Knowledge file detected as Chrome History database: {}", path)
            return self._ingest_chrome_history(
                path,
                case_name=case_name,
                investigator_name=investigator_name,
                provenance=provenance,
            )

        parsed = read_artifact(path)
        text_chunks = parsed if parsed is not None else list(self._text_chunks(path))
        if not text_chunks:
            logger.debug("Knowledge file has no ingestible text chunks: {}", path)
            return None
        if self._sha256(path) != baseline:
            raise ValueError("Evidence changed during parsing")

        document = self.backend.replace_document(
            source_path=str(path),
            kind="windows_artifact" if parsed else "text_log",
            sha256=baseline,
            size_bytes=size,
            mtime=path.stat().st_mtime,
            metadata={
                "caseName": case_name,
                "investigatorName": investigator_name,
                "filename": path.name,
                **provenance,
            },
        )
        embedded_chunks, embedded_count = self._embed_chunks(text_chunks)
        chunk_count = self.backend.add_chunks(document, embedded_chunks)
        graph_counts = self._index_text_graph(
            document,
            (text for text, _metadata in text_chunks),
        )
        if parsed:
            self._index_event_relationships(document, text_chunks)
        self._add_case_graph(
            document,
            case_name=case_name,
            investigator_name=investigator_name,
        )
        self._register_case_document(document)
        logger.debug(
            "Text file indexed locally: documentId={} chunks={} embedded={} entities={} relationships={}",
            document.id,
            chunk_count,
            embedded_count,
            graph_counts["entities"],
            graph_counts["relationships"],
        )
        return {
            "chunks": chunk_count,
            "embeddedChunks": embedded_count,
            "entities": graph_counts["entities"],
            "relationships": graph_counts["relationships"],
        }

    def _text_chunks(self, path: Path) -> Iterable[tuple[str, dict[str, Any]]]:
        encoding = self._detect_text_encoding(path)
        if not encoding:
            return
        chunk_chars = int(getattr(self.config, "chunk_chars", 6000))
        overlap = int(getattr(self.config, "chunk_overlap_chars", 400))
        buffer = ""
        line_start = 1
        line_no = 0
        with path.open("r", encoding=encoding, errors="replace", newline="") as handle:
            for line in handle:
                line_no += 1
                if not buffer:
                    line_start = line_no
                buffer += line
                if len(buffer) >= chunk_chars:
                    yield (
                        buffer,
                        {"lineStart": line_start, "lineEnd": line_no, "encoding": encoding},
                    )
                    buffer = buffer[-overlap:] if overlap > 0 else ""
                    line_start = line_no
            if buffer.strip():
                yield buffer, {"lineStart": line_start, "lineEnd": line_no, "encoding": encoding}

    @staticmethod
    def _detect_text_encoding(path: Path) -> str | None:
        with path.open("rb") as handle:
            sample = handle.read(65536)
        if not sample:
            return None
        candidates = []
        if sample.startswith(b"\xef\xbb\xbf"):
            candidates.append("utf-8-sig")
        if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
            candidates.append("utf-16")
        candidates.extend(["utf-8", "cp949"])
        detected = chardet.detect(sample).get("encoding")
        if detected:
            candidates.append(detected)
        for encoding in dict.fromkeys(candidates):
            try:
                decoded = sample.decode(encoding)
            except (LookupError, UnicodeDecodeError):
                continue
            if KnowledgeService._looks_like_text(decoded):
                return encoding
        return None

    @staticmethod
    def _looks_like_text(text: str) -> bool:
        if not text:
            return True
        if "\x00" in text:
            return False
        controls = sum(1 for char in text if ord(char) < 32 and char not in "\n\r\t\f")
        return controls <= max(2, len(text) // 100)

    def _is_chrome_history(self, path: Path) -> bool:
        if path.name.lower() not in {"history", "history.sqlite"} and path.suffix.lower() not in {
            ".sqlite",
            ".sqlite3",
            ".db",
        }:
            return False
        temp = self._copy_for_sqlite(path)
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(temp)
            tables = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            }
            return {"urls", "visits"}.issubset(tables)
        except sqlite3.DatabaseError:
            return False
        finally:
            if conn is not None:
                conn.close()
            temp.unlink(missing_ok=True)

    def _ingest_chrome_history(
        self,
        path: Path,
        *,
        case_name: str | None,
        investigator_name: str | None,
        provenance: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        max_rows = int(getattr(self.config, "max_chrome_rows", 10000))
        baseline = self._sha256(path)
        logger.info("Chrome History ingest started: path={} maxRows={}", path, max_rows)
        temp = self._copy_for_sqlite(path)
        rows: list[dict[str, Any]] = []
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(temp)
            conn.row_factory = sqlite3.Row
            for row in conn.execute(
                """
                SELECT
                    urls.id AS url_id,
                    visits.id AS visit_id,
                    visits.from_visit AS from_visit,
                    visits.transition AS transition,
                    urls.url AS url,
                    urls.title AS title,
                    urls.visit_count AS visit_count,
                    urls.last_visit_time AS last_visit_time,
                    visits.visit_time AS latest_visit_time,
                    (SELECT COUNT(*) FROM visits v WHERE v.url=urls.id) AS observed_visits
                FROM urls
                LEFT JOIN visits ON visits.url = urls.id
                ORDER BY COALESCE(visits.visit_time, urls.last_visit_time) DESC
                LIMIT ?
                """,
                (max_rows,),
            ):
                rows.append(dict(row))
        finally:
            if conn is not None:
                conn.close()
            temp.unlink(missing_ok=True)

        if self._sha256(path) != baseline:
            raise ValueError("Chrome History changed during parsing")
        document = self.backend.replace_document(
            source_path=str(path),
            kind="chrome_history",
            sha256=baseline,
            size_bytes=path.stat().st_size,
            mtime=path.stat().st_mtime,
            metadata={
                "caseName": case_name,
                "investigatorName": investigator_name,
                "filename": path.name,
                "rows": len(rows),
                **(provenance or {}),
            },
        )
        chunks: list[tuple[str, dict[str, Any]]] = []
        for index, row in enumerate(rows):
            latest = self._chrome_time(row.get("latest_visit_time") or row.get("last_visit_time"))
            text = "\n".join(
                [
                    f"Chrome History URL: {row.get('url') or ''}",
                    f"Title: {row.get('title') or ''}",
                    f"Visit Count: {row.get('visit_count') or 0}",
                    f"Observed Visits: {row.get('observed_visits') or 0}",
                    f"Latest Visit UTC: {latest or 'unknown'}",
                    f"Visit ID: {row.get('visit_id')}",
                ]
            )
            chunks.append(
                (
                    text,
                    {
                        "rowIndex": index,
                        "urlId": row.get("url_id"),
                        "visitId": row.get("visit_id"),
                        "latestVisitUtc": latest,
                    },
                )
            )

        embedded_chunks, embedded_count = self._embed_chunks(chunks)
        chunk_count = self.backend.add_chunks(document, embedded_chunks)
        graph_counts = self._index_chrome_graph(document, rows)
        self._add_case_graph(
            document,
            case_name=case_name,
            investigator_name=investigator_name,
        )
        self._register_case_document(document)
        logger.info(
            "Chrome History ingest finished: documentId={} rows={} chunks={} embedded={} "
            "entities={} relationships={}",
            document.id,
            len(rows),
            chunk_count,
            embedded_count,
            graph_counts["entities"],
            graph_counts["relationships"],
        )
        return {
            "chunks": chunk_count,
            "embeddedChunks": embedded_count,
            "entities": graph_counts["entities"],
            "relationships": graph_counts["relationships"],
        }

    def _copy_for_sqlite(self, path: Path) -> Path:
        temp_dir = self.backend.root / "tmp" if hasattr(self.backend, "root") else None
        if temp_dir is None:
            temp_dir = self.workspace / "knowledge" / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(suffix=path.suffix or ".sqlite", dir=temp_dir)
        os.close(fd)
        target = Path(name)
        try:
            with closing(sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)) as original:
                with closing(sqlite3.connect(target)) as copied:
                    original.backup(copied)
        except sqlite3.DatabaseError:
            shutil.copy2(path, target)
        return target

    def _register_case_document(self, document: DocumentRecord) -> None:
        CaseStore(self.workspace).register_document(
            document,
            self.backend.chunks_for_document(document.id),
            self.backend.graph_for_document(document.id),
        )

    @staticmethod
    def _chrome_time(value: Any) -> str | None:
        try:
            raw = int(value or 0)
        except (TypeError, ValueError):
            return None
        if raw <= 0:
            return None
        return (_CHROME_EPOCH + timedelta(microseconds=raw)).isoformat()

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _add_case_graph(
        self,
        document: DocumentRecord,
        *,
        case_name: str | None,
        investigator_name: str | None,
    ) -> None:
        source_id = self.backend.upsert_entity(
            kind="Source",
            value=document.source_path,
            metadata={"kind": document.kind, **document.metadata},
        )
        if case_name:
            case_id = self.backend.upsert_entity(kind="Case", value=case_name)
            self.backend.upsert_relationship(
                source_id=case_id,
                target_id=source_id,
                rel_type="HAS_SOURCE",
                document_id=document.id,
            )
        if investigator_name:
            investigator_id = self.backend.upsert_entity(
                kind="Investigator", value=investigator_name
            )
            self.backend.upsert_relationship(
                source_id=investigator_id,
                target_id=source_id,
                rel_type="INGESTED",
                document_id=document.id,
            )

    def _index_text_graph(self, document: DocumentRecord, chunks: Iterable[str]) -> dict[str, int]:
        source_id = self.backend.upsert_entity(
            kind="Source",
            value=document.source_path,
            metadata={"kind": document.kind, **document.metadata},
        )
        entity_count = 1
        rel_count = 0
        seen: set[tuple[str, str]] = set()
        for text in chunks:
            for kind, value in self._extract_entities(text):
                key = (kind, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                target_id = self.backend.upsert_entity(kind=kind, value=value)
                self.backend.upsert_relationship(
                    source_id=source_id,
                    target_id=target_id,
                    rel_type="MENTIONS",
                    document_id=document.id,
                )
                entity_count += 1
                rel_count += 1
        return {"entities": entity_count, "relationships": rel_count}

    def _index_chrome_graph(
        self, document: DocumentRecord, rows: list[dict[str, Any]]
    ) -> dict[str, int]:
        source_id = self.backend.upsert_entity(
            kind="Source",
            value=document.source_path,
            metadata={"kind": document.kind, **document.metadata},
        )
        entity_count = 1
        rel_count = 0
        for row in rows:
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            url_id = self.backend.upsert_entity(
                kind="URL",
                value=url,
                metadata={},
            )
            self.backend.upsert_relationship(
                source_id=source_id,
                target_id=url_id,
                rel_type="VISITED_URL",
                document_id=document.id,
            )
            entity_count += 1
            rel_count += 1
            domain = self._domain_from_url(url)
            if domain:
                domain_id = self.backend.upsert_entity(kind="Domain", value=domain)
                self.backend.upsert_relationship(
                    source_id=url_id,
                    target_id=domain_id,
                    rel_type="HAS_DOMAIN",
                    document_id=document.id,
                )
                entity_count += 1
                rel_count += 1
        return {"entities": entity_count, "relationships": rel_count}

    def _index_event_relationships(
        self, document: DocumentRecord, chunks: list[tuple[str, dict[str, Any]]]
    ) -> None:
        for _, metadata in chunks:
            values = metadata.get("eventValues", {})
            provider, event_id = values.get("Provider"), values.get("EventID")
            target_kind, target_value, rel_type = None, None, None
            if provider == "Microsoft-Windows-Sysmon":
                rule = {
                    "3": ("IP", "DestinationIp", "CONNECTED_TO"),
                    "11": ("FilePath", "TargetFilename", "CREATED_FILE"),
                    "13": ("RegistryKey", "TargetObject", "SET_REGISTRY_VALUE"),
                }.get(event_id)
                if rule:
                    target_kind, field, rel_type = rule
                    target_value = values.get(field)
            if not target_value or not values.get("Image"):
                continue
            process = values.get("ProcessGuid") or f"record:{metadata.get('recordId')}"
            process_id = self.backend.upsert_entity(
                kind="Process",
                value=f"{document.source_path}#{process}",
                metadata={"image": values["Image"]},
            )
            target_id = self.backend.upsert_entity(kind=target_kind, value=target_value)
            self.backend.upsert_relationship(
                source_id=process_id,
                target_id=target_id,
                rel_type=rel_type,
                document_id=document.id,
                metadata={
                    "basis": "recorded_event",
                    "recordId": metadata.get("recordId"),
                    "timestamp": metadata.get("eventTimestamp"),
                    "sourceId": document.metadata.get("sourceId"),
                },
            )

    @staticmethod
    def _extract_entities(text: str) -> Iterable[tuple[str, str]]:
        yielded: set[tuple[str, str]] = set()
        for kind, regex in (
            ("IP", _IP_RE),
            ("URL", _URL_RE),
            ("Domain", _DOMAIN_RE),
            ("FilePath", _WINDOWS_PATH_RE),
            ("RegistryKey", _REGISTRY_RE),
            ("Executable", _EXECUTABLE_RE),
        ):
            for value in regex.findall(text):
                clean = value.strip(".,;:)]}\"'")
                if kind == "Domain":
                    if clean.lower().startswith(("http.", "https.")) or _EXECUTABLE_RE.fullmatch(
                        clean
                    ):
                        continue
                key = (kind, clean.lower())
                if clean and key not in yielded:
                    yielded.add(key)
                    yield kind, clean

    @staticmethod
    def _domain_from_url(url: str) -> str | None:
        try:
            parsed = urlparse(url)
        except Exception:
            return None
        return parsed.netloc.lower() or None

    @staticmethod
    def result_to_text(result: KnowledgeIngestResult) -> str:
        """Format an ingest result for tool output."""
        if not result.ok:
            return "Knowledge ingest failed.\n" + "\n".join(f"- {error}" for error in result.errors)
        lines = [
            "Knowledge ingest ready."
            if result.ready
            else "Knowledge ingest finished with no indexed files.",
            f"- scannedFiles: {result.scanned_files}",
            f"- ingestedFiles: {result.ingested_files}",
            f"- skippedFiles: {result.skipped_files}",
            f"- chunks: {result.chunks}",
            f"- embeddedChunks: {result.embedded_chunks}",
            f"- graphEntities: {result.entities}",
            f"- graphRelationships: {result.relationships}",
        ]
        if result.vector:
            lines.append(f"- vector: {json.dumps(result.vector, ensure_ascii=False)}")
        if result.errors:
            lines.append("- errors:")
            lines.extend(f"  - {error}" for error in result.errors[:10])
        if result.ready:
            lines.append("Ready: ask questions now; use knowledge_search before answering.")
        return "\n".join(lines)
