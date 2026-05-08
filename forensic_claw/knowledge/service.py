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
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import chardet

from forensic_claw.knowledge.neo4j_sink import Neo4jSink
from forensic_claw.knowledge.store import DocumentRecord, KnowledgeStore

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
    errors: list[str] = field(default_factory=list)
    neo4j: dict[str, Any] = field(default_factory=dict)


class KnowledgeService:
    """Ingest local artifacts into a SQLite RAG index and Neo4j graph."""

    def __init__(self, workspace: Path, config: Any):
        self.workspace = workspace
        self.config = config
        self.enabled = bool(getattr(config, "enabled", True))
        self.store = KnowledgeStore(workspace, getattr(config, "store_dir", "knowledge"))
        self.neo4j = Neo4jSink(getattr(config, "neo4j", None))

    def status(self) -> dict[str, Any]:
        """Return local RAG and Neo4j readiness."""
        return {
            "enabled": self.enabled,
            "store": self.store.stats(),
            "neo4j": self.neo4j.status(),
        }

    def reconfigure(self, config: Any) -> None:
        """Apply updated knowledge settings to future ingest/search operations."""
        self.config = config
        self.enabled = bool(getattr(config, "enabled", True))
        self.store = KnowledgeStore(self.workspace, getattr(config, "store_dir", "knowledge"))
        self.neo4j = Neo4jSink(getattr(config, "neo4j", None))

    def ingest_path(
        self,
        path: str | Path,
        *,
        recursive: bool = True,
        file_globs: list[str] | None = None,
        max_files: int | None = None,
        case_name: str | None = None,
        investigator_name: str | None = None,
        sync_neo4j: bool = True,
    ) -> KnowledgeIngestResult:
        """Ingest a file or directory."""
        if not self.enabled:
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=["Knowledge RAG is disabled in config."],
                neo4j=self.neo4j.status(),
            )

        target = Path(path).expanduser()
        if not target.is_absolute():
            target = self.workspace / target
        target = target.resolve()
        if not target.exists():
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=[f"Path not found: {target}"],
                neo4j=self.neo4j.status(),
            )

        result = KnowledgeIngestResult(ok=True, ready=False)
        neo4j_totals = {"enabled": self.neo4j.enabled, "state": "not_synced", "entities": 0, "relationships": 0}

        for file_path in self._iter_files(target, recursive=recursive, file_globs=file_globs, max_files=max_files):
            result.scanned_files += 1
            try:
                one = self._ingest_file(
                    file_path,
                    case_name=case_name,
                    investigator_name=investigator_name,
                    sync_neo4j=sync_neo4j,
                )
                if one is None:
                    result.skipped_files += 1
                    continue
                result.ingested_files += 1
                result.chunks += int(one.get("chunks", 0))
                result.entities += int(one.get("entities", 0))
                result.relationships += int(one.get("relationships", 0))
                neo4j = one.get("neo4j") or {}
                if neo4j:
                    neo4j_totals["state"] = neo4j.get("state", neo4j_totals["state"])
                    neo4j_totals["entities"] += int(neo4j.get("entities", 0) or 0)
                    neo4j_totals["relationships"] += int(neo4j.get("relationships", 0) or 0)
            except Exception as exc:
                result.errors.append(f"{file_path}: {exc}")

        if not result.scanned_files:
            result.errors.append(f"No ingestible files found under: {target}")
        result.ready = result.ok and result.ingested_files > 0
        result.neo4j = neo4j_totals if sync_neo4j else {"enabled": self.neo4j.enabled, "state": "skipped"}
        return result

    def search(self, query: str, *, limit: int = 8, include_graph: bool = True) -> dict[str, Any]:
        """Retrieve RAG chunks and graph hints for a question."""
        hits = self.store.search(query, limit=limit)
        graph = self.store.graph_search(query, limit=limit) if include_graph else []
        return {
            "query": query,
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
        }

    def discover_chrome_history(self, *, max_files: int = 20) -> list[Path]:
        """Find Chrome History SQLite databases in likely local locations."""
        candidates: list[Path] = []
        seen: set[Path] = set()
        for root in self._chrome_history_roots():
            if not root.exists():
                continue
            for path in self._walk_history_files(root):
                resolved = path.resolve()
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
        investigator_name: str | None = None,
        max_files: int = 20,
        sync_neo4j: bool = True,
    ) -> KnowledgeIngestResult:
        """Discover Chrome History databases and ingest them."""
        paths = self.discover_chrome_history(max_files=max_files)
        if not paths:
            return KnowledgeIngestResult(
                ok=False,
                ready=False,
                errors=["No Chrome History database found in local Chrome profile paths or workspace."],
                neo4j=self.neo4j.status(),
            )

        result = KnowledgeIngestResult(ok=True, ready=False)
        neo4j_totals = {"enabled": self.neo4j.enabled, "state": "not_synced", "entities": 0, "relationships": 0}
        for path in paths:
            one = self.ingest_path(
                path,
                recursive=False,
                case_name=case_name,
                investigator_name=investigator_name,
                sync_neo4j=sync_neo4j,
            )
            result.scanned_files += one.scanned_files
            result.ingested_files += one.ingested_files
            result.skipped_files += one.skipped_files
            result.chunks += one.chunks
            result.entities += one.entities
            result.relationships += one.relationships
            result.errors.extend(one.errors)
            if one.neo4j:
                neo4j_totals["state"] = one.neo4j.get("state", neo4j_totals["state"])
                neo4j_totals["entities"] += int(one.neo4j.get("entities", 0) or 0)
                neo4j_totals["relationships"] += int(one.neo4j.get("relationships", 0) or 0)

        result.ready = result.ingested_files > 0
        result.ok = result.ready
        result.neo4j = neo4j_totals if sync_neo4j else {"enabled": self.neo4j.enabled, "state": "skipped"}
        return result

    def _chrome_history_roots(self) -> list[Path]:
        roots: list[Path] = []
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            roots.append(Path(local_app_data) / "Google" / "Chrome" / "User Data")
        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            roots.append(Path(user_profile) / "AppData" / "Local" / "Google" / "Chrome" / "User Data")
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
            walker = ((str(target), [], [item.name for item in target.iterdir() if item.is_file()]),)

        for root, dirnames, filenames in walker:
            dirnames[:] = [name for name in dirnames if name not in _SKIP_DIRS]
            for filename in sorted(filenames):
                if not any(fnmatch.fnmatch(filename, pattern) for pattern in patterns):
                    continue
                yield Path(root) / filename
                yielded += 1
                if max_files and yielded >= max_files:
                    return

    def _ingest_file(
        self,
        path: Path,
        *,
        case_name: str | None,
        investigator_name: str | None,
        sync_neo4j: bool,
    ) -> dict[str, Any] | None:
        size = path.stat().st_size
        max_size = int(getattr(self.config, "max_file_bytes", 256 * 1024 * 1024))
        if size > max_size:
            raise ValueError(f"file exceeds maxFileBytes ({size} > {max_size})")

        if self._is_chrome_history(path):
            return self._ingest_chrome_history(
                path,
                case_name=case_name,
                investigator_name=investigator_name,
                sync_neo4j=sync_neo4j,
            )

        text_chunks = list(self._text_chunks(path))
        if not text_chunks:
            return None

        document = self.store.replace_document(
            source_path=str(path),
            kind="text_log",
            sha256=self._sha256(path),
            size_bytes=size,
            mtime=path.stat().st_mtime,
            metadata={
                "caseName": case_name,
                "investigatorName": investigator_name,
                "filename": path.name,
            },
        )
        chunk_count = self.store.add_chunks(document, text_chunks)
        graph_counts = self._index_text_graph(
            document,
            (text for text, _metadata in text_chunks),
        )
        self._add_case_graph(
            document,
            case_name=case_name,
            investigator_name=investigator_name,
        )
        graph = self.store.graph_for_document(document.id)
        neo4j = self.neo4j.sync(graph) if sync_neo4j else {"enabled": self.neo4j.enabled, "state": "skipped"}
        return {
            "chunks": chunk_count,
            "entities": graph_counts["entities"],
            "relationships": graph_counts["relationships"],
            "neo4j": neo4j,
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
                    yield buffer, {"lineStart": line_start, "lineEnd": line_no, "encoding": encoding}
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
        if path.name.lower() not in {"history", "history.sqlite"} and path.suffix.lower() not in {".sqlite", ".sqlite3", ".db"}:
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
        sync_neo4j: bool,
    ) -> dict[str, Any]:
        max_rows = int(getattr(self.config, "max_chrome_rows", 10000))
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
                    urls.url AS url,
                    urls.title AS title,
                    urls.visit_count AS visit_count,
                    urls.last_visit_time AS last_visit_time,
                    MAX(visits.visit_time) AS latest_visit_time,
                    COUNT(visits.id) AS observed_visits
                FROM urls
                LEFT JOIN visits ON visits.url = urls.id
                GROUP BY urls.id, urls.url, urls.title, urls.visit_count, urls.last_visit_time
                ORDER BY COALESCE(MAX(visits.visit_time), urls.last_visit_time) DESC
                LIMIT ?
                """,
                (max_rows,),
            ):
                rows.append(dict(row))
        finally:
            if conn is not None:
                conn.close()
            temp.unlink(missing_ok=True)

        document = self.store.replace_document(
            source_path=str(path),
            kind="chrome_history",
            sha256=self._sha256(path),
            size_bytes=path.stat().st_size,
            mtime=path.stat().st_mtime,
            metadata={
                "caseName": case_name,
                "investigatorName": investigator_name,
                "filename": path.name,
                "rows": len(rows),
            },
        )
        chunks = []
        for index, row in enumerate(rows):
            latest = self._chrome_time(row.get("latest_visit_time") or row.get("last_visit_time"))
            text = "\n".join(
                [
                    f"Chrome History URL: {row.get('url') or ''}",
                    f"Title: {row.get('title') or ''}",
                    f"Visit Count: {row.get('visit_count') or 0}",
                    f"Observed Visits: {row.get('observed_visits') or 0}",
                    f"Latest Visit UTC: {latest or 'unknown'}",
                ]
            )
            chunks.append(
                (
                    text,
                    {
                        "rowIndex": index,
                        "urlId": row.get("url_id"),
                        "latestVisitUtc": latest,
                    },
                )
            )

        chunk_count = self.store.add_chunks(document, chunks)
        graph_counts = self._index_chrome_graph(document, rows)
        self._add_case_graph(
            document,
            case_name=case_name,
            investigator_name=investigator_name,
        )
        graph = self.store.graph_for_document(document.id)
        neo4j = self.neo4j.sync(graph) if sync_neo4j else {"enabled": self.neo4j.enabled, "state": "skipped"}
        return {
            "chunks": chunk_count,
            "entities": graph_counts["entities"],
            "relationships": graph_counts["relationships"],
            "neo4j": neo4j,
        }

    def _copy_for_sqlite(self, path: Path) -> Path:
        temp_dir = self.store.root / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(suffix=path.suffix or ".sqlite", dir=temp_dir)
        os.close(fd)
        target = Path(name)
        shutil.copy2(path, target)
        return target

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
        source_id = self.store.upsert_entity(
            kind="Source",
            value=document.source_path,
            metadata={"kind": document.kind, **document.metadata},
        )
        if case_name:
            case_id = self.store.upsert_entity(kind="Case", value=case_name)
            self.store.upsert_relationship(
                source_id=case_id,
                target_id=source_id,
                rel_type="HAS_SOURCE",
                document_id=document.id,
            )
        if investigator_name:
            investigator_id = self.store.upsert_entity(kind="Investigator", value=investigator_name)
            self.store.upsert_relationship(
                source_id=investigator_id,
                target_id=source_id,
                rel_type="INGESTED",
                document_id=document.id,
            )

    def _index_text_graph(self, document: DocumentRecord, chunks: Iterable[str]) -> dict[str, int]:
        source_id = self.store.upsert_entity(
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
                target_id = self.store.upsert_entity(kind=kind, value=value)
                self.store.upsert_relationship(
                    source_id=source_id,
                    target_id=target_id,
                    rel_type="MENTIONS",
                    document_id=document.id,
                )
                entity_count += 1
                rel_count += 1
        return {"entities": entity_count, "relationships": rel_count}

    def _index_chrome_graph(self, document: DocumentRecord, rows: list[dict[str, Any]]) -> dict[str, int]:
        source_id = self.store.upsert_entity(
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
            url_id = self.store.upsert_entity(
                kind="URL",
                value=url,
                metadata={
                    "title": row.get("title") or "",
                    "visitCount": row.get("visit_count") or 0,
                    "latestVisitUtc": self._chrome_time(row.get("latest_visit_time") or row.get("last_visit_time")),
                },
            )
            self.store.upsert_relationship(
                source_id=source_id,
                target_id=url_id,
                rel_type="VISITED_URL",
                document_id=document.id,
            )
            entity_count += 1
            rel_count += 1
            domain = self._domain_from_url(url)
            if domain:
                domain_id = self.store.upsert_entity(kind="Domain", value=domain)
                self.store.upsert_relationship(
                    source_id=url_id,
                    target_id=domain_id,
                    rel_type="HAS_DOMAIN",
                    document_id=document.id,
                )
                entity_count += 1
                rel_count += 1
        return {"entities": entity_count, "relationships": rel_count}

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
                if kind == "Domain" and clean.lower().startswith(("http.", "https.")):
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
            "Knowledge ingest ready." if result.ready else "Knowledge ingest finished with no indexed files.",
            f"- scannedFiles: {result.scanned_files}",
            f"- ingestedFiles: {result.ingested_files}",
            f"- skippedFiles: {result.skipped_files}",
            f"- chunks: {result.chunks}",
            f"- graphEntities: {result.entities}",
            f"- graphRelationships: {result.relationships}",
            f"- neo4j: {json.dumps(result.neo4j, ensure_ascii=False)}",
        ]
        if result.errors:
            lines.append("- errors:")
            lines.extend(f"  - {error}" for error in result.errors[:10])
        if result.ready:
            lines.append("Ready: ask questions now; use knowledge_search before answering.")
        return "\n".join(lines)
