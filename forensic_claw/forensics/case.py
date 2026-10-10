"""Case materialization and context assembly for the forensics domain layer.

A "case" lives on disk under ``<workspace>/forensics/cases/<case_id>/`` and holds:

- ``manifest.json`` — case metadata (read by the WebUI case explorer)
- ``evidence/<id>/metadata.json`` + ``evidence/<id>/files/`` — analyzed artifacts
- ``sources/<id>/metadata.json`` + ``sources/<id>/raw/`` — original sources
- ``graph.json`` — relationship graph snapshot (optional)
- ``report.md`` / ``report.html`` / ``report.pdf`` / ``report.json`` — checked report

``CaseStore`` creates and updates cases; ``CaseStore.collect_context`` reads one
case back into a :class:`CaseContext` (including file integrity hashes) so the
report generator can work from a single structured object.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Any

from loguru import logger

from forensic_claw.session.scopes import normalize_scope_id
from forensic_claw.utils.hashing import (
    DEFAULT_HASH_ALGORITHMS,
    calculate_file_hashes,
    verify_hashes,
)

CASE_SCHEMA_VERSION = 1
_MANIFEST_NAME = "manifest.json"
_CASE_LOCK = RLock()
# Skip integrity hashing for very large evidence files by default so that
# materializing a case never blocks the chat request for minutes. The report
# generator can force a full pass later.
_DEFAULT_MAX_HASH_BYTES = 512 * 1024 * 1024


def derive_case_id(case_name: str) -> str:
    """Derive a stable, filesystem-safe case id from a free-form case name."""
    case_id = normalize_scope_id(case_name)
    if not case_id:
        raise ValueError(f"case_name produced an empty case id: {case_name!r}")
    return case_id


@dataclass
class EvidenceItem:
    """One analyzed artifact folder under ``evidence/``."""

    id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    # relative file path -> {algorithm: hex digest}
    hashes: dict[str, dict[str, str]] = field(default_factory=dict)
    verification: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class SourceItem:
    """One original source folder under ``sources/``."""

    id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)
    hashes: dict[str, dict[str, str]] = field(default_factory=dict)
    verification: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class CaseContext:
    """Everything the report generator needs for one case, read from disk."""

    case_id: str
    root: Path
    manifest: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceItem] = field(default_factory=list)
    sources: list[SourceItem] = field(default_factory=list)
    graph: dict[str, Any] | None = None

    @property
    def case_name(self) -> str:
        return str(self.manifest.get("caseName") or self.manifest.get("title") or self.case_id)

    @property
    def investigator_name(self) -> str | None:
        return self.manifest.get("investigatorName")

    def integrity_rows(self) -> list[dict[str, Any]]:
        """Flatten evidence files into rows for the report integrity table."""
        rows: list[dict[str, Any]] = []
        for item in [*self.sources, *self.evidence]:
            for relpath in item.files:
                digests = item.hashes.get(relpath, {})
                rows.append(
                    {
                        "evidenceId": item.id,
                        "file": relpath,
                        "sha256": digests.get("sha256", ""),
                        "md5": digests.get("md5", ""),
                        "status": "PARTIAL"
                        if item.verification.get(relpath, {}).get("ok") is True
                        else "UNVERIFIED",
                    }
                )
        return rows


class CaseStore:
    """Create, update, and read cases on the local filesystem."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)

    @property
    def root(self) -> Path:
        return self.workspace / "forensics" / "cases"

    def case_dir(self, case_id: str) -> Path:
        normalized = normalize_scope_id(case_id)
        if not normalized:
            raise ValueError("Invalid case id")
        target = self.root / normalized
        target.resolve().relative_to(self.root.resolve())
        return target

    def acquire_source(
        self,
        path: Path,
        *,
        case_name: str,
        investigator_name: str | None = None,
        case_id: str | None = None,
    ) -> tuple[Path, dict[str, Any]]:
        with _CASE_LOCK:
            manifest = self.ensure_case(
                case_name=case_name, investigator_name=investigator_name, case_id=case_id
            )
            hashes = calculate_file_hashes(path)
            wal = path.with_name(path.name + "-wal")
            wal_hashes = calculate_file_hashes(wal) if wal.is_file() else None
            identity = str(path.resolve()) + hashes["sha256"] + (wal_hashes or {}).get("sha256", "")
            source_id = "SRC-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
            root = self.case_dir(manifest["caseId"]) / "sources" / source_id
            raw = root / "raw" / path.name
            if not raw.is_file():
                raw.parent.mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(dir=raw.parent)
                os.close(fd)
                try:
                    shutil.copy2(path, temporary)
                    if (
                        calculate_file_hashes(Path(temporary)) != hashes
                        or calculate_file_hashes(path) != hashes
                    ):
                        raise ValueError("Source changed during acquisition")
                    if wal_hashes:
                        preserved_wal = raw.with_name(raw.name + "-wal")
                        shutil.copy2(wal, preserved_wal)
                        if (
                            calculate_file_hashes(preserved_wal) != wal_hashes
                            or calculate_file_hashes(wal) != wal_hashes
                        ):
                            raise ValueError("SQLite WAL changed during acquisition")
                    os.replace(temporary, raw)
                finally:
                    Path(temporary).unlink(missing_ok=True)
            elif calculate_file_hashes(raw) != hashes:
                raise ValueError("Preserved source failed integrity verification")
            if wal_hashes and calculate_file_hashes(raw.with_name(raw.name + "-wal")) != wal_hashes:
                raise ValueError("Preserved WAL failed integrity verification")
            metadata_path = root / "metadata.json"
            metadata = _load_json(metadata_path) or {
                "sourceId": source_id,
                "caseId": manifest["caseId"],
                "caseName": case_name,
                "originalPath": str(path.resolve()),
                "timestamp": _utcnow_iso(),
                "timestampKind": "acquired_at",
                "hashes": {path.name: hashes},
            }
            if wal_hashes:
                metadata["hashes"][wal.name] = wal_hashes
            _write_json(metadata_path, metadata)
            return raw, metadata

    def register_document(self, document: Any, chunks: list[Any], graph: dict[str, Any]) -> None:
        with _CASE_LOCK:
            metadata = document.metadata
            case_id, source_id = metadata.get("caseId"), metadata.get("sourceId")
            if not case_id or not source_id:
                return
            case_dir = self.case_dir(case_id)
            source_root = case_dir / "sources" / source_id
            if not (source_root / "metadata.json").is_file():
                raise ValueError("Evidence must reference an acquired source")
            evidence_id = "EVD-" + source_id.removeprefix("SRC-")
            item_dir = case_dir / "evidence" / evidence_id
            artifact = item_dir / "files" / "observations.json"
            _write_json(
                artifact,
                {
                    "kind": document.kind,
                    "sourceId": source_id,
                    "chunks": [
                        {"id": chunk.id, "text": chunk.text, "metadata": chunk.metadata}
                        for chunk in chunks
                    ],
                },
            )
            _write_json(
                item_dir / "metadata.json",
                {
                    "evidenceId": evidence_id,
                    "sourceIds": [source_id],
                    "kind": document.kind,
                    "sourcePath": document.source_path,
                    "grade": "PARTIAL",
                    "hashes": {artifact.name: calculate_file_hashes(artifact)},
                    "timestamp": metadata["timestamp"],
                    "timestampKind": metadata["timestampKind"],
                },
            )
            snapshot = _load_json(case_dir / "graph.json") or {"nodes": [], "edges": []}
            nodes = {node["id"]: node for node in snapshot.get("nodes", [])}
            edges = {
                edge["id"]: edge
                for edge in snapshot.get("edges", [])
                if edge.get("metadata", {}).get("evidenceId") != evidence_id
            }
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
                    "metadata": {
                        **edge["metadata"],
                        "sourceId": source_id,
                        "evidenceId": evidence_id,
                    },
                }
            _write_json(
                case_dir / "graph.json",
                {"nodes": list(nodes.values()), "edges": list(edges.values())},
            )
            timeline_path = case_dir / "timeline.jsonl"
            existing = (
                [
                    json.loads(line)
                    for line in timeline_path.read_text(encoding="utf-8").splitlines()
                ]
                if timeline_path.is_file()
                else []
            )
            existing = [entry for entry in existing if entry.get("evidenceId") != evidence_id]
            for chunk in chunks:
                timestamp = chunk.metadata.get("latestVisitUtc") or chunk.metadata.get(
                    "eventTimestamp"
                )
                kind = "event_time"
                if (
                    not timestamp
                    and chunk.metadata.get("timestampKind") == "registry_key_last_written"
                ):
                    timestamp, kind = chunk.metadata.get("timestamp"), "registry_key_last_written"
                if timestamp:
                    existing.append(
                        {
                            "timestamp": timestamp,
                            "timestampKind": kind,
                            "title": chunk.text[:200],
                            "sourceId": source_id,
                            "evidenceId": evidence_id,
                            "chunkId": chunk.id,
                        }
                    )
            _write_text(
                timeline_path,
                "".join(
                    json.dumps(entry, ensure_ascii=False) + "\n"
                    for entry in sorted(existing, key=lambda e: e["timestamp"])
                ),
            )
            note = [
                "# 사건 증거",
                "",
                "등급은 출처 검증 상태이며 법적 증거 능력 판정이 아닙니다.",
                "",
            ]
            for item in _subdirs(case_dir / "evidence"):
                data = _load_json(item / "metadata.json") or {}
                note.append(
                    f"- [{item.name}](../evidence/{item.name}/metadata.json): {data.get('sourcePath', '')}"
                )
            _write_text(case_dir / "wiki" / "evidence.md", "\n".join(note) + "\n")

    def exists(self, case_id: str) -> bool:
        return (self.case_dir(case_id) / _MANIFEST_NAME).is_file()

    def ensure_case(
        self,
        *,
        case_name: str,
        investigator_name: str | None = None,
        case_id: str | None = None,
        title: str | None = None,
        summary: str | None = None,
    ) -> dict[str, Any]:
        """Create the case manifest or refresh its investigator metadata."""
        with _CASE_LOCK:
            resolved_id = normalize_scope_id(case_id) if case_id else None
            resolved_id = resolved_id or derive_case_id(case_name)
            case_dir = self.case_dir(resolved_id)
            (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
            (case_dir / "sources").mkdir(parents=True, exist_ok=True)

            manifest_path = case_dir / _MANIFEST_NAME
            now = _utcnow_iso()

            if manifest_path.is_file():
                manifest = _load_json(manifest_path) or {}
                changed = False
                if investigator_name and manifest.get("investigatorName") != investigator_name:
                    manifest["investigatorName"] = investigator_name
                    changed = True
                if case_name and not manifest.get("caseName"):
                    manifest["caseName"] = case_name
                    changed = True
                if changed:
                    manifest["updatedAt"] = now
                    _write_json(manifest_path, manifest)
                return manifest

            manifest = {
                "schemaVersion": CASE_SCHEMA_VERSION,
                "caseId": resolved_id,
                "caseName": case_name,
                "title": title or case_name,
                "investigatorName": investigator_name,
                "status": "open",
                "summary": summary or "",
                "tags": [],
                "createdAt": now,
                "updatedAt": now,
            }
            _write_json(manifest_path, manifest)
            logger.info("Case materialized: id={} name={}", resolved_id, case_name)
            return manifest

    def collect_context(
        self,
        case_id: str,
        *,
        compute_hashes: bool = True,
        hash_algorithms: tuple[str, ...] | None = None,
        max_hash_bytes: int | None = _DEFAULT_MAX_HASH_BYTES,
    ) -> CaseContext | None:
        """Read one case back into a :class:`CaseContext`, or None if missing."""
        case_dir = self.case_dir(case_id)
        if not case_dir.is_dir():
            return None

        manifest = _load_json(case_dir / _MANIFEST_NAME) or {}
        evidence = [
            self._load_evidence(
                item_dir,
                compute_hashes=compute_hashes,
                hash_algorithms=hash_algorithms,
                max_hash_bytes=max_hash_bytes,
            )
            for item_dir in _subdirs(case_dir / "evidence")
        ]
        sources = [
            self._load_source(item_dir, compute_hashes=compute_hashes)
            for item_dir in _subdirs(case_dir / "sources")
        ]
        graph = _load_json(case_dir / "graph.json")
        return CaseContext(
            case_id=case_id,
            root=case_dir,
            manifest=manifest,
            evidence=evidence,
            sources=sources,
            graph=graph if isinstance(graph, dict) else None,
        )

    def _load_evidence(
        self,
        item_dir: Path,
        *,
        compute_hashes: bool,
        hash_algorithms: tuple[str, ...] | None,
        max_hash_bytes: int | None,
    ) -> EvidenceItem:
        metadata = _load_json(item_dir / "metadata.json")
        metadata = metadata if isinstance(metadata, dict) else {}
        recorded = metadata.get("hashes")
        recorded = recorded if isinstance(recorded, dict) else {}
        files_root = item_dir / "files"
        files = _relative_files(files_root)
        files = sorted(
            set(files)
            | {
                name
                for name in recorded
                if (files_root / name).resolve().is_relative_to(files_root.resolve())
            }
        )

        hashes: dict[str, dict[str, str]] = {}
        verification: dict[str, dict[str, Any]] = {}
        existing = metadata.get("hashes") if isinstance(metadata, dict) else None
        if isinstance(existing, dict):
            # Preserve acquisition values only until current bytes can be checked.
            for relpath, digests in existing.items():
                if isinstance(digests, dict):
                    hashes[str(relpath)] = {str(k): str(v) for k, v in digests.items()}

        if compute_hashes:
            algorithms = hash_algorithms or DEFAULT_HASH_ALGORITHMS
            for relpath in files:
                file_path = files_root / relpath
                try:
                    if max_hash_bytes is not None and file_path.stat().st_size > max_hash_bytes:
                        logger.debug("Skip hashing large evidence file: {}", file_path)
                        continue
                    expected = hashes.get(relpath)
                    selected = tuple(dict.fromkeys((*algorithms, *(expected or {}))))
                    hashes[relpath] = calculate_file_hashes(file_path, selected)
                    verification[relpath] = verify_hashes(hashes[relpath], expected)
                except (OSError, ValueError) as exc:
                    logger.warning("Failed to hash evidence file {}: {}", file_path, exc)
                    verification[relpath] = {"ok": False, "error": str(exc)}
                    hashes.pop(relpath, None)

        return EvidenceItem(
            id=item_dir.name,
            metadata={
                **(metadata if isinstance(metadata, dict) else {}),
                "grade": "PARTIAL"
                if files and all(verification.get(name, {}).get("ok") is True for name in files)
                else "UNVERIFIED",
            },
            files=files,
            hashes=hashes,
            verification=verification,
        )

    def _load_source(self, item_dir: Path, *, compute_hashes: bool = True) -> SourceItem:
        metadata = _load_json(item_dir / "metadata.json")
        metadata = metadata if isinstance(metadata, dict) else {}
        recorded = metadata.get("hashes")
        recorded = recorded if isinstance(recorded, dict) else {}
        files = _relative_files(item_dir / "raw")
        files = sorted(
            set(files)
            | {
                name
                for name in recorded
                if (item_dir / "raw" / name).resolve().is_relative_to((item_dir / "raw").resolve())
            }
        )
        hashes, verification = {}, {}
        for name in files:
            if not compute_hashes:
                continue
            try:
                hashes[name] = calculate_file_hashes(item_dir / "raw" / name)
                expected = recorded.get(name)
                expected = expected if isinstance(expected, dict) else None
                verification[name] = verify_hashes(hashes[name], expected)
            except OSError as exc:
                verification[name] = {"ok": False, "error": str(exc)}
        return SourceItem(
            id=item_dir.name,
            metadata={
                **metadata,
                "grade": "PARTIAL"
                if files and all(verification.get(name, {}).get("ok") is True for name in files)
                else "UNVERIFIED",
            },
            files=files,
            hashes=hashes,
            verification=verification,
        )


def _utcnow_iso() -> str:
    return datetime.now(UTC).isoformat()


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    _write_text(path, json.dumps(payload, ensure_ascii=False, indent=2))


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _subdirs(path: Path) -> list[Path]:
    if not path.is_dir():
        return []
    return sorted((item for item in path.iterdir() if item.is_dir()), key=lambda p: p.name)


def _relative_files(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    return sorted(
        candidate.relative_to(root).as_posix()
        for candidate in root.rglob("*")
        if candidate.is_file() and candidate.resolve().is_relative_to(root.resolve())
    )
