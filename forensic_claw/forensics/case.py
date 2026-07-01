"""Case materialization and context assembly for the forensics domain layer.

A "case" lives on disk under ``<workspace>/forensics/cases/<case_id>/`` and holds:

- ``manifest.json`` — case metadata (read by the WebUI case explorer)
- ``evidence/<id>/metadata.json`` + ``evidence/<id>/files/`` — analyzed artifacts
- ``sources/<id>/metadata.json`` + ``sources/<id>/raw/`` — original sources
- ``graph.json`` — relationship graph snapshot (optional)
- ``report.md`` / ``report.docx`` — generated report (optional)

``CaseStore`` creates and updates cases; ``CaseStore.collect_context`` reads one
case back into a :class:`CaseContext` (including file integrity hashes) so the
report generator can work from a single structured object.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

from forensic_claw.session.scopes import normalize_scope_id
from forensic_claw.utils.hashing import (
    DEFAULT_HASH_ALGORITHMS,
    calculate_file_hashes,
)

CASE_SCHEMA_VERSION = 1
_MANIFEST_NAME = "manifest.json"
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


@dataclass
class SourceItem:
    """One original source folder under ``sources/``."""

    id: str
    metadata: dict[str, Any] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)


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
        for item in self.evidence:
            for relpath in item.files:
                digests = item.hashes.get(relpath, {})
                rows.append(
                    {
                        "evidenceId": item.id,
                        "file": relpath,
                        "sha256": digests.get("sha256", ""),
                        "md5": digests.get("md5", ""),
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
        return self.root / case_id

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
        """Create the case folder + manifest if missing, otherwise refresh it.

        Returns the current manifest. The derived ``caseId`` is stable for a
        given ``case_name`` so repeated chats route to the same case folder.
        """
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
        sources = [self._load_source(item_dir) for item_dir in _subdirs(case_dir / "sources")]
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
        files_root = item_dir / "files"
        files = _relative_files(files_root)

        hashes: dict[str, dict[str, str]] = {}
        existing = metadata.get("hashes") if isinstance(metadata, dict) else None
        if isinstance(existing, dict):
            # Trust hashes already recorded at acquisition time.
            for relpath, digests in existing.items():
                if isinstance(digests, dict):
                    hashes[str(relpath)] = {str(k): str(v) for k, v in digests.items()}

        if compute_hashes:
            algorithms = hash_algorithms or DEFAULT_HASH_ALGORITHMS
            for relpath in files:
                if relpath in hashes:
                    continue
                file_path = files_root / relpath
                try:
                    if max_hash_bytes is not None and file_path.stat().st_size > max_hash_bytes:
                        logger.debug("Skip hashing large evidence file: {}", file_path)
                        continue
                    hashes[relpath] = calculate_file_hashes(file_path, algorithms)
                except OSError as exc:
                    logger.warning("Failed to hash evidence file {}: {}", file_path, exc)

        return EvidenceItem(
            id=item_dir.name,
            metadata=metadata if isinstance(metadata, dict) else {},
            files=files,
            hashes=hashes,
        )

    def _load_source(self, item_dir: Path) -> SourceItem:
        metadata = _load_json(item_dir / "metadata.json")
        return SourceItem(
            id=item_dir.name,
            metadata=metadata if isinstance(metadata, dict) else {},
            files=_relative_files(item_dir / "raw"),
        )


def _utcnow_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


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
        if candidate.is_file()
    )
