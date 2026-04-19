"""Filesystem-backed forensic case store."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from forensic_claw.forensics.graph import empty_report_graph, read_report_graph, write_report_graph
from forensic_claw.forensics.ids import (
    next_case_id,
    next_evidence_id,
    next_source_id,
    next_timeline_id,
)
from forensic_claw.forensics.ingest import prepare_source_ingest
from forensic_claw.forensics.models import (
    CaseManifest,
    EvidenceMetadata,
    ReportGraph,
    SourceMetadata,
    TimelineEntry,
)
from forensic_claw.forensics.provenance import (
    ensure_sortable_timestamp,
    merge_report_graph,
    normalize_id_list,
)
from forensic_claw.forensics.timeline import append_timeline_entry, read_timeline_entries
from forensic_claw.utils.helpers import ensure_dir

FileContent = str | bytes


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _year_from_timestamp(timestamp: str | None) -> int:
    if not timestamp:
        return datetime.now().astimezone().year
    try:
        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).year
    except ValueError:
        return datetime.now().astimezone().year


class CaseStore:
    """Manage structured case storage under ``workspace/forensics/cases``."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)
        self.cases_root = ensure_dir(self.workspace / "forensics" / "cases")

    @staticmethod
    def _resolve_direct_child(root: Path, name: str) -> Path | None:
        candidate_path = Path(name)
        if candidate_path.is_absolute() or len(candidate_path.parts) != 1:
            return None
        if candidate_path.parts[0] in {"", ".", ".."}:
            return None

        root_resolved = root.resolve(strict=False)
        try:
            candidate = (root / candidate_path.parts[0]).resolve(strict=False)
            candidate.relative_to(root_resolved)
        except Exception:
            return None

        if candidate.parent != root_resolved:
            return None
        return candidate

    @staticmethod
    def _resolve_relative_path(root: Path, relative: str) -> Path | None:
        candidate_path = Path(relative)
        if candidate_path.is_absolute():
            return None
        if any(part in {"", ".", ".."} for part in candidate_path.parts):
            return None

        root_resolved = root.resolve(strict=False)
        try:
            candidate = (root / candidate_path).resolve(strict=False)
            candidate.relative_to(root_resolved)
        except Exception:
            return None
        return candidate

    @staticmethod
    def _read_json_file(path: Path) -> dict[str, Any] | None:
        if not path.exists() or not path.is_file():
            return None
        raw = path.read_text(encoding="utf-8")
        if not raw.strip():
            return None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def _list_relative_files(root: Path) -> list[str]:
        if not root.exists() or not root.is_dir():
            return []
        return sorted(
            candidate.relative_to(root).as_posix()
            for candidate in root.rglob("*")
            if candidate.is_file()
        )

    def _case_dir(self, case_id: str, *, must_exist: bool = True) -> Path:
        case_dir = self._resolve_direct_child(self.cases_root, case_id)
        if case_dir is None:
            raise FileNotFoundError(f"Invalid case id: {case_id}")
        if must_exist and not case_dir.is_dir():
            raise FileNotFoundError(f"Case not found: {case_id}")
        return case_dir

    def _entity_dir(self, case_id: str, collection: str, entity_id: str) -> Path:
        case_dir = self._case_dir(case_id)
        root = case_dir / collection
        entity_dir = self._resolve_direct_child(root, entity_id)
        if entity_dir is None or not entity_dir.is_dir():
            raise FileNotFoundError(f"{collection.rstrip('s').title()} not found: {entity_id}")
        return entity_dir

    def _entity_exists(self, case_id: str, collection: str, entity_id: str) -> bool:
        try:
            self._entity_dir(case_id, collection, entity_id)
        except FileNotFoundError:
            return False
        return True

    def _prepare_files(
        self, root: Path, files: dict[str, FileContent] | None
    ) -> list[tuple[Path, FileContent]]:
        if not files:
            return []

        prepared: list[tuple[Path, FileContent]] = []
        for relative, content in files.items():
            resolved = self._resolve_relative_path(root, relative)
            if resolved is None:
                raise ValueError(f"Invalid relative path: {relative}")
            prepared.append((resolved, content))
        return prepared

    @staticmethod
    def _write_prepared_files(prepared: list[tuple[Path, FileContent]]) -> None:
        for path, content in prepared:
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")

    def _validate_source_ids(
        self, case_id: str, source_ids: list[str], *, required: bool
    ) -> list[str]:
        normalized_source_ids = normalize_id_list(
            source_ids,
            field_name="source_ids",
            required=required,
        )
        missing_source_ids = [
            source_id
            for source_id in normalized_source_ids
            if not self._entity_exists(case_id, "sources", source_id)
        ]
        if missing_source_ids:
            raise ValueError(f"Unknown source ids: {', '.join(missing_source_ids)}")
        return normalized_source_ids

    def _validate_evidence_ids(
        self, case_id: str, evidence_ids: list[str] | None, *, required: bool = False
    ) -> list[str]:
        normalized_evidence_ids = normalize_id_list(
            evidence_ids,
            field_name="evidence_ids",
            required=required,
        )
        missing_evidence_ids = [
            evidence_id
            for evidence_id in normalized_evidence_ids
            if not self._entity_exists(case_id, "evidence", evidence_id)
        ]
        if missing_evidence_ids:
            raise ValueError(f"Unknown evidence ids: {', '.join(missing_evidence_ids)}")
        return normalized_evidence_ids

    def _validate_timeline_ids(self, case_id: str, timeline_ids: list[str] | None) -> list[str]:
        normalized_timeline_ids = normalize_id_list(timeline_ids, field_name="timeline_ids")
        existing_timeline_ids = {entry.id for entry in self.read_timeline(case_id)}
        missing_timeline_ids = [
            timeline_id
            for timeline_id in normalized_timeline_ids
            if timeline_id not in existing_timeline_ids
        ]
        if missing_timeline_ids:
            raise ValueError(f"Unknown timeline ids: {', '.join(missing_timeline_ids)}")
        return normalized_timeline_ids

    def _sync_case_outputs(
        self,
        case_id: str,
        *,
        source_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        timeline_dates: list[str] | None = None,
    ) -> None:
        from forensic_claw.forensics.report_builder import CaseReportBuilder
        from forensic_claw.forensics.wiki_writer import CaseWikiWriter

        writer = CaseWikiWriter(self.workspace)
        for source_id in source_ids or []:
            writer.sync_source_note(self, case_id, source_id)
        for evidence_id in evidence_ids or []:
            writer.sync_evidence_note(self, case_id, evidence_id)
        for date_key in timeline_dates or []:
            writer.sync_timeline_note(self, case_id, date_key)
        CaseReportBuilder(self.workspace).rebuild(self, case_id)

    def list_case_ids(self) -> list[str]:
        if not self.cases_root.exists():
            return []
        return sorted(child.name for child in self.cases_root.iterdir() if child.is_dir())

    def case_dir(self, case_id: str) -> Path:
        return self._case_dir(case_id)

    def create_case(
        self,
        *,
        title: str,
        case_id: str | None = None,
        status: str = "draft",
        created_at: str | None = None,
        updated_at: str | None = None,
        summary: str | None = None,
        tags: list[str] | None = None,
        primary_session_key: str | None = None,
        timezone: str | None = None,
    ) -> CaseManifest:
        created = created_at or _now_iso()
        updated = updated_at or created
        resolved_case_id = case_id or next_case_id(
            self.cases_root, year=_year_from_timestamp(created)
        )

        case_dir = self._case_dir(resolved_case_id, must_exist=False)
        if case_dir.exists():
            raise FileExistsError(f"Case already exists: {resolved_case_id}")

        ensure_dir(case_dir)
        ensure_dir(case_dir / "evidence")
        ensure_dir(case_dir / "sources")
        (case_dir / "timeline.jsonl").write_text("", encoding="utf-8")

        manifest = CaseManifest(
            id=resolved_case_id,
            title=title,
            status=status,
            created_at=created,
            updated_at=updated,
            summary=summary,
            tags=list(tags or []),
            primary_session_key=primary_session_key,
            timezone=timezone,
        )
        self.save_manifest(manifest)
        self.write_graph(manifest.id, empty_report_graph())
        self.write_report(manifest.id, "")
        return manifest

    def save_manifest(self, manifest: CaseManifest) -> None:
        case_dir = self._case_dir(manifest.id)
        self._write_json_file(case_dir / "manifest.json", manifest.to_dict())

    def load_manifest(self, case_id: str) -> CaseManifest:
        case_dir = self._case_dir(case_id)
        payload = self._read_json_file(case_dir / "manifest.json")
        if payload is None:
            raise FileNotFoundError(f"Manifest not found: {case_id}")
        return CaseManifest.from_dict(payload)

    def register_source(
        self,
        case_id: str,
        metadata: SourceMetadata,
        *,
        raw_files: dict[str, FileContent] | None = None,
    ) -> SourceMetadata:
        case_dir = self._case_dir(case_id)
        source_id = metadata.id or next_source_id(case_dir)
        sources_root = ensure_dir(case_dir / "sources")
        source_dir = self._resolve_direct_child(sources_root, source_id)
        if source_dir is None:
            raise ValueError(f"Invalid source id: {source_id}")
        if source_dir.exists():
            raise FileExistsError(f"Source already exists: {source_id}")

        prepared = self._prepare_files(source_dir / "raw", raw_files)
        ensure_dir(source_dir / "raw")
        stored = SourceMetadata(
            id=source_id,
            kind=metadata.kind,
            label=metadata.label,
            origin_path=metadata.origin_path,
            acquired_at=metadata.acquired_at,
            sha256=metadata.sha256,
            size=metadata.size,
            parser=metadata.parser,
            read_only=metadata.read_only,
            notes=metadata.notes,
            storage_policy=metadata.storage_policy,
        )
        self._write_json_file(source_dir / "metadata.json", stored.to_dict())
        self._write_prepared_files(prepared)
        return stored

    def add_source(
        self,
        case_id: str,
        *,
        kind: str,
        source_path: str | Path | None = None,
        content: FileContent | None = None,
        filename: str | None = None,
        label: str | None = None,
        origin_path: str | None = None,
        policy: str = "copy",
        acquired_at: str | None = None,
        parser: str | None = None,
        notes: str | None = None,
        read_only: bool = True,
        source_id: str | None = None,
    ) -> SourceMetadata:
        prepared = prepare_source_ingest(
            source_path=source_path,
            content=content,
            filename=filename,
            label=label,
            origin_path=origin_path,
            policy=policy,
        )
        stored = self.register_source(
            case_id,
            SourceMetadata(
                id=source_id,
                kind=kind,
                label=prepared.label,
                origin_path=prepared.origin_path,
                acquired_at=acquired_at,
                sha256=prepared.sha256,
                size=prepared.size,
                parser=parser,
                read_only=read_only,
                notes=notes,
                storage_policy=prepared.storage_policy,
            ),
            raw_files=prepared.raw_files or None,
        )
        self._sync_case_outputs(case_id, source_ids=[stored.id or ""])
        return stored

    def load_source(self, case_id: str, source_id: str) -> SourceMetadata:
        source_dir = self._entity_dir(case_id, "sources", source_id)
        payload = self._read_json_file(source_dir / "metadata.json")
        if payload is None:
            raise FileNotFoundError(f"Source metadata not found: {source_id}")
        return SourceMetadata.from_dict(payload)

    def list_source_files(self, case_id: str, source_id: str) -> list[str]:
        source_dir = self._entity_dir(case_id, "sources", source_id)
        return self._list_relative_files(source_dir / "raw")

    def get_source_file_paths(self, case_id: str, source_id: str) -> list[Path]:
        source_dir = self._entity_dir(case_id, "sources", source_id)
        raw_root = source_dir / "raw"
        if not raw_root.exists() or not raw_root.is_dir():
            return []
        return sorted(candidate for candidate in raw_root.rglob("*") if candidate.is_file())

    def list_source_ids(self, case_id: str) -> list[str]:
        case_dir = self._case_dir(case_id)
        sources_root = case_dir / "sources"
        if not sources_root.exists() or not sources_root.is_dir():
            return []
        return sorted(child.name for child in sources_root.iterdir() if child.is_dir())

    def register_evidence(
        self,
        case_id: str,
        metadata: EvidenceMetadata,
        *,
        files: dict[str, FileContent] | None = None,
    ) -> EvidenceMetadata:
        case_dir = self._case_dir(case_id)
        evidence_id = metadata.id or next_evidence_id(case_dir)
        evidence_root = ensure_dir(case_dir / "evidence")
        evidence_dir = self._resolve_direct_child(evidence_root, evidence_id)
        if evidence_dir is None:
            raise ValueError(f"Invalid evidence id: {evidence_id}")
        if evidence_dir.exists():
            raise FileExistsError(f"Evidence already exists: {evidence_id}")

        prepared = self._prepare_files(evidence_dir / "files", files)
        ensure_dir(evidence_dir / "files")
        stored = EvidenceMetadata(
            id=evidence_id,
            artifact_type=metadata.artifact_type,
            title=metadata.title,
            summary=metadata.summary,
            derived_from_source_ids=list(metadata.derived_from_source_ids),
            produced_by=metadata.produced_by,
            observed_at=metadata.observed_at,
            confidence=metadata.confidence,
            tags=list(metadata.tags),
        )
        self._write_json_file(evidence_dir / "metadata.json", stored.to_dict())
        self._write_prepared_files(prepared)
        return stored

    def add_evidence(
        self,
        case_id: str,
        *,
        artifact_type: str,
        title: str,
        source_ids: list[str],
        summary: str | None = None,
        produced_by: str | None = None,
        observed_at: str | None = None,
        confidence: float | None = None,
        tags: list[str] | None = None,
        files: dict[str, FileContent] | None = None,
        evidence_id: str | None = None,
    ) -> EvidenceMetadata:
        normalized_source_ids = self._validate_source_ids(case_id, source_ids, required=True)
        evidence = self.register_evidence(
            case_id,
            EvidenceMetadata(
                id=evidence_id,
                artifact_type=artifact_type,
                title=title,
                summary=summary,
                derived_from_source_ids=normalized_source_ids,
                produced_by=produced_by,
                observed_at=observed_at,
                confidence=confidence,
                tags=list(tags or []),
            ),
            files=files,
        )
        self.update_report_graph(
            case_id,
            evidence_ids=[evidence.id or ""],
            source_ids=normalized_source_ids,
        )
        return evidence

    def load_evidence(self, case_id: str, evidence_id: str) -> EvidenceMetadata:
        evidence_dir = self._entity_dir(case_id, "evidence", evidence_id)
        payload = self._read_json_file(evidence_dir / "metadata.json")
        if payload is None:
            raise FileNotFoundError(f"Evidence metadata not found: {evidence_id}")
        return EvidenceMetadata.from_dict(payload)

    def list_evidence_files(self, case_id: str, evidence_id: str) -> list[str]:
        evidence_dir = self._entity_dir(case_id, "evidence", evidence_id)
        return self._list_relative_files(evidence_dir / "files")

    def list_evidence_ids(self, case_id: str) -> list[str]:
        case_dir = self._case_dir(case_id)
        evidence_root = case_dir / "evidence"
        if not evidence_root.exists() or not evidence_root.is_dir():
            return []
        return sorted(child.name for child in evidence_root.iterdir() if child.is_dir())

    def append_timeline(self, case_id: str, entry: TimelineEntry) -> TimelineEntry:
        case_dir = self._case_dir(case_id)
        timeline_path = case_dir / "timeline.jsonl"
        ensure_sortable_timestamp(entry.timestamp)
        stored = TimelineEntry(
            id=entry.id or next_timeline_id(timeline_path),
            timestamp=entry.timestamp,
            timezone=entry.timezone,
            title=entry.title,
            description=entry.description,
            evidence_ids=list(entry.evidence_ids),
            source_ids=list(entry.source_ids),
            kind=entry.kind,
        )
        append_timeline_entry(timeline_path, stored)
        return stored

    def add_timeline_entry(
        self,
        case_id: str,
        *,
        timestamp: str,
        title: str,
        timezone: str | None = None,
        description: str | None = None,
        evidence_ids: list[str] | None = None,
        source_ids: list[str] | None = None,
        kind: str | None = None,
        entry_id: str | None = None,
    ) -> TimelineEntry:
        normalized_evidence_ids = self._validate_evidence_ids(case_id, evidence_ids)
        normalized_source_ids = self._validate_source_ids(case_id, source_ids or [], required=False)
        if not normalized_evidence_ids and not normalized_source_ids:
            raise ValueError("timeline entry must reference at least one evidence id or source id")

        entry = self.append_timeline(
            case_id,
            TimelineEntry(
                id=entry_id,
                timestamp=ensure_sortable_timestamp(timestamp),
                timezone=timezone,
                title=title,
                description=description,
                evidence_ids=normalized_evidence_ids,
                source_ids=normalized_source_ids,
                kind=kind,
            ),
        )
        self.update_report_graph(
            case_id,
            evidence_ids=normalized_evidence_ids,
            source_ids=normalized_source_ids,
            timeline_ids=[entry.id or ""],
        )
        return entry

    def read_timeline(self, case_id: str) -> list[TimelineEntry]:
        case_dir = self._case_dir(case_id)
        return read_timeline_entries(case_dir / "timeline.jsonl")

    def read_graph(self, case_id: str) -> ReportGraph:
        case_dir = self._case_dir(case_id)
        return read_report_graph(case_dir / "graph.json")

    def write_graph(self, case_id: str, graph: ReportGraph) -> None:
        case_dir = self._case_dir(case_id)
        write_report_graph(case_dir / "graph.json", graph)

    def update_report_graph(
        self,
        case_id: str,
        *,
        report_section_id: str | None = None,
        report_section_title: str | None = None,
        evidence_ids: list[str] | None = None,
        source_ids: list[str] | None = None,
        timeline_ids: list[str] | None = None,
    ) -> ReportGraph:
        normalized_evidence_ids = self._validate_evidence_ids(case_id, evidence_ids)
        normalized_source_ids = self._validate_source_ids(case_id, source_ids or [], required=False)
        normalized_timeline_ids = self._validate_timeline_ids(case_id, timeline_ids)

        graph = merge_report_graph(
            self.read_graph(case_id),
            report_section_id=report_section_id,
            report_section_title=report_section_title,
            evidence_ids=normalized_evidence_ids,
            source_ids=normalized_source_ids,
            timeline_ids=normalized_timeline_ids,
        )
        self.write_graph(case_id, graph)
        timeline_dates = []
        if normalized_timeline_ids:
            timeline_index = {entry.id: entry for entry in self.read_timeline(case_id) if entry.id}
            timeline_dates = sorted(
                {
                    datetime.fromisoformat(
                        timeline_index[timeline_id].timestamp.replace("Z", "+00:00")
                    ).date().isoformat()
                    for timeline_id in normalized_timeline_ids
                    if timeline_id in timeline_index
                }
            )
        self._sync_case_outputs(
            case_id,
            source_ids=normalized_source_ids,
            evidence_ids=normalized_evidence_ids,
            timeline_dates=timeline_dates,
        )
        return graph

    def read_report(self, case_id: str) -> str:
        case_dir = self._case_dir(case_id)
        report_path = case_dir / "report.md"
        if not report_path.exists() or not report_path.is_file():
            return ""
        return report_path.read_text(encoding="utf-8")

    def read_report_draft(self, case_id: str) -> str:
        case_dir = self._case_dir(case_id)
        report_path = case_dir / "report-draft.md"
        if not report_path.exists() or not report_path.is_file():
            return ""
        return report_path.read_text(encoding="utf-8")

    def write_report(self, case_id: str, content: str) -> None:
        case_dir = self._case_dir(case_id)
        (case_dir / "report.md").write_text(content, encoding="utf-8")

    def write_report_draft(self, case_id: str, content: str) -> None:
        case_dir = self._case_dir(case_id)
        (case_dir / "report-draft.md").write_text(content, encoding="utf-8")
