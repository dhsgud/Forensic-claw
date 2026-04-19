"""Core forensic domain models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


def _get_value(data: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return default


def _normalize_str_list(value: Any, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"{field_name} must be a list")
    return [str(item) for item in value]


def _normalize_mapping_list(value: Any, *, field_name: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"{field_name} must be a list")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise TypeError(f"{field_name} entries must be mappings")
        normalized.append(dict(item))
    return normalized


def _compact_dict(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value is not None}


@dataclass
class CaseManifest:
    id: str
    title: str
    status: str = "draft"
    created_at: str | None = None
    updated_at: str | None = None
    summary: str | None = None
    tags: list[str] = field(default_factory=list)
    primary_session_key: str | None = None
    timezone: str | None = None

    def __post_init__(self) -> None:
        if not self.id or not self.id.strip():
            raise ValueError("CaseManifest.id is required")
        if not self.title or not self.title.strip():
            raise ValueError("CaseManifest.title is required")
        self.tags = _normalize_str_list(self.tags, field_name="tags")

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "id": self.id,
                "title": self.title,
                "status": self.status,
                "createdAt": self.created_at,
                "updatedAt": self.updated_at,
                "summary": self.summary,
                "tags": list(self.tags),
                "primarySessionKey": self.primary_session_key,
                "timezone": self.timezone,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "CaseManifest":
        return cls(
            id=str(_get_value(data, "id", default="")),
            title=str(_get_value(data, "title", default="")),
            status=str(_get_value(data, "status", default="draft")),
            created_at=_get_value(data, "created_at", "createdAt"),
            updated_at=_get_value(data, "updated_at", "updatedAt"),
            summary=_get_value(data, "summary"),
            tags=_normalize_str_list(_get_value(data, "tags"), field_name="tags"),
            primary_session_key=_get_value(data, "primary_session_key", "primarySessionKey"),
            timezone=_get_value(data, "timezone"),
        )


@dataclass
class SourceMetadata:
    kind: str
    label: str
    id: str | None = None
    origin_path: str | None = None
    acquired_at: str | None = None
    sha256: str | None = None
    size: int | None = None
    parser: str | None = None
    read_only: bool = True
    notes: str | None = None
    storage_policy: str = "copy"

    def __post_init__(self) -> None:
        if self.id is not None and not self.id.strip():
            raise ValueError("SourceMetadata.id must not be blank")
        if not self.kind or not self.kind.strip():
            raise ValueError("SourceMetadata.kind is required")
        if not self.label or not self.label.strip():
            raise ValueError("SourceMetadata.label is required")
        if self.size is not None:
            self.size = int(self.size)
            if self.size < 0:
                raise ValueError("SourceMetadata.size must be >= 0")
        self.read_only = bool(self.read_only)
        if self.storage_policy not in {"copy", "reference"}:
            raise ValueError("SourceMetadata.storage_policy must be 'copy' or 'reference'")

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "id": self.id,
                "kind": self.kind,
                "label": self.label,
                "originPath": self.origin_path,
                "acquiredAt": self.acquired_at,
                "sha256": self.sha256,
                "size": self.size,
                "parser": self.parser,
                "readOnly": self.read_only,
                "notes": self.notes,
                "storagePolicy": self.storage_policy,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SourceMetadata":
        return cls(
            id=_get_value(data, "id"),
            kind=str(_get_value(data, "kind", default="")),
            label=str(_get_value(data, "label", default="")),
            origin_path=_get_value(data, "origin_path", "originPath"),
            acquired_at=_get_value(data, "acquired_at", "acquiredAt"),
            sha256=_get_value(data, "sha256"),
            size=_get_value(data, "size"),
            parser=_get_value(data, "parser"),
            read_only=bool(_get_value(data, "read_only", "readOnly", default=True)),
            notes=_get_value(data, "notes"),
            storage_policy=str(_get_value(data, "storage_policy", "storagePolicy", default="copy")),
        )


@dataclass
class EvidenceMetadata:
    artifact_type: str
    title: str
    id: str | None = None
    summary: str | None = None
    derived_from_source_ids: list[str] = field(default_factory=list)
    produced_by: str | None = None
    observed_at: str | None = None
    confidence: float | None = None
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.id is not None and not self.id.strip():
            raise ValueError("EvidenceMetadata.id must not be blank")
        if not self.artifact_type or not self.artifact_type.strip():
            raise ValueError("EvidenceMetadata.artifact_type is required")
        if not self.title or not self.title.strip():
            raise ValueError("EvidenceMetadata.title is required")
        self.derived_from_source_ids = _normalize_str_list(
            self.derived_from_source_ids,
            field_name="derived_from_source_ids",
        )
        self.tags = _normalize_str_list(self.tags, field_name="tags")
        if self.confidence is not None:
            self.confidence = float(self.confidence)
            if self.confidence < 0 or self.confidence > 1:
                raise ValueError("EvidenceMetadata.confidence must be between 0 and 1")

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "id": self.id,
                "artifactType": self.artifact_type,
                "title": self.title,
                "summary": self.summary,
                "derivedFromSourceIds": list(self.derived_from_source_ids),
                "producedBy": self.produced_by,
                "observedAt": self.observed_at,
                "confidence": self.confidence,
                "tags": list(self.tags),
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EvidenceMetadata":
        return cls(
            id=_get_value(data, "id"),
            artifact_type=str(_get_value(data, "artifact_type", "artifactType", default="")),
            title=str(_get_value(data, "title", default="")),
            summary=_get_value(data, "summary"),
            derived_from_source_ids=_normalize_str_list(
                _get_value(data, "derived_from_source_ids", "derivedFromSourceIds"),
                field_name="derived_from_source_ids",
            ),
            produced_by=_get_value(data, "produced_by", "producedBy"),
            observed_at=_get_value(data, "observed_at", "observedAt"),
            confidence=_get_value(data, "confidence"),
            tags=_normalize_str_list(_get_value(data, "tags"), field_name="tags"),
        )


@dataclass
class TimelineEntry:
    timestamp: str
    title: str
    id: str | None = None
    timezone: str | None = None
    description: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    kind: str | None = None

    def __post_init__(self) -> None:
        if self.id is not None and not self.id.strip():
            raise ValueError("TimelineEntry.id must not be blank")
        if not self.timestamp or not self.timestamp.strip():
            raise ValueError("TimelineEntry.timestamp is required")
        if not self.title or not self.title.strip():
            raise ValueError("TimelineEntry.title is required")
        self.evidence_ids = _normalize_str_list(self.evidence_ids, field_name="evidence_ids")
        self.source_ids = _normalize_str_list(self.source_ids, field_name="source_ids")

    def to_dict(self) -> dict[str, Any]:
        return _compact_dict(
            {
                "id": self.id,
                "timestamp": self.timestamp,
                "timezone": self.timezone,
                "title": self.title,
                "description": self.description,
                "evidenceIds": list(self.evidence_ids),
                "sourceIds": list(self.source_ids),
                "kind": self.kind,
            }
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "TimelineEntry":
        return cls(
            id=_get_value(data, "id"),
            timestamp=str(_get_value(data, "timestamp", default="")),
            timezone=_get_value(data, "timezone"),
            title=str(_get_value(data, "title", default="")),
            description=_get_value(data, "description"),
            evidence_ids=_normalize_str_list(
                _get_value(data, "evidence_ids", "evidenceIds"), field_name="evidence_ids"
            ),
            source_ids=_normalize_str_list(
                _get_value(data, "source_ids", "sourceIds"), field_name="source_ids"
            ),
            kind=_get_value(data, "kind"),
        )


@dataclass
class ReportGraph:
    report_sections: list[dict[str, Any]] = field(default_factory=list)
    evidence_links: list[dict[str, Any]] = field(default_factory=list)
    source_links: list[dict[str, Any]] = field(default_factory=list)
    timeline_links: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.report_sections = _normalize_mapping_list(
            self.report_sections, field_name="report_sections"
        )
        self.evidence_links = _normalize_mapping_list(
            self.evidence_links, field_name="evidence_links"
        )
        self.source_links = _normalize_mapping_list(self.source_links, field_name="source_links")
        self.timeline_links = _normalize_mapping_list(
            self.timeline_links, field_name="timeline_links"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "reportSections": [dict(item) for item in self.report_sections],
            "evidenceLinks": [dict(item) for item in self.evidence_links],
            "sourceLinks": [dict(item) for item in self.source_links],
            "timelineLinks": [dict(item) for item in self.timeline_links],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ReportGraph":
        return cls(
            report_sections=_normalize_mapping_list(
                _get_value(data, "report_sections", "reportSections"),
                field_name="report_sections",
            ),
            evidence_links=_normalize_mapping_list(
                _get_value(data, "evidence_links", "evidenceLinks"),
                field_name="evidence_links",
            ),
            source_links=_normalize_mapping_list(
                _get_value(data, "source_links", "sourceLinks"),
                field_name="source_links",
            ),
            timeline_links=_normalize_mapping_list(
                _get_value(data, "timeline_links", "timelineLinks"),
                field_name="timeline_links",
            ),
        )
