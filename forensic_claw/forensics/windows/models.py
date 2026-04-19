"""Structured models for Windows artifact parsing."""

from __future__ import annotations

from dataclasses import dataclass, field

from forensic_claw.forensics.models import EvidenceMetadata, SourceMetadata, TimelineEntry


@dataclass(frozen=True)
class ArtifactUpdateResult:
    """Outcome of ingesting or analyzing one artifact into the case store."""

    source: SourceMetadata | None
    evidence: EvidenceMetadata
    timeline_entries: list[TimelineEntry] = field(default_factory=list)
    summary: str = ""


@dataclass(frozen=True)
class EventLogRecord:
    timestamp: str
    log_name: str
    source: str
    event_id: str
    level: str | None = None
    computer: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class PrefetchArtifact:
    executable_name: str
    run_count: int | None = None
    last_run_times: list[str] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    prefetch_hash: str | None = None
    version: str | None = None
    source_filename: str | None = None
    layout_ini_path: str | None = None
    layout_prefetch_entries: list[str] = field(default_factory=list)
    layout_prefetch_entry_count: int = 0


@dataclass(frozen=True)
class AmcacheArtifact:
    program_name: str
    path: str | None = None
    sha1: str | None = None
    first_seen: str | None = None
    modified_at: str | None = None


@dataclass(frozen=True)
class TimelineBuildResult:
    evidence: EvidenceMetadata
    entries: list[TimelineEntry] = field(default_factory=list)
    summary: str = ""
