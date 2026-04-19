"""Windows forensic artifact tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from forensic_claw.agent.tools.base import Tool
from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.amcache import analyze_amcache_artifact
from forensic_claw.forensics.windows.eventlog import (
    EventLogRunner,
    ingest_eventlog_query_output,
    run_windows_eventlog_query,
)
from forensic_claw.forensics.windows.prefetch import PECmdRunner, analyze_prefetch_artifact
from forensic_claw.forensics.windows.timeline import build_windows_timeline


class _WindowsTool(Tool):
    def __init__(self, workspace: Path):
        self._workspace = Path(workspace)

    @property
    def store(self) -> CaseStore:
        return CaseStore(self._workspace)


class WindowsEventLogQueryTool(_WindowsTool):
    def __init__(self, workspace: Path, query_runner: EventLogRunner | None = None):
        super().__init__(workspace)
        self._query_runner = query_runner

    @property
    def name(self) -> str:
        return "windows_eventlog_query"

    @property
    def description(self) -> str:
        return "Query Windows Event Logs, store the raw source, create evidence, and append timeline entries."

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Target forensic case id"},
                "log_name": {"type": "string", "description": "Windows event log name"},
                "event_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "Optional list of event ids to filter",
                },
                "start_time": {
                    "type": "string",
                    "description": "Optional ISO 8601 start timestamp",
                },
                "end_time": {"type": "string", "description": "Optional ISO 8601 end timestamp"},
                "max_events": {
                    "type": "integer",
                    "description": "Maximum number of events to fetch",
                },
            },
            "required": ["case_id", "log_name"],
        }

    async def execute(
        self,
        case_id: str,
        log_name: str,
        event_ids: list[int] | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        max_events: int = 50,
        **kwargs: Any,
    ) -> str:
        text = await run_windows_eventlog_query(
            log_name=log_name,
            event_ids=event_ids,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
            runner=self._query_runner,
        )
        result = ingest_eventlog_query_output(
            self.store,
            case_id=case_id,
            log_name=log_name,
            query_output=text,
            event_ids=event_ids,
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
        )
        return (
            f"Stored {log_name} event log query in case {case_id}: "
            f"source={result.source.id if result.source else '-'}, "
            f"evidence={result.evidence.id}, "
            f"timeline_entries={len(result.timeline_entries)}"
        )


class WindowsPrefetchAnalyzeTool(_WindowsTool):
    def __init__(self, workspace: Path, runner: PECmdRunner | None = None):
        super().__init__(workspace)
        self._runner = runner

    @property
    def name(self) -> str:
        return "windows_prefetch_analyze"

    @property
    def description(self) -> str:
        return "Analyze a Prefetch artifact, store evidence, and append execution timeline entries."

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Target forensic case id"},
                "prefetch_path": {"type": "string", "description": "Path to a Prefetch artifact"},
                "layout_path": {
                    "type": "string",
                    "description": "Optional path to Layout.ini for Prefetch listing enrichment",
                },
                "source_id": {
                    "type": "string",
                    "description": "Existing source id containing Prefetch raw data",
                },
            },
            "required": ["case_id"],
        }

    async def execute(
        self,
        case_id: str,
        prefetch_path: str | None = None,
        layout_path: str | None = None,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> str:
        result = analyze_prefetch_artifact(
            self.store,
            case_id=case_id,
            prefetch_path=prefetch_path,
            layout_path=layout_path,
            source_id=source_id,
            runner=self._runner,
        )
        return (
            f"Analyzed Prefetch artifact for case {case_id}: "
            f"source={result.source.id if result.source else '-'}, "
            f"evidence={result.evidence.id}, "
            f"timeline_entries={len(result.timeline_entries)}"
        )


class WindowsAmcacheAnalyzeTool(_WindowsTool):
    @property
    def name(self) -> str:
        return "windows_amcache_analyze"

    @property
    def description(self) -> str:
        return "Analyze an Amcache hive export, store evidence, and append timeline entries."

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Target forensic case id"},
                "hive_path": {"type": "string", "description": "Path to an Amcache hive artifact"},
                "source_id": {
                    "type": "string",
                    "description": "Existing source id containing Amcache raw data",
                },
            },
            "required": ["case_id"],
        }

    async def execute(
        self,
        case_id: str,
        hive_path: str | None = None,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> str:
        result = analyze_amcache_artifact(
            self.store,
            case_id=case_id,
            hive_path=hive_path,
            source_id=source_id,
        )
        return (
            f"Analyzed Amcache artifact for case {case_id}: "
            f"source={result.source.id if result.source else '-'}, "
            f"evidence={result.evidence.id}, "
            f"timeline_entries={len(result.timeline_entries)}"
        )


class WindowsTimelineBuildTool(_WindowsTool):
    @property
    def name(self) -> str:
        return "windows_timeline_build"

    @property
    def description(self) -> str:
        return "Build a merged Windows forensic timeline from existing eventlog, Prefetch, and Amcache evidence."

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Target forensic case id"},
                "evidence_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional evidence ids to constrain the merged timeline",
                },
                "source_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional source ids to constrain the merged timeline",
                },
                "merge_strategy": {
                    "type": "string",
                    "enum": ["chronological", "dedupe"],
                    "description": "Timeline merge strategy",
                },
            },
            "required": ["case_id"],
        }

    async def execute(
        self,
        case_id: str,
        evidence_ids: list[str] | None = None,
        source_ids: list[str] | None = None,
        merge_strategy: str = "chronological",
        **kwargs: Any,
    ) -> str:
        result = build_windows_timeline(
            self.store,
            case_id=case_id,
            evidence_ids=evidence_ids,
            source_ids=source_ids,
            merge_strategy=merge_strategy,
        )
        return (
            f"Built merged Windows timeline for case {case_id}: "
            f"evidence={result.evidence.id}, entries={len(result.entries)}"
        )
