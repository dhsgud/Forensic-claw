"""Windows forensic artifact tools."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from forensic_claw.agent.tools.base import Tool
from forensic_claw.agent.tools.shell import ExecTool
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

    @staticmethod
    def _powershell_single_quote(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"


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
    _DIRECTORY_DEFAULT_MAX_FILES = 5

    def __init__(self, workspace: Path, runner: PECmdRunner | None = None):
        super().__init__(workspace)
        self._runner = runner

    @property
    def name(self) -> str:
        return "windows_prefetch_analyze"

    @property
    def description(self) -> str:
        return (
            "Analyze a Prefetch artifact, or analyze the most recent .pf files from a "
            "Prefetch directory, store evidence, and append execution timeline entries."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "case_id": {"type": "string", "description": "Target forensic case id"},
                "prefetch_path": {
                    "type": "string",
                    "description": "Path to a Prefetch artifact or a directory containing .pf files",
                },
                "max_files": {
                    "type": "integer",
                    "description": (
                        "When prefetch_path is a directory, analyze up to this many recent .pf files "
                        f"(default {self._DIRECTORY_DEFAULT_MAX_FILES})."
                    ),
                },
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
        max_files: int = _DIRECTORY_DEFAULT_MAX_FILES,
        layout_path: str | None = None,
        source_id: str | None = None,
        **kwargs: Any,
    ) -> str:
        if source_id is None and prefetch_path is not None:
            requested_path = Path(prefetch_path)
            if requested_path.is_dir():
                limit = max(1, int(max_files or self._DIRECTORY_DEFAULT_MAX_FILES))
                targets = await self._list_directory_prefetch_candidates(requested_path, limit)
                if not targets:
                    raise FileNotFoundError(f"No .pf files found under {requested_path}")

                results = [
                    analyze_prefetch_artifact(
                        self.store,
                        case_id=case_id,
                        prefetch_path=target,
                        layout_path=layout_path,
                        runner=self._runner,
                    )
                    for target in targets
                ]
                evidence_ids = [result.evidence.id for result in results if result.evidence.id]
                timeline_count = sum(len(result.timeline_entries) for result in results)
                analyzed_names = ", ".join(target.name for target in targets[:3])
                if len(targets) > 3:
                    analyzed_names += ", ..."
                return (
                    f"Analyzed Prefetch directory for case {case_id}: "
                    f"files={len(results)}, evidence={len(evidence_ids)}, "
                    f"timeline_entries={timeline_count}, samples={analyzed_names}"
                )

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

    async def _list_directory_prefetch_candidates(
        self,
        requested_path: Path,
        limit: int,
    ) -> list[Path]:
        try:
            candidates = sorted(
                (
                    candidate
                    for candidate in requested_path.glob("*.pf")
                    if candidate.is_file()
                ),
                key=lambda candidate: candidate.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                return candidates[:limit]
            next(requested_path.iterdir(), None)
            return []
        except PermissionError:
            return await self._list_directory_prefetch_candidates_via_exec(requested_path, limit)

    async def _list_directory_prefetch_candidates_via_exec(
        self,
        requested_path: Path,
        limit: int,
    ) -> list[Path]:
        exec_tool = ExecTool(timeout=60, working_dir=str(self._workspace))
        path_literal = self._powershell_single_quote(str(requested_path))
        command = (
            "$prefetchFiles = @(\n"
            f"  Get-ChildItem -LiteralPath {path_literal} -Filter '*.pf' -File -ErrorAction Stop |\n"
            "  Sort-Object LastWriteTime -Descending |\n"
            f"  Select-Object -First {limit} -ExpandProperty FullName\n"
            ")\n"
            "$prefetchFiles\n"
        )
        capture = await exec_tool.capture(command, working_dir=str(self._workspace))
        if capture.timed_out:
            raise TimeoutError(f"Timed out while enumerating Prefetch directory {requested_path}")
        if capture.exit_code not in (0, None):
            detail = ExecTool._decode_output(capture.stderr or capture.stdout).strip() or "unknown error"
            raise RuntimeError(f"Failed to enumerate Prefetch directory {requested_path}: {detail}")

        output = ExecTool._decode_output(capture.stdout)
        return [
            Path(line.strip())
            for line in output.splitlines()
            if line.strip() and os.path.splitext(line.strip())[1].lower() == ".pf"
        ]


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
