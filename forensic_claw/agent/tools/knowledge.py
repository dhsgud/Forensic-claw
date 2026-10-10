"""Tools for local RAG and graph knowledge ingestion."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any

from forensic_claw.agent.tools.base import Tool
from forensic_claw.knowledge.service import KnowledgeService


def _is_under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory.resolve())
        return True
    except ValueError:
        return False


class _KnowledgeTool(Tool):
    def __init__(
        self,
        service: KnowledgeService,
        *,
        workspace: Path,
        allowed_dir: Path | None = None,
    ):
        self.service = service
        self.workspace = workspace
        self.allowed_dir = allowed_dir
        self.case_id: str | None = None
        self.case_name: str | None = None
        self.investigator_name: str | None = None

    def set_context(self, metadata: dict[str, Any]) -> None:
        self.case_id = metadata.get("case_id") or metadata.get("caseId")
        self.case_name = metadata.get("case_name") or metadata.get("caseName") or self.case_id
        self.investigator_name = metadata.get("investigator_name") or metadata.get(
            "investigatorName"
        )

    def _resolve(self, path: str) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        resolved = candidate.resolve()
        if self.allowed_dir and not _is_under(resolved, self.allowed_dir):
            raise PermissionError(f"Path {path} is outside allowed directory {self.allowed_dir}")
        return resolved


class KnowledgeDiscoverTool(_KnowledgeTool):
    """Locate candidate local artifacts without collecting unrelated file contents."""

    @property
    def name(self) -> str:
        return "knowledge_discover"

    @property
    def description(self) -> str:
        return (
            "Find existing local evidence locations when the user has not uploaded files. "
            "Use chrome_history for Chrome databases, windows_events for EVTX files, or "
            "locations for workspace/home/app-data directories. Inspect relevant candidates "
            "with list_dir, then knowledge_ingest and knowledge_search before answering."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "source": {
                    "type": "string",
                    "enum": ["chrome_history", "windows_events", "locations"],
                }
            },
            "required": ["source"],
        }

    async def execute(self, source: str, **_: Any) -> str:
        if source not in {"chrome_history", "windows_events", "locations"}:
            return "Error: unsupported evidence source"

        def discover() -> dict[str, Any]:
            locations = {"workspace": self.workspace.resolve(), "home": Path.home().resolve()}
            for name in ("LOCALAPPDATA", "APPDATA", "SystemRoot"):
                if value := os.environ.get(name):
                    locations[name] = Path(value).resolve()
            permitted = {
                name: path
                for name, path in locations.items()
                if path.is_dir() and (not self.allowed_dir or _is_under(path, self.allowed_dir))
            }
            candidates = []
            if source == "chrome_history":
                candidates = self.service.discover_chrome_history(
                    max_files=20, allowed_dir=self.allowed_dir
                )
            elif source == "windows_events" and "SystemRoot" in permitted:
                logs = (permitted["SystemRoot"] / "System32/winevt/Logs").resolve()
                if not self.allowed_dir or _is_under(logs, self.allowed_dir):
                    permitted["event_logs"] = logs
                candidates = [
                    logs / name
                    for name in (
                        "System.evtx",
                        "Application.evtx",
                        "Security.evtx",
                        "Windows PowerShell.evtx",
                        "Microsoft-Windows-PowerShell%4Operational.evtx",
                        "Microsoft-Windows-Sysmon%4Operational.evtx",
                    )
                ]
            return {
                "source": source,
                "locations": {name: str(path) for name, path in permitted.items()},
                "candidates": [
                    str(path.resolve())
                    for path in candidates
                    if path.is_file()
                    and (not self.allowed_dir or _is_under(path.resolve(), self.allowed_dir))
                ],
                "next_step": "Ingest only relevant candidates, then search the current case.",
            }

        try:
            return json.dumps(await asyncio.to_thread(discover), ensure_ascii=False)
        except OSError as exc:
            return f"Error: evidence discovery failed: {exc}"


class KnowledgeIngestTool(_KnowledgeTool):
    """Prepare large local evidence into the RAG and graph stores."""

    @property
    def name(self) -> str:
        return "knowledge_ingest"

    @property
    def description(self) -> str:
        return (
            "Ingest a local evidence file or directory into the local RAG index and graph store. "
            "Use this for large logs, Chrome History SQLite databases, and evidence folders before "
            "answering questions about their contents. After it reports ready, search the newly "
            "collected evidence and answer the current question in the same turn."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File or directory path to ingest. Relative paths resolve from the workspace.",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "Recursively scan a directory. Defaults to true.",
                },
                "file_globs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional filename globs such as *.log, History, *.sqlite.",
                },
                "max_files": {
                    "type": ["integer", "null"],
                    "description": "Optional maximum number of files to ingest.",
                    "minimum": 1,
                },
                "case_name": {
                    "type": ["string", "null"],
                    "description": "Case name to attach to graph source nodes.",
                },
                "investigator_name": {
                    "type": ["string", "null"],
                    "description": "Investigator name to attach to graph source nodes.",
                },
            },
            "required": ["path"],
        }

    async def execute(
        self,
        path: str,
        recursive: bool = True,
        file_globs: list[str] | None = None,
        max_files: int | None = None,
        case_name: str | None = None,
        investigator_name: str | None = None,
        **_: Any,
    ) -> Any:
        try:
            resolved = self._resolve(path)
        except Exception as exc:
            return f"Error: {exc}"
        result = await asyncio.to_thread(
            self.service.ingest_path,
            resolved,
            recursive=recursive,
            file_globs=file_globs,
            max_files=max_files,
            case_name=self.case_name or case_name,
            case_id=self.case_id,
            investigator_name=self.investigator_name or investigator_name,
        )
        return self.service.result_to_text(result)


class KnowledgeSearchTool(_KnowledgeTool):
    """Retrieve evidence context from the RAG and graph stores."""

    @property
    def name(self) -> str:
        return "knowledge_search"

    @property
    def description(self) -> str:
        return (
            "Search prepared local evidence in the RAG index and graph mirror. "
            "Use this before answering questions about evidence that has already been ingested."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Question or search terms."},
                "limit": {
                    "type": "integer",
                    "description": "Maximum RAG chunks and graph hits to return. Defaults to 8.",
                    "minimum": 1,
                    "maximum": 25,
                },
                "include_graph": {
                    "type": "boolean",
                    "description": "Include local graph entity matches. Defaults to true.",
                },
            },
            "required": ["query"],
        }

    async def execute(
        self,
        query: str,
        limit: int = 8,
        include_graph: bool = True,
        **_: Any,
    ) -> Any:
        data = await asyncio.to_thread(
            self.service.search,
            query,
            limit=limit,
            include_graph=include_graph,
            case_id=self.case_id,
        )
        return json.dumps(data, ensure_ascii=False, indent=2)


class KnowledgeStatusTool(_KnowledgeTool):
    """Report RAG and graph backend readiness."""

    @property
    def name(self) -> str:
        return "knowledge_status"

    @property
    def description(self) -> str:
        return "Show local RAG store counts and graph backend readiness."

    @property
    def parameters(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def execute(self, **_: Any) -> Any:
        data = await asyncio.to_thread(self.service.status)
        return json.dumps(data, ensure_ascii=False, indent=2)
