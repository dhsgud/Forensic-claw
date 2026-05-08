"""Tools for local RAG and graph knowledge ingestion."""

from __future__ import annotations

import asyncio
import json
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

    def _resolve(self, path: str) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = self.workspace / candidate
        resolved = candidate.resolve()
        if self.allowed_dir and not _is_under(resolved, self.allowed_dir):
            raise PermissionError(f"Path {path} is outside allowed directory {self.allowed_dir}")
        return resolved


class KnowledgeIngestTool(_KnowledgeTool):
    """Prepare large local evidence into the RAG and graph stores."""

    @property
    def name(self) -> str:
        return "knowledge_ingest"

    @property
    def description(self) -> str:
        return (
            "Ingest a local evidence file or directory into the local RAG index and Neo4j graph. "
            "Use this for large logs, Chrome History SQLite databases, and evidence folders before "
            "answering questions about their contents. When it reports ready, tell the user they can ask questions."
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
                "sync_neo4j": {
                    "type": "boolean",
                    "description": "Push graph rows to Neo4j when configured. Defaults to true.",
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
        sync_neo4j: bool = True,
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
            case_name=case_name,
            investigator_name=investigator_name,
            sync_neo4j=sync_neo4j,
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
        )
        return json.dumps(data, ensure_ascii=False, indent=2)


class KnowledgeStatusTool(_KnowledgeTool):
    """Report RAG and Neo4j readiness."""

    @property
    def name(self) -> str:
        return "knowledge_status"

    @property
    def description(self) -> str:
        return "Show local RAG store counts and Neo4j connectivity/readiness."

    @property
    def parameters(self) -> dict[str, Any]:
        return {"type": "object", "properties": {}}

    async def execute(self, **_: Any) -> Any:
        data = await asyncio.to_thread(self.service.status)
        return json.dumps(data, ensure_ascii=False, indent=2)
