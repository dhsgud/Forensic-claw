"""LLM-driven, template-first report generation.

The generator walks the template section by section. Metadata/integrity/graph
sections are filled directly from the :class:`CaseContext` (no model, so the
integrity-critical parts never depend on the LLM). Narrative sections gather
evidence from the local knowledge store and ask the model to write prose using
only that evidence.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from loguru import logger

from forensic_claw.forensics.case import CaseContext
from forensic_claw.forensics.report.models import (
    GeneratedReport,
    GeneratedSection,
    ReportSpec,
    SectionSpec,
)
from forensic_claw.forensics.report.template import default_template
from forensic_claw.session.scopes import normalize_scope_id
from forensic_claw.utils.helpers import strip_think

OnSection = Callable[[int, int, str], Awaitable[None]]


class ReportGenerator:
    """Render a :class:`CaseContext` into a structured report."""

    _MAX_EVIDENCE_CHARS = 8000
    _HIT_TEXT_LIMIT = 600
    _SEARCH_LIMIT = 6

    def __init__(
        self,
        *,
        provider: Any,
        model: str,
        knowledge_service: Any | None = None,
        template: ReportSpec | None = None,
        temperature: float = 0.1,
        app_version: str | None = None,
    ):
        self.provider = provider
        self.model = model
        self.knowledge_service = knowledge_service
        self.template = template or default_template()
        self.temperature = temperature
        self.app_version = app_version

    async def generate(
        self,
        context: CaseContext,
        *,
        on_section: OnSection | None = None,
    ) -> GeneratedReport:
        total = len(self.template.sections)
        sections: list[GeneratedSection] = []
        for index, spec in enumerate(self.template.sections, start=1):
            if on_section:
                await on_section(index, total, spec.title)
            sections.append(await self._render_section(spec, context))
        return GeneratedReport(
            case_id=context.case_id,
            template_id=self.template.id,
            title=self.template.title,
            generated_at=datetime.now().astimezone().isoformat(),
            sections=sections,
        )

    async def _render_section(self, spec: SectionSpec, context: CaseContext) -> GeneratedSection:
        if spec.kind == "llm":
            markdown, sources, used_llm = await self._llm(spec, context)
        else:
            markdown = self._render_data_section(spec, context)
            sources, used_llm = [], False
        return GeneratedSection(
            id=spec.id,
            title=spec.title,
            kind=spec.kind,
            markdown=markdown,
            sources=sources,
            used_llm=used_llm,
        )

    def _render_data_section(self, spec: SectionSpec, context: CaseContext) -> str:
        if spec.kind == "document_info":
            return self._document_info(context)
        if spec.kind == "integrity_table":
            return self._integrity_table(context)
        if spec.kind == "environment":
            return self._environment(context)
        if spec.kind == "graph":
            return self._graph(context)
        if spec.kind == "signature":
            return self._signature(context)
        return self._fill(spec.body, context)

    def _document_info(self, context: CaseContext) -> str:
        manifest = context.manifest or {}
        rows = [
            ("사건번호", context.case_id),
            ("사건명", context.case_name),
            ("분석관", context.investigator_name or "-"),
            ("분석 기관", manifest.get("organization") or "-"),
            ("분석 도구", f"Forensic-Claw {self.app_version}" if self.app_version else "Forensic-Claw"),
            ("분석 모델", self.model or "-"),
            ("작성일시", _now_str()),
        ]
        lines = ["| 항목 | 내용 |", "| --- | --- |"]
        lines += [f"| {label} | {_cell(value)} |" for label, value in rows]
        return "\n".join(lines)

    def _integrity_table(self, context: CaseContext) -> str:
        rows = context.integrity_rows()
        if not rows:
            return "등록된 증거 파일이 없어 무결성 해시 표를 생성하지 못했습니다."
        lines = ["| 증거 | 파일 | SHA-256 | MD5 |", "| --- | --- | --- | --- |"]
        for row in rows:
            lines.append(
                f"| {_cell(row['evidenceId'])} | {_cell(row['file'])} "
                f"| {_cell(row['sha256']) or '-'} | {_cell(row['md5']) or '-'} |"
            )
        return "\n".join(lines)

    def _environment(self, context: CaseContext) -> str:
        tool_line = f"Forensic-Claw {self.app_version}" if self.app_version else "Forensic-Claw"
        lines = [
            f"- 분석 도구: {tool_line}",
            f"- 분석 모델: {self.model or '-'}",
            "- 분석 방식: 로컬 LLM 기반 RAG/그래프 인덱싱 및 검색",
            "- 실행 환경: Windows 네이티브 로컬 워크벤치",
        ]
        return "\n".join(lines)

    def _graph(self, context: CaseContext) -> str:
        graph = context.graph
        if not isinstance(graph, dict):
            return "관계 그래프 스냅샷(graph.json)이 없어 관계 분석을 생략합니다."
        nodes = graph.get("nodes") or graph.get("entities") or []
        edges = graph.get("edges") or graph.get("relationships") or []
        labels = []
        for node in nodes[:10]:
            if isinstance(node, dict):
                labels.append(str(node.get("label") or node.get("value") or node.get("id") or ""))
        summary = [
            f"- 노드 수: {len(nodes)}",
            f"- 관계 수: {len(edges)}",
        ]
        if labels:
            summary.append("- 주요 엔티티: " + ", ".join(label for label in labels if label))
        return "\n".join(summary)

    def _signature(self, context: CaseContext) -> str:
        investigator = context.investigator_name or "________"
        return (
            f"분석관: {investigator}　　(서명) ____________________\n\n"
            "작성일: 20​__ . ​__ . ​__ ."
        )

    async def _llm(self, spec: SectionSpec, context: CaseContext) -> tuple[str, list[str], bool]:
        evidence, sources = await asyncio.to_thread(self._gather_evidence, spec, context)
        if not evidence:
            return (spec.fallback or "해당 항목에 대한 근거를 찾지 못했습니다.", [], False)

        messages = [
            {"role": "system", "content": self._system_prompt(context)},
            {"role": "user", "content": self._user_prompt(spec, evidence)},
        ]
        try:
            response = await self.provider.chat_with_retry(
                messages=messages,
                tools=None,
                model=self.model,
                temperature=self.temperature,
            )
        except Exception as exc:
            logger.warning("Report section '{}' generation failed: {}", spec.id, exc)
            return (spec.fallback or "본문 생성 중 오류가 발생했습니다.", sources, False)

        if getattr(response, "finish_reason", None) == "error":
            logger.warning(
                "Report section '{}' provider returned an error response: {}",
                spec.id,
                (getattr(response, "content", "") or "")[:120],
            )
            return (spec.fallback or "보고서 본문 생성 중 오류가 발생했습니다.", sources, False)

        content = strip_think(response.content or "") if response and response.content else ""
        content = (content or "").strip()
        if not content:
            return (spec.fallback or "내용을 생성하지 못했습니다.", sources, False)
        if spec.cite and sources:
            refs = "\n".join(f"- {src}" for src in sources)
            content = f"{content}\n\n**참고 출처**\n{refs}"
        return (content, sources, True)

    def _gather_evidence(self, spec: SectionSpec, context: CaseContext) -> tuple[str, list[str]]:
        service = self.knowledge_service
        if service is None or not getattr(service, "enabled", False):
            return "", []
        seen: set[tuple[str, str]] = set()
        blocks: list[str] = []
        sources: list[str] = []
        total = 0
        for query in spec.queries:
            try:
                data = service.search(query, limit=self._SEARCH_LIMIT)
            except Exception as exc:
                logger.debug("Report evidence search failed for '{}': {}", query, exc)
                continue
            for hit in data.get("hits", []) if isinstance(data, dict) else []:
                if not self._hit_matches_case(hit, context):
                    continue
                text = str(hit.get("text") or "").strip()
                source = str(hit.get("sourcePath") or "").strip()
                key = (source, text[:80])
                if not text or key in seen:
                    continue
                seen.add(key)
                block = f"- [출처: {source or 'unknown'}] {text[: self._HIT_TEXT_LIMIT]}"
                if total + len(block) > self._MAX_EVIDENCE_CHARS:
                    return "\n".join(blocks), sources
                blocks.append(block)
                total += len(block)
                if source and source not in sources:
                    sources.append(source)
        return "\n".join(blocks), sources

    def _hit_matches_case(self, hit: dict[str, Any], context: CaseContext) -> bool:
        if not isinstance(hit, dict):
            return False
        metadata = hit.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        expected = _case_scope_values(context)
        hit_values = {
            _normalize_case_scope(metadata.get(key))
            for key in ("caseId", "case_id", "caseName", "case_name")
        }
        hit_values.discard(None)
        if hit_values:
            return bool(expected & hit_values)
        return _path_is_under_case_root(str(hit.get("sourcePath") or ""), context.root)

    def _system_prompt(self, context: CaseContext) -> str:
        return (
            "당신은 디지털 포렌식 분석관을 보조하는 보고서 작성 도우미다.\n"
            "- 반드시 제공된 근거만 사용하고, 근거에 없는 사실은 지어내지 않는다.\n"
            "- 격식 있는 한국어로 간결하고 객관적으로 작성한다.\n"
            "- 추정과 사실을 구분하고, 불확실한 부분은 그 취지를 밝힌다.\n"
            f"- 사건명: {context.case_name}"
        )

    def _user_prompt(self, spec: SectionSpec, evidence: str) -> str:
        return (
            f"[섹션] {spec.title}\n"
            f"[작성 지침] {spec.prompt}\n\n"
            f"[근거]\n{evidence}\n\n"
            f"위 근거만 사용하여 '{spec.title}' 섹션 본문을 작성하라. "
            "제목이나 머리말은 붙이지 말고 본문만 반환하라."
        )

    def _fill(self, text: str, context: CaseContext) -> str:
        replacements = {
            "{case_name}": context.case_name,
            "{case_id}": context.case_id,
            "{investigator}": context.investigator_name or "",
            "{date}": _now_str(),
        }
        for token, value in replacements.items():
            text = text.replace(token, value)
        return text


def _case_scope_values(context: CaseContext) -> set[str]:
    values = {
        _normalize_case_scope(context.case_id),
        _normalize_case_scope(context.case_name),
        _normalize_case_scope((context.manifest or {}).get("caseId")),
        _normalize_case_scope((context.manifest or {}).get("caseName")),
        _normalize_case_scope((context.manifest or {}).get("title")),
    }
    values.discard(None)
    return {value for value in values if value}


def _normalize_case_scope(value: Any) -> str | None:
    if value is None:
        return None
    return normalize_scope_id(str(value))


def _path_is_under_case_root(source: str, root: Path) -> bool:
    if not source:
        return False
    try:
        source_path = Path(source).expanduser()
        if not source_path.is_absolute():
            return False
        source_path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")
