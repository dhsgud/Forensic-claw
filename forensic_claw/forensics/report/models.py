"""Data models for the report template and generated report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SectionSpec:
    """One section definition from a report template.

    ``kind`` selects the renderer:
      - ``document_info`` — case/document metadata table (no LLM)
      - ``integrity_table`` — evidence file hash table (no LLM)
      - ``environment`` — analysis tools and model (no LLM)
      - ``graph`` — relationship graph summary (no LLM)
      - ``signature`` — investigator signature block (no LLM)
      - ``static`` — fixed body text with ``{placeholders}``
      - ``llm`` — knowledge_search evidence + model-written prose
    """

    id: str
    title: str
    kind: str
    body: str = ""
    prompt: str = ""
    queries: list[str] = field(default_factory=list)
    cite: bool = False
    fallback: str = ""


@dataclass
class ReportSpec:
    """A full report template."""

    id: str
    name: str
    title: str
    language: str = "ko"
    sections: list[SectionSpec] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReportSpec":
        sections = [
            SectionSpec(
                id=str(item["id"]),
                title=str(item["title"]),
                kind=str(item["kind"]),
                body=str(item.get("body", "")),
                prompt=str(item.get("prompt", "")),
                queries=[str(q) for q in item.get("queries", [])],
                cite=bool(item.get("cite", False)),
                fallback=str(item.get("fallback", "")),
            )
            for item in payload.get("sections", [])
        ]
        return cls(
            id=str(payload["id"]),
            name=str(payload.get("name", payload["id"])),
            title=str(payload.get("title", payload.get("name", payload["id"]))),
            language=str(payload.get("language", "ko")),
            sections=sections,
        )


@dataclass
class GeneratedSection:
    """One rendered section of a report."""

    id: str
    title: str
    kind: str
    markdown: str
    sources: list[str] = field(default_factory=list)
    used_llm: bool = False


@dataclass
class GeneratedReport:
    """A fully rendered report ready to persist."""

    case_id: str
    template_id: str
    title: str
    generated_at: str
    sections: list[GeneratedSection] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = [f"# {self.title}", ""]
        for section in self.sections:
            lines.append(f"## {section.title}")
            lines.append("")
            lines.append(section.markdown.strip() or "_(내용 없음)_")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"
