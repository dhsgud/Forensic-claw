"""Report generation entry point used by commands and the WebUI."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from forensic_claw.forensics.case import CaseStore
from forensic_claw.forensics.report.generator import OnSection, ReportGenerator
from forensic_claw.forensics.report.models import ReportSpec


class ReportService:
    """Collect a case, generate its report, and persist ``report.md``."""

    def __init__(
        self,
        *,
        workspace: Path,
        provider: Any,
        model: str,
        knowledge_service: Any | None = None,
        template: ReportSpec | None = None,
        app_version: str | None = None,
        temperature: float = 0.1,
    ):
        self.case_store = CaseStore(workspace)
        self.generator = ReportGenerator(
            provider=provider,
            model=model,
            knowledge_service=knowledge_service,
            template=template,
            temperature=temperature,
            app_version=app_version,
        )

    async def generate_report(
        self,
        case_id: str,
        *,
        on_section: OnSection | None = None,
        compute_hashes: bool = True,
        max_hash_bytes: int | None = None,
    ) -> dict[str, Any]:
        context = await asyncio.to_thread(
            self.case_store.collect_context,
            case_id,
            compute_hashes=compute_hashes,
            max_hash_bytes=max_hash_bytes,
        )
        if context is None:
            return {"ok": False, "error": "case_not_found", "caseId": case_id}

        report = await self.generator.generate(context, on_section=on_section)
        markdown = report.to_markdown()
        report_path = self.case_store.case_dir(case_id) / "report.md"
        await asyncio.to_thread(_write_text, report_path, markdown)

        return {
            "ok": True,
            "caseId": case_id,
            "reportPath": str(report_path),
            "templateId": report.template_id,
            "title": report.title,
            "generatedAt": report.generated_at,
            "sections": [
                {"id": section.id, "title": section.title, "usedLlm": section.used_llm}
                for section in report.sections
            ],
            "markdown": markdown,
        }


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
