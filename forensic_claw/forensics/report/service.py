"""Report generation entry point used by commands and the WebUI."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from forensic_claw.forensics.case import CaseStore
from forensic_claw.forensics.report.export import render_html, render_pdf
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
        fresh = await asyncio.to_thread(
            self.case_store.collect_context,
            case_id,
            compute_hashes=compute_hashes,
            max_hash_bytes=max_hash_bytes,
        )
        if fresh is None:
            return {"ok": False, "error": "case_disappeared", "caseId": case_id}
        valid_sources = {
            str(fresh.root / "sources" / source.id / "raw" / name)
            for source in fresh.sources
            for name in source.files
            if source.verification.get(name, {}).get("ok") is True
        }
        for index, spec in enumerate(self.generator.template.sections):
            section = report.sections[index]
            if spec.kind == "integrity_table":
                report.sections[index] = await self.generator._render_section(spec, fresh)
            elif section.checks and any(source not in valid_sources for source in section.sources):
                section.markdown = "**UNVERIFIED** — 생성 중 원본 무결성이 변경되어 결과를 제외했습니다. 재수집·검토 필요."
                for check in section.checks:
                    check["grade"] = "UNVERIFIED"
                    check["issues"] = sorted(
                        set(check["issues"] + ["source_integrity_unavailable"])
                    )
        markdown = report.to_markdown()
        report_path = self.case_store.case_dir(case_id) / "report.md"
        exports = await asyncio.to_thread(_write_exports, context.root, report)

        return {
            "ok": True,
            "caseId": case_id,
            "reportPath": str(report_path),
            "exports": exports,
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


def _write_exports(root: Path, report) -> dict[str, str]:
    with tempfile.TemporaryDirectory(prefix=".report-", dir=root) as temporary:
        stage = Path(temporary)
        _write_text(stage / "report.md", report.to_markdown())
        _write_text(stage / "report.html", render_html(report))
        _write_text(stage / "report.json", json.dumps(asdict(report), ensure_ascii=False, indent=2))
        render_pdf(report, stage / "report.pdf")
        paths = {}
        for format in ("md", "html", "json", "pdf"):
            target = root / f"report.{format}"
            os.replace(stage / target.name, target)
            paths[format] = str(target)
        return paths
