"""Case report and report-draft generation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from forensic_claw.forensics.store import CaseStore


@dataclass(frozen=True)
class ReportBuildResult:
    report_path: Path
    draft_path: Path


class CaseReportBuilder:
    """Generate deterministic report files from the case graph and stored artifacts."""

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace)

    def rebuild(self, store: CaseStore, case_id: str) -> ReportBuildResult:
        manifest = store.load_manifest(case_id)
        graph = store.read_graph(case_id)
        report_sections = graph.report_sections or [
            {
                "id": "collected-findings",
                "title": "Collected Findings",
                "evidenceIds": store.list_evidence_ids(case_id),
            }
        ]

        evidence_to_sources = {
            row["id"]: list(row.get("sourceIds", []))
            for row in graph.evidence_links
            if isinstance(row.get("id"), str)
        }
        source_to_timelines = {
            row["id"]: list(row.get("timelineIds", []))
            for row in graph.source_links
            if isinstance(row.get("id"), str)
        }
        timeline_to_evidence = {
            row["id"]: list(row.get("evidenceIds", []))
            for row in graph.timeline_links
            if isinstance(row.get("id"), str)
        }
        timeline_index = {entry.id: entry for entry in store.read_timeline(case_id) if entry.id}

        report_lines = [
            f"# {manifest.title} Report",
            "",
            "## Case Summary",
            "",
            f"- Case ID: {manifest.id}",
            f"- Status: {manifest.status}",
            f"- Summary: {manifest.summary or '-'}",
            "",
        ]
        draft_lines = [
            f"# {manifest.title} Draft",
            "",
            "## Case Summary",
            "",
            f"- Case ID: {manifest.id}",
            f"- Status: {manifest.status}",
            f"- Summary: {manifest.summary or '-'}",
            "",
        ]

        for section in report_sections:
            section_title = str(section.get("title") or section.get("id") or "Untitled Section")
            evidence_ids = [str(value) for value in section.get("evidenceIds", [])]
            source_ids = []
            timeline_ids = []
            evidence_rows = []
            timeline_rows = []
            for evidence_id in evidence_ids:
                try:
                    evidence = store.load_evidence(case_id, evidence_id)
                except FileNotFoundError:
                    continue
                evidence_rows.append(evidence)
                for source_id in evidence_to_sources.get(evidence_id, evidence.derived_from_source_ids):
                    if source_id not in source_ids:
                        source_ids.append(source_id)
                for timeline_id, linked_evidence_ids in timeline_to_evidence.items():
                    if evidence_id in linked_evidence_ids and timeline_id not in timeline_ids:
                        timeline_ids.append(timeline_id)
            if not timeline_ids:
                for source_id in source_ids:
                    for timeline_id in source_to_timelines.get(source_id, []):
                        if timeline_id not in timeline_ids:
                            timeline_ids.append(timeline_id)
            for timeline_id in timeline_ids:
                entry = timeline_index.get(timeline_id)
                if entry is not None:
                    timeline_rows.append(entry)

            report_lines.extend(
                self._section_block(
                    title=section_title,
                    evidence_rows=evidence_rows,
                    source_ids=source_ids,
                    timeline_rows=timeline_rows,
                )
            )
            draft_lines.extend(
                self._draft_section_block(
                    title=section_title,
                    evidence_rows=evidence_rows,
                    source_ids=source_ids,
                    timeline_rows=timeline_rows,
                )
            )

        store.write_report(case_id, "\n".join(report_lines).strip() + "\n")
        store.write_report_draft(case_id, "\n".join(draft_lines).strip() + "\n")
        case_dir = store.case_dir(case_id)
        return ReportBuildResult(
            report_path=case_dir / "report.md",
            draft_path=case_dir / "report-draft.md",
        )

    @staticmethod
    def _section_block(*, title: str, evidence_rows, source_ids: list[str], timeline_rows) -> list[str]:
        lines = [
            f"## {title}",
            "",
            "## Observed",
            "",
        ]
        if evidence_rows:
            for evidence in evidence_rows:
                lines.append(f"- Evidence {evidence.id}: {evidence.summary or evidence.title}")
        else:
            lines.append("- No evidence is linked to this section yet.")
        if timeline_rows:
            for entry in timeline_rows:
                lines.append(f"- Timeline {entry.id}: {entry.timestamp} | {entry.title}")
        if source_ids:
            lines.append(f"- Sources: {', '.join(source_ids)}")
        lines.extend(
            [
                "",
                "## Inferred",
                "",
                "- The grouped artifacts may describe related activity, but the linkage should remain anchored to cited evidence and sources.",
                "",
                "## Unknown",
                "",
                "- Intent, completeness, and excluded alternatives remain unconfirmed.",
                "",
                f"References: evidence={', '.join(evidence.id or '-' for evidence in evidence_rows) or '-'}; "
                f"sources={', '.join(source_ids) or '-'}; "
                f"timeline={', '.join(entry.id or '-' for entry in timeline_rows) or '-'}",
                "",
            ]
        )
        return lines

    @staticmethod
    def _draft_section_block(*, title: str, evidence_rows, source_ids: list[str], timeline_rows) -> list[str]:
        lines = [
            f"## {title}",
            "",
            "## Observed",
            "",
        ]
        if evidence_rows:
            for evidence in evidence_rows:
                lines.append(
                    f"- {evidence.id}: type={evidence.artifact_type}, title={evidence.title}, summary={evidence.summary or '-'}"
                )
                lines.append(
                    f"  Source IDs: {', '.join(evidence.derived_from_source_ids) or '-'} | Produced By: {evidence.produced_by or '-'} | Observed At: {evidence.observed_at or '-'}"
                )
        else:
            lines.append("- No evidence is linked to this section yet.")
        for entry in timeline_rows:
            lines.append(
                f"- {entry.id}: {entry.timestamp} | {entry.title} | evidence={', '.join(entry.evidence_ids) or '-'} | source={', '.join(entry.source_ids) or '-'}"
            )
        if source_ids:
            lines.append(f"- Source IDs: {', '.join(source_ids)}")
        lines.extend(
            [
                "",
                "## Inferred",
                "",
                "- Draft correlation only. Confirm with raw source content before promoting to a final statement.",
                "",
                "## Unknown",
                "",
                "- Additional artifacts, missing telemetry, and analyst interpretation gaps are unresolved.",
                "",
            ]
        )
        return lines
