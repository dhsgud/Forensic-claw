"""Case-scoped wiki note generation."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from forensic_claw.forensics.store import CaseStore
from forensic_claw.utils.helpers import ensure_dir


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat()


def _timeline_date_key(timestamp: str) -> str:
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).date().isoformat()


class CaseWikiWriter:
    """Write deterministic case wiki notes under ``workspace/wiki/cases``."""

    def __init__(self, workspace: Path):
        self.root = ensure_dir(Path(workspace) / "wiki" / "cases")

    def sync_source_note(self, store: CaseStore, case_id: str, source_id: str) -> Path:
        source = store.load_source(case_id, source_id)
        path = ensure_dir(self.root / case_id / "sources") / f"{source_id}.md"
        body = "\n".join(
            [
                "---",
                f'title: {json.dumps(f"Source {source_id}", ensure_ascii=False)}',
                f'updated_at: {json.dumps(_now_iso(), ensure_ascii=False)}',
                f'case_id: {json.dumps(case_id, ensure_ascii=False)}',
                f'source_id: {json.dumps(source_id, ensure_ascii=False)}',
                'note_type: "source"',
                "---",
                "",
                f"# Source {source_id}",
                "",
                "## Observed",
                "",
                f"- Kind: {source.kind}",
                f"- Label: {source.label}",
                f"- Origin Path: {source.origin_path or '-'}",
                f"- SHA256: {source.sha256 or '-'}",
                f"- Size: {source.size if source.size is not None else '-'}",
                f"- Parser: {source.parser or '-'}",
                f"- Storage Policy: {source.storage_policy}",
                "",
                "## Inferred",
                "",
                "- This source is available for correlation with derived evidence and timeline records.",
                "",
                "## Unknown",
                "",
                "- Collection context beyond recorded metadata is not yet confirmed.",
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        return path

    def sync_evidence_note(self, store: CaseStore, case_id: str, evidence_id: str) -> Path:
        evidence = store.load_evidence(case_id, evidence_id)
        path = ensure_dir(self.root / case_id / "artifacts") / f"{evidence_id}.md"
        body = "\n".join(
            [
                "---",
                f'title: {json.dumps(f"Artifact {evidence_id}", ensure_ascii=False)}',
                f'updated_at: {json.dumps(_now_iso(), ensure_ascii=False)}',
                f'case_id: {json.dumps(case_id, ensure_ascii=False)}',
                f'artifact_id: {json.dumps(evidence_id, ensure_ascii=False)}',
                'note_type: "evidence"',
                "---",
                "",
                f"# Artifact {evidence_id}",
                "",
                "## Observed",
                "",
                f"- Artifact Type: {evidence.artifact_type}",
                f"- Title: {evidence.title}",
                f"- Summary: {evidence.summary or '-'}",
                f"- Source IDs: {', '.join(evidence.derived_from_source_ids) or '-'}",
                f"- Produced By: {evidence.produced_by or '-'}",
                f"- Observed At: {evidence.observed_at or '-'}",
                "",
                "## Inferred",
                "",
                "- This evidence may describe related activity, but interpretation should remain tied to cited sources.",
                "",
                "## Unknown",
                "",
                "- Scope, operator intent, and excluded alternatives remain unconfirmed.",
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        return path

    def sync_timeline_note(self, store: CaseStore, case_id: str, date_key: str) -> Path:
        entries = [entry for entry in store.read_timeline(case_id) if _timeline_date_key(entry.timestamp) == date_key]
        entries.sort(key=lambda entry: (entry.timestamp, entry.id or ""))
        path = ensure_dir(self.root / case_id / "timelines") / f"{date_key}.md"

        observed_lines = []
        for entry in entries:
            refs = []
            if entry.evidence_ids:
                refs.append(f"evidence={', '.join(entry.evidence_ids)}")
            if entry.source_ids:
                refs.append(f"source={', '.join(entry.source_ids)}")
            observed_lines.extend(
                [
                    f"- {entry.id or '-'} | {entry.timestamp} | {entry.title}",
                    f"  Description: {entry.description or '-'}",
                    f"  Kind: {entry.kind or '-'}",
                    f"  Refs: {'; '.join(refs) or '-'}",
                ]
            )

        body = "\n".join(
            [
                "---",
                f'title: {json.dumps(f"Timeline {date_key}", ensure_ascii=False)}',
                f'updated_at: {json.dumps(_now_iso(), ensure_ascii=False)}',
                f'case_id: {json.dumps(case_id, ensure_ascii=False)}',
                f'timeline_date: {json.dumps(date_key, ensure_ascii=False)}',
                'note_type: "timeline"',
                "---",
                "",
                f"# Timeline {date_key}",
                "",
                "## Observed",
                "",
                *(observed_lines or ["- No entries matched this timeline slice."]),
                "",
                "## Inferred",
                "",
                "- Adjacent timeline entries may describe related activity, but ordering alone is not proof of causation.",
                "",
                "## Unknown",
                "",
                "- Missing artifacts or logging gaps may hide additional activity outside this slice.",
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        return path
