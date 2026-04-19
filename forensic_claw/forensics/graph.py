"""Report graph helpers."""

from __future__ import annotations

import json
from pathlib import Path

from forensic_claw.forensics.models import ReportGraph


def empty_report_graph() -> ReportGraph:
    return ReportGraph()


def read_report_graph(path: Path) -> ReportGraph:
    if not path.exists() or not path.is_file():
        return empty_report_graph()

    raw = path.read_text(encoding="utf-8")
    if not raw.strip():
        return empty_report_graph()

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return empty_report_graph()

    if not isinstance(payload, dict):
        return empty_report_graph()
    return ReportGraph.from_dict(payload)


def write_report_graph(path: Path, graph: ReportGraph) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(graph.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
