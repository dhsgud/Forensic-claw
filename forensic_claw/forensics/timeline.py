"""Timeline serialization helpers."""

from __future__ import annotations

import json
from pathlib import Path

from forensic_claw.forensics.models import TimelineEntry


def read_timeline_entries(path: Path) -> list[TimelineEntry]:
    if not path.exists() or not path.is_file():
        return []

    entries: list[TimelineEntry] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if not raw_line.strip():
            continue
        payload = json.loads(raw_line)
        if not isinstance(payload, dict):
            raise ValueError("Timeline entries must be JSON objects")
        entries.append(TimelineEntry.from_dict(payload))
    return entries


def append_timeline_entry(path: Path, entry: TimelineEntry) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = json.dumps(entry.to_dict(), ensure_ascii=False)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(serialized + "\n")
