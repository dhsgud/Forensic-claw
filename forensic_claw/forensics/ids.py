"""Stable identifier generation for forensic case storage."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

_CASE_RE = re.compile(r"^case-(\d{4})-(\d{4})$")
_SOURCE_RE = re.compile(r"^SRC-(\d{3})$")
_EVIDENCE_RE = re.compile(r"^EVD-(\d{3})$")
_TIMELINE_RE = re.compile(r"^TLN-(\d{3})$")


def _now_year() -> int:
    return datetime.now().astimezone().year


def _next_sequence(names: list[str], pattern: re.Pattern[str]) -> int:
    highest = 0
    for name in names:
        match = pattern.match(name)
        if not match:
            continue
        highest = max(highest, int(match.group(match.lastindex or 1)))
    return highest + 1


def _directory_names(path: Path) -> list[str]:
    if not path.exists() or not path.is_dir():
        return []
    return [child.name for child in path.iterdir() if child.is_dir()]


def next_case_id(cases_root: Path, *, year: int | None = None) -> str:
    target_year = year or _now_year()
    highest = 0
    for name in _directory_names(cases_root):
        match = _CASE_RE.match(name)
        if not match or int(match.group(1)) != target_year:
            continue
        highest = max(highest, int(match.group(2)))
    return f"case-{target_year:04d}-{highest + 1:04d}"


def next_source_id(case_dir: Path) -> str:
    sequence = _next_sequence(_directory_names(case_dir / "sources"), _SOURCE_RE)
    return f"SRC-{sequence:03d}"


def next_evidence_id(case_dir: Path) -> str:
    sequence = _next_sequence(_directory_names(case_dir / "evidence"), _EVIDENCE_RE)
    return f"EVD-{sequence:03d}"


def next_timeline_id(timeline_path: Path) -> str:
    highest = 0
    if timeline_path.exists():
        for raw_line in timeline_path.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            try:
                payload = json.loads(raw_line)
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, dict):
                continue
            entry_id = payload.get("id")
            if not isinstance(entry_id, str):
                continue
            match = _TIMELINE_RE.match(entry_id)
            if not match:
                continue
            highest = max(highest, int(match.group(1)))
    return f"TLN-{highest + 1:03d}"
