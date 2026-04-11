"""Helpers for compacting Windows event log output."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import re
from typing import Any
from zoneinfo import ZoneInfo

_EVENT_START_RE = re.compile(r"^Event\[(\d+)\]\s*$")
_FIELD_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _-]+):\s*(.*)$")
_KNOWN_FIELDS = {
    "Log Name",
    "Source",
    "Date",
    "Event ID",
    "Task",
    "Level",
    "Opcode",
    "Keyword",
    "User",
    "User Name",
    "Computer",
    "Description",
}
_INLINE_WHITESPACE_RE = re.compile(r"\s+")
_ISO_TS_RE = re.compile(
    r"(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?P<frac>\.\d{1,9})?(?P<tz>Z|[+-]\d{2}:\d{2})$"
)


def looks_like_windows_event_log_output(text: str | None) -> bool:
    """Return whether *text* resembles PowerShell-formatted Windows event logs."""
    if not text:
        return False
    return bool(re.search(r"^Event\[\d+\]\s*$", text, flags=re.MULTILINE)) and "Log Name:" in text and "Event ID:" in text


def parse_event_log_timestamp(raw: str | None) -> datetime | None:
    """Parse Windows event-log timestamps with flexible fractional precision."""
    if not raw:
        return None
    value = raw.strip()
    match = _ISO_TS_RE.search(value)
    if not match:
        return None

    base = match.group("base")
    frac = match.group("frac") or ""
    tz = match.group("tz")
    if frac:
        frac = "." + frac[1:7]
    iso_value = f"{base}{frac}{'+00:00' if tz == 'Z' else tz}"
    try:
        return datetime.fromisoformat(iso_value)
    except ValueError:
        return None


def format_dual_timestamp(raw: str | None, *, local_timezone: str = "Asia/Seoul") -> str | None:
    """Format a timestamp in both UTC and a local timezone."""
    parsed = parse_event_log_timestamp(raw)
    if parsed is None:
        return None

    utc_dt = parsed.astimezone(timezone.utc)
    local_dt = parsed.astimezone(ZoneInfo(local_timezone))
    local_name = "KST" if local_timezone == "Asia/Seoul" else local_timezone
    return (
        f"UTC {utc_dt.strftime('%Y-%m-%d %H:%M:%S')}Z"
        f" | {local_name} {local_dt.strftime('%Y-%m-%d %H:%M:%S')} UTC{local_dt.strftime('%z')[:3]}:{local_dt.strftime('%z')[3:]}"
    )


def parse_windows_event_blocks(text: str) -> list[dict[str, Any]]:
    """Parse custom-formatted Windows event blocks into structured dictionaries."""
    events: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    description_lines: list[str] = []
    in_description = False

    def _flush() -> None:
        nonlocal current, description_lines, in_description
        if not current:
            return
        description = "\n".join(description_lines).strip()
        if description:
            current["Description"] = description
        events.append(current)
        current = None
        description_lines = []
        in_description = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        event_match = _EVENT_START_RE.match(line.strip())
        if event_match:
            _flush()
            current = {"index": int(event_match.group(1))}
            continue

        if current is None:
            continue

        if in_description:
            description_lines.append(line)
            continue

        field_match = _FIELD_RE.match(line)
        if not field_match:
            continue

        key = field_match.group(1).strip()
        value = field_match.group(2).strip()
        if key not in _KNOWN_FIELDS:
            continue

        if key == "Description":
            in_description = True
            if value:
                description_lines.append(value)
            continue

        current[key] = value

    _flush()
    return events


def _compact_description(text: str | None, *, max_len: int = 180) -> str:
    if not text:
        return ""
    collapsed = _INLINE_WHITESPACE_RE.sub(" ", text).strip()
    if len(collapsed) <= max_len:
        return collapsed
    return collapsed[: max_len - 3].rstrip() + "..."


def _counter_line(counter: Counter[str], *, limit: int = 4) -> str:
    parts = [f"{name} x{count}" for name, count in counter.most_common(limit) if name]
    return ", ".join(parts) if parts else "-"


def compact_windows_event_log_output(
    text: str | None,
    *,
    local_timezone: str = "Asia/Seoul",
    detail_limit: int = 8,
) -> str | None:
    """Turn verbose Windows event dumps into a compact, timestamp-normalized summary."""
    if not text or not looks_like_windows_event_log_output(text):
        return None

    events = parse_windows_event_blocks(text)
    if not events:
        return None

    level_counts = Counter(event.get("Level", "") for event in events)
    source_counts = Counter(event.get("Source", "") for event in events)
    event_id_counts = Counter(event.get("Event ID", "") for event in events)

    dated_events = [
        (parse_event_log_timestamp(event.get("Date")), event)
        for event in events
        if event.get("Date")
    ]
    dated_events = [(dt, event) for dt, event in dated_events if dt is not None]

    lines = [
        "Windows Event Log Summary",
        f"Events parsed: {len(events)}",
        "Timestamps normalized: UTC + KST (UTC+09:00)",
    ]

    if dated_events:
        newest = max(dated_events, key=lambda item: item[0])[1]
        oldest = min(dated_events, key=lambda item: item[0])[1]
        lines.extend(
            [
                f"Newest: {format_dual_timestamp(newest.get('Date'), local_timezone=local_timezone) or newest.get('Date')}",
                f"Oldest: {format_dual_timestamp(oldest.get('Date'), local_timezone=local_timezone) or oldest.get('Date')}",
            ]
        )

    lines.extend(
        [
            f"Levels: {_counter_line(level_counts)}",
            f"Top sources: {_counter_line(source_counts)}",
            f"Top event IDs: {_counter_line(event_id_counts)}",
            "",
            f"Detailed events (showing {min(len(events), detail_limit)} of {len(events)}):",
        ]
    )

    for offset, event in enumerate(events[:detail_limit], start=1):
        when = format_dual_timestamp(event.get("Date"), local_timezone=local_timezone) or event.get("Date") or "-"
        log_name = event.get("Log Name") or "-"
        source = event.get("Source") or "-"
        event_id = event.get("Event ID") or "-"
        level = event.get("Level") or "-"
        computer = event.get("Computer") or "-"
        description = _compact_description(event.get("Description"))

        lines.append(f"[{offset}] {when}")
        lines.append(f"  Log={log_name} | Source={source} | EventID={event_id} | Level={level}")
        lines.append(f"  Computer={computer}")
        if description:
            lines.append(f"  Description={description}")
        lines.append("")

    omitted = len(events) - detail_limit
    if omitted > 0:
        lines.append(
            f"{omitted} more events omitted. Narrow by time window, source, level, or Event ID for a deeper scan."
        )

    return "\n".join(lines).strip()
