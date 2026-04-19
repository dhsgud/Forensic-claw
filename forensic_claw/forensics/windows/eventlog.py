"""Windows event log query and ingest helpers."""

from __future__ import annotations

import asyncio
import platform
from datetime import datetime
from typing import Awaitable, Callable

from forensic_claw.forensics.store import CaseStore
from forensic_claw.forensics.windows.models import ArtifactUpdateResult, EventLogRecord
from forensic_claw.utils.event_logs import (
    compact_windows_event_log_output,
    parse_windows_event_blocks,
)

EventLogRunner = Callable[..., Awaitable[str]]


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _utc_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    return dt.astimezone().isoformat()


def parse_eventlog_records(text: str) -> list[EventLogRecord]:
    records: list[EventLogRecord] = []
    for event in parse_windows_event_blocks(text):
        timestamp = event.get("Date")
        log_name = event.get("Log Name")
        source = event.get("Source")
        event_id = event.get("Event ID")
        if not all(
            isinstance(value, str) and value for value in (timestamp, log_name, source, event_id)
        ):
            continue
        records.append(
            EventLogRecord(
                timestamp=timestamp,
                log_name=log_name,
                source=source,
                event_id=event_id,
                level=event.get("Level") if isinstance(event.get("Level"), str) else None,
                computer=event.get("Computer") if isinstance(event.get("Computer"), str) else None,
                description=event.get("Description")
                if isinstance(event.get("Description"), str)
                else None,
            )
        )
    return records


async def run_windows_eventlog_query(
    *,
    log_name: str,
    event_ids: list[int] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    max_events: int = 50,
    runner: EventLogRunner | None = None,
) -> str:
    if runner is not None:
        return await runner(
            log_name=log_name,
            event_ids=event_ids or [],
            start_time=start_time,
            end_time=end_time,
            max_events=max_events,
        )

    if platform.system() != "Windows":
        raise RuntimeError(
            "windows_eventlog_query requires Windows when no runner override is provided"
        )

    filters = [f"LogName = {_ps_quote(log_name)}"]
    if event_ids:
        ids = ", ".join(str(int(event_id)) for event_id in event_ids)
        filters.append(f"Id = @({ids})")
    if start_time:
        filters.append(f"StartTime = [datetime]{_ps_quote(_utc_or_none(start_time) or start_time)}")
    if end_time:
        filters.append(f"EndTime = [datetime]{_ps_quote(_utc_or_none(end_time) or end_time)}")

    script = "\n".join(
        [
            f"$filter = @{{ {'; '.join(filters)} }}",
            f"$events = Get-WinEvent -FilterHashtable $filter -MaxEvents {int(max_events)}",
            "$i = 1",
            "foreach ($event in $events) {",
            '  Write-Output "Event[$i]"',
            '  Write-Output "  Log Name: $($event.LogName)"',
            '  Write-Output "  Source: $($event.ProviderName)"',
            '  Write-Output "  Date: $($event.TimeCreated.ToString(\\"o\\"))"',
            '  Write-Output "  Event ID: $($event.Id)"',
            '  Write-Output "  Task: $($event.TaskDisplayName)"',
            '  Write-Output "  Level: $($event.LevelDisplayName)"',
            '  Write-Output "  Opcode: $($event.OpcodeDisplayName)"',
            '  Write-Output "  Keyword: $([string]::Join(\\", \\", $event.KeywordsDisplayNames))"',
            '  Write-Output "  User: $($event.UserId)"',
            '  Write-Output "  Computer: $($event.MachineName)"',
            '  Write-Output "  Description: $($event.FormatDescription())"',
            "  Write-Output ''",
            "  $i++",
            "}",
        ]
    )

    process = await asyncio.create_subprocess_exec(
        "powershell",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        script,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        raise RuntimeError(
            stderr.decode("utf-8", errors="replace").strip() or "Get-WinEvent failed"
        )
    return stdout.decode("utf-8", errors="replace")


def ingest_eventlog_query_output(
    store: CaseStore,
    *,
    case_id: str,
    log_name: str,
    query_output: str,
    event_ids: list[int] | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    max_events: int | None = None,
) -> ArtifactUpdateResult:
    records = parse_eventlog_records(query_output)
    if not records:
        raise ValueError("No structured Windows event records were parsed")

    source = store.add_source(
        case_id,
        kind="eventlog",
        content=query_output,
        filename=f"{log_name.lower()}-events.txt",
        label=f"{log_name} event log query",
        parser="windows_eventlog_query",
        notes=(
            f"event_ids={event_ids or []}, start_time={start_time or '-'}, "
            f"end_time={end_time or '-'}, max_events={max_events or len(records)}"
        ),
    )
    summary_text = (
        compact_windows_event_log_output(query_output) or f"{len(records)} {log_name} events"
    )
    evidence = store.add_evidence(
        case_id,
        artifact_type="eventlog-query",
        title=f"{log_name} event log summary",
        summary=summary_text,
        source_ids=[source.id or ""],
        produced_by="windows_eventlog_query",
        observed_at=records[0].timestamp,
        tags=["eventlog", log_name.lower()],
    )

    timeline_entries = []
    for record in records:
        description_parts = [f"Source={record.source}", f"EventID={record.event_id}"]
        if record.level:
            description_parts.append(f"Level={record.level}")
        if record.computer:
            description_parts.append(f"Computer={record.computer}")
        if record.description:
            description_parts.append(record.description.strip())
        timeline_entries.append(
            store.add_timeline_entry(
                case_id,
                timestamp=record.timestamp,
                title=f"{record.log_name} event {record.event_id}",
                description=" | ".join(part for part in description_parts if part),
                evidence_ids=[evidence.id or ""],
                source_ids=[source.id or ""],
                kind="eventlog",
            )
        )

    store.update_report_graph(
        case_id,
        report_section_id="windows-eventlog",
        report_section_title="Windows Event Log",
        evidence_ids=[evidence.id or ""],
        source_ids=[source.id or ""],
        timeline_ids=[entry.id or "" for entry in timeline_entries],
    )
    return ArtifactUpdateResult(
        source=source,
        evidence=evidence,
        timeline_entries=timeline_entries,
        summary=summary_text,
    )
