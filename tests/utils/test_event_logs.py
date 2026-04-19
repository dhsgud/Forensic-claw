from __future__ import annotations

from forensic_claw.utils.event_logs import (
    compact_windows_event_log_output,
    format_dual_timestamp,
    parse_windows_event_blocks,
)

RAW_EVENTS = """Event[0]
  Log Name: System
  Source: EventLog
  Date: 2025-12-28T21:22:32.7910000Z
  Event ID: 6011
  Level: 정보
  Computer: WIN-TEST
  Description:
이 컴퓨터의 NetBIOS 이름이 WIN-TEST로 변경되었습니다.

Event[1]
  Log Name: System
  Source: Microsoft-Windows-Kernel-Boot
  Date: 2025-12-28T21:22:06.7140000Z
  Event ID: 247
  Level: 정보
  Computer: WIN-TEST
  Description:
Windows 펌웨어를 로드할 수 없습니다. StatusCode: STATUS_SUCCESS
"""


def test_format_dual_timestamp_renders_utc_and_kst() -> None:
    rendered = format_dual_timestamp("2025-12-28T21:22:32.7910000Z")

    assert rendered == "UTC 2025-12-28 21:22:32Z | KST 2025-12-29 06:22:32 UTC+09:00"


def test_parse_windows_event_blocks_reads_description() -> None:
    events = parse_windows_event_blocks(RAW_EVENTS)

    assert len(events) == 2
    assert events[0]["Event ID"] == "6011"
    assert "NetBIOS" in events[0]["Description"]
    assert events[1]["Source"] == "Microsoft-Windows-Kernel-Boot"


def test_compact_windows_event_log_output_summarizes_events() -> None:
    compacted = compact_windows_event_log_output(RAW_EVENTS)

    assert compacted is not None
    assert "Windows Event Log Summary" in compacted
    assert "Events parsed: 2" in compacted
    assert "UTC 2025-12-28 21:22:32Z | KST 2025-12-29 06:22:32 UTC+09:00" in compacted
    assert "Top event IDs: 6011 x1, 247 x1" in compacted
    assert "NetBIOS" in compacted
    assert "Event[0]" not in compacted
