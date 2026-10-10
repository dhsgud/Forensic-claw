"""Read bounded Windows artifact records without mounting or modifying original evidence."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def event_records(xml: str, *, limit: int = 10000) -> list[tuple[str, dict[str, Any]]]:
    root = ET.fromstring(xml)
    records = []
    for event in root.iter():
        if event.tag.rsplit("}", 1)[-1] != "Event":
            continue
        values, timestamp = {}, None
        for element in event.iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag == "TimeCreated":
                timestamp = element.get("SystemTime")
            elif tag == "Provider":
                values["Provider"] = element.get("Name", "")
            elif tag == "Data":
                values[element.get("Name") or "Data"] = element.text or ""
            elif tag in {"EventID", "EventRecordID", "Computer", "Channel"}:
                values[tag] = element.text or ""
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00")) if timestamp else None
        if parsed is not None and parsed.utcoffset() is None:
            raise ValueError("Event timestamp must include timezone")
        time = parsed.astimezone(UTC).isoformat() if parsed else None
        text = "Windows Event Record\n" + "\n".join(
            f"{key}: {value}" for key, value in values.items()
        )
        if time:
            text += f"\nEvent Timestamp UTC: {time}"
        records.append(
            (
                text,
                {
                    "eventTimestamp": time,
                    "recordId": values.get("EventRecordID"),
                    "eventValues": values,
                },
            )
        )
        if len(records) >= limit:
            break
    return records


def read_artifact(path: Path, *, limit: int = 10000) -> list[tuple[str, dict[str, Any]]] | None:
    if path.suffix.lower() == ".xml":
        return event_records(path.read_text(encoding="utf-8-sig"), limit=limit) or None
    if path.suffix.lower() == ".evtx":
        if sys.platform != "win32":
            raise ValueError(
                "Native EVTX input requires Windows; export Event XML on other platforms"
            )
        escaped = str(path).replace("'", "''")
        script = (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            f"$events=Get-WinEvent -Path '{escaped}' -MaxEvents {int(limit)} -ErrorAction Stop;"
            "'<Events>';foreach($event in $events){$event.ToXml()};'</Events>'"
        )
        command = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
            capture_output=True,
            timeout=60,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode:
            raise ValueError(result.stderr.decode("utf-8", errors="replace"))
        return event_records(result.stdout.decode("utf-8-sig"), limit=limit)
    with path.open("rb") as handle:
        header = handle.read(4)
    if header == b"regf":
        return _hive_records(path, limit=limit)
    return None


def _hive_records(path: Path, *, limit: int) -> list[tuple[str, dict[str, Any]]]:
    if sys.platform != "win32":
        raise ValueError(
            "Native registry hive input requires Windows; export .reg text on other platforms"
        )
    import ctypes
    import shutil
    import winreg
    from ctypes import wintypes

    loader = ctypes.WinDLL("advapi32").RegLoadAppKeyW
    loader.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    loader.restype = wintypes.LONG
    records = []
    with tempfile.TemporaryDirectory(prefix="fc-hive-") as temporary:
        copied = Path(temporary) / "hive"
        shutil.copy2(path, copied)
        handle = wintypes.HANDLE()
        error = loader(str(copied), ctypes.byref(handle), winreg.KEY_READ, 1, 0)
        if error:
            raise OSError(error, "Cannot open registry hive read-only")
        pending = [(winreg.HKEYType(handle.value), "", 0)]
        processed = 0
        try:
            while pending and len(records) < limit and processed < limit:
                key, name, depth = pending.pop()
                processed += 1
                with key:
                    subkeys, values, written = winreg.QueryInfoKey(key)
                    timestamp = (
                        datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=written // 10)
                    ).isoformat()
                    for index in range(min(values, limit - len(records))):
                        value_name, value, type = winreg.EnumValue(key, index)
                        if isinstance(value, bytes):
                            value = value.hex()
                        text = f"Registry Key: {name or '(root)'}\nValue: {value_name or '(default)'}\nType: {type}\nData: {json.dumps(value, ensure_ascii=False)}\nKey Last Written UTC: {timestamp}"
                        records.append(
                            (
                                text,
                                {
                                    "registryKey": name,
                                    "timestamp": timestamp,
                                    "timestampKind": "registry_key_last_written",
                                },
                            )
                        )
                    if depth < 64:
                        for index in range(min(subkeys, max(0, limit - processed - len(pending)))):
                            child = winreg.EnumKey(key, index)
                            pending.append(
                                (
                                    winreg.OpenKey(key, child, access=winreg.KEY_READ),
                                    name + "\\" + child,
                                    depth + 1,
                                )
                            )
        finally:
            for key, _, _ in pending:
                key.Close()
    return records
