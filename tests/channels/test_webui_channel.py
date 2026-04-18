from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from urllib.parse import quote

import pytest
from aiohttp.test_utils import TestClient, TestServer

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.session.manager import SessionManager
from forensic_claw.session.scopes import build_scoped_session_key


async def _make_client(tmp_path: Path) -> tuple[WebUIChannel, MessageBus, SessionManager, TestClient]:
    bus = MessageBus()
    channel = WebUIChannel(
        {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8765,
            "allowFrom": ["*"],
            "streaming": True,
        },
        bus,
    )
    session_manager = SessionManager(tmp_path)
    channel.bind_runtime(session_manager=session_manager)
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()
    return channel, bus, session_manager, client


def _write_case_fixture(workspace: Path) -> None:
    case_dir = workspace / "forensics" / "cases" / "case-2026-0001"
    (case_dir / "evidence" / "EVD-001" / "files").mkdir(parents=True, exist_ok=True)
    (case_dir / "sources" / "SRC-001" / "raw").mkdir(parents=True, exist_ok=True)

    (case_dir / "manifest.json").write_text(
        json.dumps(
            {
                "id": "case-2026-0001",
                "title": "Windows execution trace case",
                "status": "draft",
                "createdAt": "2026-04-10T10:00:00+09:00",
                "updatedAt": "2026-04-10T10:30:00+09:00",
                "summary": "Prefetch와 source를 묶은 테스트 케이스",
                "tags": ["prefetch", "eventlog"],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (case_dir / "report.md").write_text("# Report\n\n초기 실행 흔적 정리", encoding="utf-8")
    (case_dir / "graph.json").write_text(
        json.dumps(
            {
                "reportSections": [{"id": "sec-1", "title": "Initial Execution", "evidenceIds": ["EVD-001"]}],
                "evidenceLinks": [{"id": "EVD-001", "sourceIds": ["SRC-001"]}],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (case_dir / "evidence" / "EVD-001" / "metadata.json").write_text(
        json.dumps({"kind": "prefetch", "hash": "abc123"}, ensure_ascii=False),
        encoding="utf-8",
    )
    (case_dir / "evidence" / "EVD-001" / "files" / "prefetch.pf").write_text("PFDATA", encoding="utf-8")
    (case_dir / "sources" / "SRC-001" / "metadata.json").write_text(
        json.dumps({"kind": "eventlog", "origin": "Security.evtx"}, ensure_ascii=False),
        encoding="utf-8",
    )
    (case_dir / "sources" / "SRC-001" / "raw" / "Security.evtx").write_text("EVTXDATA", encoding="utf-8")

    wiki_dir = workspace / "wiki" / "cases" / "case-2026-0001" / "artifacts" / "EVD-001"
    wiki_dir.mkdir(parents=True, exist_ok=True)
    (wiki_dir / "20260410-prefetch.md").write_text(
        "\n".join(
            [
                "---",
                'title: "Prefetch Summary"',
                'created_at: "2026-04-10T12:00:00+09:00"',
                'case_id: "case-2026-0001"',
                'artifact_id: "EVD-001"',
                "---",
                "",
                "# Prefetch Summary",
                "",
                "## Final Answer",
                "",
                "실행 흔적을 정리한 note입니다.",
                "",
            ]
        ),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_webui_bootstrap_and_chat_publish_scoped_inbound(tmp_path: Path) -> None:
    channel, bus, _session_manager, client = await _make_client(tmp_path)

    try:
        response = await client.get("/api/bootstrap")
        assert response.status == 200
        bootstrap = await response.json()
        session_id = bootstrap["sessionId"]
        assert session_id.startswith("sess_")
        assert any(item["command"] == "/help" for item in bootstrap["commands"])
        assert any(item["command"] == "/status" for item in bootstrap["commands"])

        response = await client.post(
            "/api/chat",
            json={
                "sessionId": session_id,
                "caseId": "Case Alpha",
                "artifactId": "Prefetch #1",
                "text": "분석 시작",
            },
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["sessionKey"] == "webui:sess_" + session_id.split("sess_", 1)[1] + ":case:Case-Alpha:artifact:Prefetch-1"

        inbound = await asyncio.wait_for(bus.consume_inbound(), timeout=1)
        assert inbound.chat_id == session_id
        assert inbound.metadata["case_id"] == "Case Alpha"
        assert inbound.metadata["artifact_id"] == "Prefetch #1"
        assert inbound.session_key == f"webui:{session_id}:case:Case-Alpha:artifact:Prefetch-1"
        assert channel.supports_streaming is True
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_stop_publishes_priority_message_for_scoped_session(tmp_path: Path) -> None:
    channel, bus, _session_manager, client = await _make_client(tmp_path)

    try:
        response = await client.get("/api/bootstrap")
        assert response.status == 200
        session_id = (await response.json())["sessionId"]

        response = await client.post(
            "/api/stop",
            json={
                "sessionId": session_id,
                "caseId": "Case Alpha",
                "artifactId": "Prefetch #1",
            },
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["sessionKey"] == f"webui:{session_id}:case:Case-Alpha:artifact:Prefetch-1"

        inbound = await asyncio.wait_for(bus.consume_inbound(), timeout=1)
        assert inbound.chat_id == session_id
        assert inbound.content == "/stop"
        assert inbound.metadata["case_id"] == "Case Alpha"
        assert inbound.metadata["artifact_id"] == "Prefetch #1"
        assert inbound.session_key == f"webui:{session_id}:case:Case-Alpha:artifact:Prefetch-1"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_ws_receives_progress_message_and_stream_events(tmp_path: Path) -> None:
    channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        session_id = (await (await client.get("/api/bootstrap")).json())["sessionId"]
        ws = await client.ws_connect(f"/ws?sessionId={session_id}")

        ready = await ws.receive_json()
        assert ready["type"] == "ready"
        assert ready["sessionId"] == session_id

        await channel.send(
            OutboundMessage(
                channel="webui",
                chat_id=session_id,
                content="도구 실행 중",
                metadata={"_progress": True, "_tool_hint": False, "case_id": "Case Alpha"},
            )
        )
        progress = await ws.receive_json()
        assert progress["type"] == "progress"
        assert progress["sessionKey"] == f"webui:{session_id}:case:Case-Alpha"

        await channel.send(
            OutboundMessage(
                channel="webui",
                chat_id=session_id,
                content="최종 응답",
                metadata={
                    "case_id": "Case Alpha",
                    "artifact_id": "EVD-001",
                    "thinking_text": "내부 추론 요약",
                    "_replace_stream_id": "stream-1",
                },
            )
        )
        message = await ws.receive_json()
        assert message["type"] == "message"
        assert message["content"] == "최종 응답"
        assert message["sessionKey"] == f"webui:{session_id}:case:Case-Alpha:artifact:EVD-001"
        assert message["thinkingText"] == "내부 추론 요약"
        assert message["replaceStreamId"] == "stream-1"

        await channel.send_delta(
            session_id,
            "분석",
            {"_stream_id": "stream-1", "case_id": "Case Alpha", "artifact_id": "EVD-001"},
        )
        delta = await ws.receive_json()
        assert delta["type"] == "stream_delta"
        assert delta["content"] == "분석"

        await channel.send_delta(
            session_id,
            "",
            {
                "_stream_id": "stream-1",
                "_stream_end": True,
                "_resuming": False,
                "case_id": "Case Alpha",
                "artifact_id": "EVD-001",
            },
        )
        end = await ws.receive_json()
        assert end["type"] == "stream_end"
        assert end["resuming"] is False

        await ws.close()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_message_can_request_browser_session_reset(tmp_path: Path) -> None:
    channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        session_id = (await (await client.get("/api/bootstrap")).json())["sessionId"]
        ws = await client.ws_connect(f"/ws?sessionId={session_id}")
        await ws.receive_json()

        await channel.send(
            OutboundMessage(
                channel="webui",
                chat_id=session_id,
                content="New session started.",
                metadata={"webui_reset_browser_session": True},
            )
        )
        message = await ws.receive_json()
        assert message["type"] == "message"
        assert message["resetBrowserSession"] is True

        await ws.close()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_ws_receives_shell_trace_and_bootstrap_replays_it(tmp_path: Path) -> None:
    channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        session_id = (await (await client.get("/api/bootstrap")).json())["sessionId"]
        ws = await client.ws_connect(f"/ws?sessionId={session_id}")
        await ws.receive_json()

        await channel.send(
            OutboundMessage(
                channel="webui",
                chat_id=session_id,
                content="",
                metadata={
                    "_shell_trace": True,
                    "case_id": "Case Alpha",
                    "artifact_id": "EVD-001",
                    "shell_trace": {
                        "traceId": "call_exec_1",
                        "phase": "start",
                        "status": "running",
                        "command": "Get-Date",
                        "workingDir": str(tmp_path),
                        "timeout": 30,
                        "shell": "powershell",
                        "launcher": "powershell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <base64>",
                    },
                },
            )
        )

        trace_event = await ws.receive_json()
        assert trace_event["type"] == "shell_trace"
        assert trace_event["trace"]["command"] == "Get-Date"
        assert trace_event["sessionKey"] == f"webui:{session_id}:case:Case-Alpha:artifact:EVD-001"

        bootstrap = await (await client.get("/api/bootstrap", params={"sessionId": session_id})).json()
        assert bootstrap["shellTraces"][0]["trace"]["traceId"] == "call_exec_1"
        assert bootstrap["shellTraces"][0]["trace"]["status"] == "running"

        await ws.close()
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_bootstrap_reset_rotates_browser_session_and_clears_shell_traces(tmp_path: Path) -> None:
    channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        initial_bootstrap = await (await client.get("/api/bootstrap")).json()
        session_id = initial_bootstrap["sessionId"]

        await channel.send(
            OutboundMessage(
                channel="webui",
                chat_id=session_id,
                content="",
                metadata={
                    "_shell_trace": True,
                    "shell_trace": {
                        "traceId": "call_exec_1",
                        "phase": "start",
                        "status": "running",
                        "command": "Get-Date",
                    },
                },
            )
        )

        reset_bootstrap = await (
            await client.get("/api/bootstrap", params={"reset": "1", "sessionId": session_id})
        ).json()
        assert reset_bootstrap["sessionId"] != session_id
        assert reset_bootstrap["shellTraces"] == []
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_sessions_api_filters_to_browser_session(tmp_path: Path) -> None:
    _channel, _bus, session_manager, client = await _make_client(tmp_path)

    try:
        key_a = build_scoped_session_key("webui", "browser-a", case_id="Case Alpha")
        session_a = session_manager.get_or_create(key_a)
        session_a.add_message("user", "u1")
        session_a.add_message("assistant", "a1", reasoning_content="숨겨진 생각")
        session_manager.save(session_a)

        key_b = build_scoped_session_key("webui", "browser-b", case_id="Case Beta")
        session_b = session_manager.get_or_create(key_b)
        session_b.add_message("user", "u2")
        session_manager.save(session_b)

        response = await client.get("/api/sessions", params={"sessionId": "browser-a"})
        assert response.status == 200
        data = await response.json()
        assert [item["key"] for item in data["sessions"]] == [key_a]
        assert data["sessions"][0]["caseId"] == "Case-Alpha"

        encoded_key = quote(key_a, safe="")
        response = await client.get(f"/api/sessions/{encoded_key}", params={"sessionId": "browser-a"})
        assert response.status == 200
        detail = await response.json()
        assert detail["session"]["key"] == key_a
        assert detail["session"]["messages"][0]["content"] == "u1"
        assert detail["session"]["messages"][1]["thinkingText"] == "숨겨진 생각"

        forbidden = await client.get(f"/api/sessions/{encoded_key}", params={"sessionId": "browser-b"})
        assert forbidden.status == 404
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_case_and_wiki_read_only_apis(tmp_path: Path) -> None:
    _write_case_fixture(tmp_path)
    _channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        bootstrap = await (await client.get("/api/bootstrap")).json()
        assert bootstrap["workspace"]["hasCases"] is True
        assert bootstrap["workspace"]["hasWiki"] is True

        response = await client.get("/api/cases")
        assert response.status == 200
        cases = await response.json()
        assert cases["cases"][0]["id"] == "case-2026-0001"
        assert cases["cases"][0]["evidenceCount"] == 1

        response = await client.get("/api/cases/case-2026-0001")
        detail = await response.json()
        assert detail["case"]["manifest"]["title"] == "Windows execution trace case"
        assert detail["case"]["evidenceIds"] == ["EVD-001"]
        assert detail["case"]["sourceIds"] == ["SRC-001"]

        response = await client.get("/api/cases/case-2026-0001/report")
        report = await response.json()
        assert "초기 실행 흔적" in report["content"]

        response = await client.get("/api/cases/case-2026-0001/graph")
        graph = await response.json()
        assert graph["graph"]["evidenceLinks"][0]["sourceIds"] == ["SRC-001"]

        response = await client.get("/api/cases/case-2026-0001/evidence/EVD-001")
        evidence = await response.json()
        assert evidence["metadata"]["kind"] == "prefetch"
        assert evidence["files"] == ["prefetch.pf"]

        response = await client.get("/api/cases/case-2026-0001/sources/SRC-001")
        source = await response.json()
        assert source["metadata"]["origin"] == "Security.evtx"
        assert source["files"] == ["Security.evtx"]

        response = await client.get(
            "/api/wiki",
            params={"sessionId": "browser-a", "caseId": "case-2026-0001", "artifactId": "EVD-001"},
        )
        notes = await response.json()
        assert notes["notes"][0]["title"] == "Prefetch Summary"

        note_id = notes["notes"][0]["id"]
        response = await client.get(f"/api/wiki/{quote(note_id, safe='')}")
        note = await response.json()
        assert note["note"]["metadata"]["artifact_id"] == "EVD-001"
        assert "실행 흔적을 정리한 note입니다." in note["note"]["content"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_rejects_note_traversal_and_missing_case(tmp_path: Path) -> None:
    _channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        response = await client.get("/api/cases/missing-case")
        assert response.status == 404

        bad_note_id = base64.urlsafe_b64encode(b"../outside.md").decode("ascii").rstrip("=")
        response = await client.get(f"/api/wiki/{quote(bad_note_id, safe='')}")
        assert response.status == 404

        response = await client.get("/api/cases/case-1/evidence/..")
        assert response.status == 404
    finally:
        await client.close()
