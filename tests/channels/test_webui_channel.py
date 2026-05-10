from __future__ import annotations

import asyncio
import json
import struct
from pathlib import Path
from urllib.parse import quote

import pytest
from aiohttp import FormData
from aiohttp.test_utils import TestClient, TestServer

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.config.schema import KnowledgeConfig
from forensic_claw.knowledge.service import KnowledgeService
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


class FakeModelSettings:
    def __init__(self) -> None:
        self.applied: list[dict] = []
        self.tested: list[dict] = []
        self._snapshot = {
            "provider": "custom",
            "providerLabel": "Custom",
            "model": "local-model",
            "apiBase": "http://127.0.0.1:1234/v1",
            "availableProviders": [{"name": "custom", "label": "Custom", "defaultApiBase": ""}],
        }

    def snapshot(self) -> dict:
        return dict(self._snapshot)

    async def apply(self, **kwargs) -> dict:
        self.applied.append(kwargs)
        if kwargs.get("provider"):
            self._snapshot["provider"] = kwargs["provider"]
        if kwargs.get("model"):
            self._snapshot["model"] = kwargs["model"]
        if kwargs.get("api_base") is not None:
            self._snapshot["apiBase"] = kwargs["api_base"]
        return self.snapshot()

    async def test_connection(self, **kwargs) -> dict:
        self.tested.append(kwargs)
        return {
            "ok": True,
            "apiBase": kwargs.get("api_base") or self._snapshot["apiBase"],
            "status": 200,
            "models": [self._snapshot["model"]],
        }


class FakeKnowledgeSettings:
    def __init__(self, service=None) -> None:
        self.service = service
        self.applied: list[dict] = []
        self.tested: list[dict] = []
        self._snapshot = {
            "enabled": True,
            "backend": "sqlite",
            "storeDir": "knowledge",
            "chunkChars": 6000,
            "chunkOverlapChars": 400,
            "maxFileBytes": 268435456,
            "maxChromeRows": 10000,
            "neo4j": {
                "enabled": True,
                "uri": "bolt://127.0.0.1:7687",
                "username": "neo4j",
                "database": "neo4j",
                "passwordConfigured": False,
                "status": {"enabled": True, "state": "unavailable"},
            },
            "helix": {
                "enabled": False,
                "local": True,
                "port": 6969,
                "apiEndpoint": "",
                "fallbackToSqlite": True,
                "status": {"enabled": False, "state": "disabled"},
            },
        }

    def snapshot(self) -> dict:
        return json.loads(json.dumps(self._snapshot))

    def apply(self, **kwargs) -> dict:
        self.applied.append(kwargs)
        if kwargs.get("enabled") is not None:
            self._snapshot["enabled"] = kwargs["enabled"]
        if kwargs.get("backend") is not None:
            self._snapshot["backend"] = kwargs["backend"]
        if kwargs.get("store_dir") is not None:
            self._snapshot["storeDir"] = kwargs["store_dir"]
        helix = self._snapshot["helix"]
        if kwargs.get("helix_enabled") is not None:
            helix["enabled"] = kwargs["helix_enabled"]
        if kwargs.get("helix_local") is not None:
            helix["local"] = kwargs["helix_local"]
        if kwargs.get("helix_port") is not None:
            helix["port"] = kwargs["helix_port"]
        if kwargs.get("helix_api_endpoint") is not None:
            helix["apiEndpoint"] = kwargs["helix_api_endpoint"]
        if kwargs.get("helix_fallback_to_sqlite") is not None:
            helix["fallbackToSqlite"] = kwargs["helix_fallback_to_sqlite"]
        helix["status"] = {"enabled": helix["enabled"], "state": "configured"}
        neo4j = self._snapshot["neo4j"]
        if kwargs.get("neo4j_enabled") is not None:
            neo4j["enabled"] = kwargs["neo4j_enabled"]
        if kwargs.get("uri") is not None:
            neo4j["uri"] = kwargs["uri"]
        if kwargs.get("username") is not None:
            neo4j["username"] = kwargs["username"]
        if kwargs.get("database") is not None:
            neo4j["database"] = kwargs["database"]
        if kwargs.get("password_supplied"):
            neo4j["passwordConfigured"] = bool(kwargs.get("password"))
        neo4j["status"] = {"enabled": neo4j["enabled"], "state": "connected", "uri": neo4j["uri"]}
        return self.snapshot()

    def test_connection(self, **kwargs) -> dict:
        self.tested.append(kwargs)
        if kwargs.get("backend") == "helix":
            return {
                "enabled": kwargs.get("helix_enabled"),
                "state": "configured",
                "port": kwargs.get("helix_port") or 6969,
            }
        return {
            "enabled": kwargs.get("enabled"),
            "state": "connected",
            "uri": kwargs.get("uri") or self._snapshot["neo4j"]["uri"],
        }


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


def _knowledge_config() -> KnowledgeConfig:
    return KnowledgeConfig(neo4j={"enabled": False}, chunk_chars=1000, chunk_overlap_chars=0)


@pytest.mark.asyncio
async def test_webui_model_config_api_returns_and_updates_runtime_settings(tmp_path: Path) -> None:
    bus = MessageBus()
    channel = WebUIChannel(
        {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8765,
            "allowFrom": ["*"],
        },
        bus,
    )
    model_settings = FakeModelSettings()
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        model_settings=model_settings,
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        response = await client.get("/api/model-config")
        assert response.status == 200
        payload = await response.json()
        assert payload["modelConfig"]["apiBase"] == "http://127.0.0.1:1234/v1"

        response = await client.patch(
            "/api/model-config",
            json={
                "provider": "custom",
                "model": "other-local-model",
                "apiBase": "http://127.0.0.1:11434/v1",
            },
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["modelConfig"]["model"] == "other-local-model"
        assert model_settings.applied == [
            {
                "provider": "custom",
                "model": "other-local-model",
                "api_base": "http://127.0.0.1:11434/v1",
                "api_base_supplied": True,
            }
        ]

        response = await client.post(
            "/api/model-config/test",
            json={"apiBase": "http://127.0.0.1:11434/v1"},
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["result"]["models"] == ["other-local-model"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_knowledge_config_api_returns_updates_and_tests_runtime_settings(
    tmp_path: Path,
) -> None:
    bus = MessageBus()
    channel = WebUIChannel(
        {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8765,
            "allowFrom": ["*"],
        },
        bus,
    )
    knowledge_settings = FakeKnowledgeSettings()
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=knowledge_settings,
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        response = await client.get("/api/knowledge-config")
        assert response.status == 200
        payload = await response.json()
        assert payload["knowledgeConfig"]["neo4j"]["uri"] == "bolt://127.0.0.1:7687"

        response = await client.patch(
            "/api/knowledge-config",
            json={
                "enabled": True,
                "storeDir": "knowledge-live",
                "neo4jEnabled": True,
                "uri": "bolt://127.0.0.1:7688",
                "username": "neo4j",
                "password": "secret",
                "database": "forensic",
            },
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["knowledgeConfig"]["storeDir"] == "knowledge-live"
        assert payload["knowledgeConfig"]["neo4j"]["passwordConfigured"] is True
        assert knowledge_settings.applied == [
            {
                "enabled": True,
                "backend": None,
                "store_dir": "knowledge-live",
                "neo4j_enabled": True,
                "uri": "bolt://127.0.0.1:7688",
                "username": "neo4j",
                "password": "secret",
                "password_supplied": True,
                "database": "forensic",
                "helix_enabled": None,
                "helix_local": None,
                "helix_port": None,
                "helix_api_endpoint": None,
                "helix_fallback_to_sqlite": None,
            }
        ]

        response = await client.post(
            "/api/knowledge-config/test",
            json={"neo4jEnabled": True, "uri": "bolt://127.0.0.1:7688"},
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["result"]["state"] == "connected"
        assert knowledge_settings.tested == [
            {
                "enabled": True,
                "backend": None,
                "uri": "bolt://127.0.0.1:7688",
                "username": None,
                "password": None,
                "password_supplied": False,
                "database": None,
                "helix_enabled": None,
                "helix_local": None,
                "helix_port": None,
                "helix_api_endpoint": None,
            }
        ]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_knowledge_config_api_updates_and_tests_helix_backend(
    tmp_path: Path,
) -> None:
    bus = MessageBus()
    channel = WebUIChannel(
        {
            "enabled": True,
            "host": "127.0.0.1",
            "port": 8765,
            "allowFrom": ["*"],
        },
        bus,
    )
    knowledge_settings = FakeKnowledgeSettings()
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=knowledge_settings,
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        response = await client.patch(
            "/api/knowledge-config",
            json={
                "enabled": True,
                "backend": "helix",
                "helixEnabled": True,
                "helixPort": 6969,
                "helixApiEndpoint": "",
                "helixFallbackToSqlite": True,
            },
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["knowledgeConfig"]["backend"] == "helix"
        assert payload["knowledgeConfig"]["helix"]["enabled"] is True
        assert knowledge_settings.applied[-1]["backend"] == "helix"
        assert knowledge_settings.applied[-1]["helix_enabled"] is True

        response = await client.post(
            "/api/knowledge-config/test",
            json={"backend": "helix", "helixEnabled": True, "helixPort": 6969},
        )
        assert response.status == 200
        payload = await response.json()
        assert payload["ok"] is True
        assert payload["result"]["state"] == "configured"
        assert knowledge_settings.tested[-1]["backend"] == "helix"
    finally:
        await client.close()


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
                "caseName": "Case Alpha",
                "investigatorName": "Investigator One",
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
        assert inbound.metadata["case_name"] == "Case Alpha"
        assert inbound.metadata["investigator_name"] == "Investigator One"
        assert inbound.session_key == f"webui:{session_id}:case:Case-Alpha:artifact:Prefetch-1"
        assert channel.supports_streaming is True
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_upload_api_indexes_text_file_when_knowledge_service_is_bound(tmp_path: Path) -> None:
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
    knowledge_service = KnowledgeService(tmp_path, _knowledge_config())
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=FakeKnowledgeSettings(service=knowledge_service),
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        form = FormData()
        form.add_field("sessionId", "sess_upload")
        form.add_field("caseName", "Case Upload")
        form.add_field("investigatorName", "Investigator One")
        form.add_field(
            "file",
            b"2026-05-09 powershell.exe connected to 10.0.0.5",
            filename="events.log",
            content_type="text/plain",
        )

        response = await client.post("/api/uploads", data=form)
        assert response.status == 200
        payload = await response.json()
        assert payload["upload"]["kind"] == "text"
        assert payload["upload"]["status"] == "ready"
        assert payload["upload"]["ingest"]["chunks"] >= 1
        assert knowledge_service.search("powershell 10.0.0.5")["hits"]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_chat_publishes_attachment_context_when_upload_is_referenced(tmp_path: Path) -> None:
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
    knowledge_service = KnowledgeService(tmp_path, _knowledge_config())
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=FakeKnowledgeSettings(service=knowledge_service),
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        form = FormData()
        form.add_field("sessionId", "sess_upload")
        form.add_field("caseName", "Case Upload")
        form.add_field("investigatorName", "Investigator One")
        form.add_field(
            "file",
            b"cmd.exe launched powershell.exe against 10.0.0.5",
            filename="events.log",
            content_type="text/plain",
        )
        upload_response = await client.post("/api/uploads", data=form)
        upload_payload = await upload_response.json()
        upload_id = upload_payload["upload"]["uploadId"]

        response = await client.post(
            "/api/chat",
            json={
                "sessionId": "sess_upload",
                "caseName": "Case Upload",
                "investigatorName": "Investigator One",
                "text": "",
                "attachments": [{"uploadId": upload_id}],
            },
        )
        assert response.status == 200

        inbound = await asyncio.wait_for(bus.consume_inbound(), timeout=1)
        assert inbound.chat_id == "sess_upload"
        assert "Attached Evidence Context" in inbound.content
        assert "events.log" in inbound.content
        assert "첨부 파일을 분석해줘." in inbound.content
        assert inbound.media == []
        assert inbound.metadata["attachments"][0]["uploadId"] == upload_id
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_chat_attaches_image_media_when_image_upload_is_referenced(tmp_path: Path) -> None:
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
    knowledge_service = KnowledgeService(tmp_path, _knowledge_config())
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=FakeKnowledgeSettings(service=knowledge_service),
    )
    client = TestClient(TestServer(channel.create_app()))
    await client.start_server()

    try:
        png = (
            b"\x89PNG\r\n\x1a\n"
            + b"\x00\x00\x00\rIHDR"
            + struct.pack(">II", 4, 5)
            + b"\x08\x02\x00\x00\x00"
            + b"\x00" * 12
        )
        form = FormData()
        form.add_field("sessionId", "sess_upload")
        form.add_field("caseName", "Case Upload")
        form.add_field("investigatorName", "Investigator One")
        form.add_field("file", png, filename="screen.png", content_type="image/png")
        upload_response = await client.post("/api/uploads", data=form)
        upload_payload = await upload_response.json()
        upload_id = upload_payload["upload"]["uploadId"]

        response = await client.post(
            "/api/chat",
            json={
                "sessionId": "sess_upload",
                "caseName": "Case Upload",
                "investigatorName": "Investigator One",
                "text": "이 이미지 확인해줘",
                "attachments": [{"uploadId": upload_id}],
            },
        )
        assert response.status == 200

        inbound = await asyncio.wait_for(bus.consume_inbound(), timeout=1)
        assert inbound.media == [upload_payload["upload"]["storedPath"]]
        assert "Vision summary" in inbound.content
        assert inbound.metadata["attachments"][0]["vision"]["dimensions"] == {"width": 4, "height": 5}
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
                "caseName": "Case Alpha",
                "investigatorName": "Investigator One",
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
async def test_webui_case_read_only_apis_return_case_artifacts_when_workspace_has_case(
    tmp_path: Path,
) -> None:
    _write_case_fixture(tmp_path)
    _channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        bootstrap = await (await client.get("/api/bootstrap")).json()
        assert bootstrap["workspace"]["hasCases"] is True

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

    finally:
        await client.close()


@pytest.mark.asyncio
async def test_webui_rejects_missing_case_and_evidence_traversal(tmp_path: Path) -> None:
    _channel, _bus, _session_manager, client = await _make_client(tmp_path)

    try:
        response = await client.get("/api/cases/missing-case")
        assert response.status == 404

        response = await client.get("/api/cases/case-1/evidence/..")
        assert response.status == 404
    finally:
        await client.close()
