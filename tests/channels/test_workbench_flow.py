from pathlib import Path

import pytest
from aiohttp import FormData
from aiohttp.test_utils import TestClient, TestServer

from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.config.schema import Config, VectorConfig
from forensic_claw.knowledge.service import KnowledgeService
from forensic_claw.runtime.knowledge_settings import RuntimeKnowledgeSettings
from forensic_claw.session.manager import SessionManager


async def test_case_creation_and_upload_keep_selected_case_and_show_current_integrity(tmp_path):
    config = Config()
    config.knowledge.vector = VectorConfig(enabled=False)
    knowledge = KnowledgeService(tmp_path, config.knowledge)
    channel = WebUIChannel({}, MessageBus())
    channel.bind_runtime(
        session_manager=SessionManager(tmp_path),
        knowledge_settings=RuntimeKnowledgeSettings(config, service=knowledge),
    )
    async with TestClient(TestServer(channel.create_app())) as client:
        response = await client.post(
            "/api/cases",
            json={"caseId": "case-42", "caseName": "표시명", "investigatorName": "분석관"},
        )
        assert response.status == 201
        created = (await response.json())["case"]
        assert created["id"] == "case-42"
        session_id = (await (await client.get("/api/bootstrap")).json())["sessionId"]
        form = FormData()
        for key, value in {
            "sessionId": session_id,
            "caseId": "case-42",
            "caseName": "표시명",
            "investigatorName": "분석관",
        }.items():
            form.add_field(key, value)
        form.add_field(
            "file", b"powershell.exe observed", filename="events.log", content_type="text/plain"
        )
        response = await client.post("/api/uploads", data=form)
        assert response.status == 200
        upload = (await response.json())["upload"]
        response = await client.post(
            "/api/chat",
            json={
                "sessionId": session_id,
                "caseId": "case-42",
                "caseName": "표시명",
                "investigatorName": "분석관",
                "text": "powershell",
                "attachments": [{"uploadId": upload["uploadId"]}],
            },
        )
        assert response.status == 200
        inbound = await channel.bus.consume_inbound()
        assert inbound.metadata["user_query"] == "powershell"
        assert "Attached Evidence Context" in inbound.content
        detail = (await (await client.get("/api/cases/case-42")).json())["case"]
        assert len(detail["sources"]) == len(detail["evidence"]) == 1
        assert detail["sources"][0]["metadata"]["grade"] == "PARTIAL"
        hits = knowledge.search("powershell", case_id="case-42")["hits"]
        assert hits and hits[0]["metadata"]["caseId"] == "case-42"
        Path(hits[0]["sourcePath"]).write_text("changed", encoding="utf-8")
        changed = (await (await client.get("/api/cases/case-42")).json())["case"]
        assert changed["sources"][0]["metadata"]["grade"] == "UNVERIFIED"


async def test_duplicate_case_creation_preserves_original_investigator(tmp_path):
    channel = WebUIChannel({}, MessageBus())
    channel.bind_runtime(session_manager=SessionManager(tmp_path))
    async with TestClient(TestServer(channel.create_app())) as client:
        original = {"caseName": "same", "investigatorName": "original"}
        assert (await client.post("/api/cases", json=original)).status == 201
        assert (
            await client.post("/api/cases", json={**original, "investigatorName": "other"})
        ).status == 409
        case = (await (await client.get("/api/cases/same")).json())["case"]
        assert case["manifest"]["investigatorName"] == "original"


@pytest.mark.parametrize(
    "body", [{"caseName": "", "investigatorName": "name"}, {"caseName": "name"}, []]
)
async def test_case_creation_rejects_incomplete_setup_without_creating_case(tmp_path, body):
    channel = WebUIChannel({}, MessageBus())
    channel.bind_runtime(session_manager=SessionManager(tmp_path))
    async with TestClient(TestServer(channel.create_app())) as client:
        assert (await client.post("/api/cases", json=body)).status == 400
        assert (await (await client.get("/api/cases")).json())["cases"] == []
