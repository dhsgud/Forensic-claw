import pytest
from aiohttp.test_utils import TestClient, TestServer

from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.forensics.case import CaseStore
from forensic_claw.session.manager import SessionManager


@pytest.mark.asyncio
async def test_case_report_downloads_use_allowed_formats_and_deny_path_traversal(tmp_path):
    store = CaseStore(tmp_path)
    store.ensure_case(case_name="case")
    (store.case_dir("case") / "report.html").write_text(
        "<html>검토용 초안</html>", encoding="utf-8"
    )
    channel = WebUIChannel({"allowFrom": ["*"]}, MessageBus())
    channel.bind_runtime(session_manager=SessionManager(tmp_path))
    async with TestClient(TestServer(channel.create_app())) as client:
        response = await client.get("/api/cases/case/report/download?format=html")
        assert response.status == 200
        assert "검토용 초안" in await response.text()
        assert "attachment" in response.headers["Content-Disposition"]
        assert (
            await client.get("/api/cases/case/report/download?format=../../secret")
        ).status == 400


@pytest.mark.asyncio
async def test_report_preview_lists_only_existing_download_formats(tmp_path):
    store = CaseStore(tmp_path)
    store.ensure_case(case_name="case")
    for extension, content in {"md": "검토용 초안", "html": "<p>검토용 초안</p>"}.items():
        (store.case_dir("case") / f"report.{extension}").write_text(content, encoding="utf-8")
    channel = WebUIChannel({}, MessageBus())
    channel.bind_runtime(session_manager=SessionManager(tmp_path))
    async with TestClient(TestServer(channel.create_app())) as client:
        response = await client.get("/api/cases/case/report")
        assert await response.json() == {
            "caseId": "case",
            "content": "검토용 초안",
            "formats": ["html", "md"],
        }
