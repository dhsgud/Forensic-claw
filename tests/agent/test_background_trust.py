import json

import pytest

from forensic_claw.agent.subagent import SubagentManager
from forensic_claw.bus.queue import MessageBus
from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.knowledge.service import KnowledgeService
from forensic_claw.providers.base import LLMResponse


class Provider:
    def get_default_model(self):
        return "fake"

    async def chat_with_retry(self, **kwargs):
        return LLMResponse(
            content='{"claims":[{"text":"fabricated malware","evidence_ids":["missing"]}]}'
        )


@pytest.mark.asyncio
async def test_background_task_persists_checked_status_and_delivers_without_resummarizing(tmp_path):
    source = tmp_path / "log.txt"
    source.write_text("powershell.exe connected", encoding="utf-8")
    knowledge = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    knowledge.ingest_path(source, case_name="case")
    bus = MessageBus()
    manager = SubagentManager(
        provider=Provider(), workspace=knowledge.workspace, bus=bus, knowledge_service=knowledge
    )
    await manager.spawn(
        "powershell", session_key="webui:one:case:case", metadata={"case_id": "case"}
    )
    message = await bus.consume_inbound()
    assert message.metadata["trust_checked"] is True
    assert "FLAGGED" in message.content and "fabricated malware" not in message.content
    records = [
        json.loads(path.read_text(encoding="utf-8"))
        for path in (knowledge.workspace / "tasks").glob("*.json")
    ]
    assert len(records) == 1 and records[0]["status"] == "completed"
    assert records[0]["caseId"] == "case" and "FLAGGED" in records[0]["result"]


def test_restarted_manager_marks_unfinished_persisted_task_interrupted(tmp_path):
    root = tmp_path / "tasks"
    root.mkdir()
    record = root / "old.json"
    record.write_text(
        json.dumps({"id": "old", "status": "running", "caseId": "case"}), encoding="utf-8"
    )
    SubagentManager(provider=Provider(), workspace=tmp_path, bus=MessageBus())
    saved = json.loads(record.read_text(encoding="utf-8"))
    assert saved["status"] == "interrupted" and saved["caseId"] == "case"
