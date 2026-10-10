import json

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.events import InboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.command.builtin import cmd_report
from forensic_claw.command.router import CommandContext
from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.providers.base import GenerationSettings, LLMResponse


async def test_report_uses_selected_case_number_when_display_name_differs(tmp_path):
    class ModelBoundary:
        generation = GenerationSettings()

        def get_default_model(self):
            return "boundary"

        async def chat_with_retry(self, *, messages, **kwargs):
            hits = json.loads(messages[-1]["content"].split("[근거 JSON]\n", 1)[1])
            return LLMResponse(
                content=json.dumps(
                    {"claims": [{"text": hits[0]["text"], "evidence_ids": [hits[0]["evidenceId"]]}]}
                )
            )

    loop = AgentLoop(
        bus=MessageBus(),
        provider=ModelBoundary(),
        workspace=tmp_path,
        knowledge_config=KnowledgeConfig(vector=VectorConfig(enabled=False)),
    )
    source = tmp_path / "events.log"
    source.write_text("powershell.exe network connection observed", encoding="utf-8")
    loop.knowledge_service.ingest_path(
        source, case_id="selected-42", case_name="Display Name", investigator_name="Analyst"
    )
    message = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="one",
        content="/report",
        metadata={
            "case_id": "selected-42",
            "case_name": "Display Name",
            "investigator_name": "Analyst",
        },
    )
    context = CommandContext(
        msg=message, session=None, key="webui:one:case:selected-42", raw="/report", loop=loop
    )
    try:
        result = await cmd_report(context)
        assert result.metadata["case_id"] == "selected-42"
        root = tmp_path / "forensics/cases"
        assert (root / "selected-42/report.pdf").is_file()
        assert not (root / "Display-Name").exists()
    finally:
        await loop.close_mcp()
