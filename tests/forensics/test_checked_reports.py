import json

import pytest
from pypdf import PdfReader

from forensic_claw.config.schema import KnowledgeConfig, VectorConfig
from forensic_claw.forensics.report import ReportService
from forensic_claw.knowledge.service import KnowledgeService


class ExtractiveProvider:
    async def chat_with_retry(self, *, messages, **kwargs):
        evidence = json.loads(messages[-1]["content"].split("[근거 JSON]\n", 1)[1])

        class Response:
            content = json.dumps(
                {
                    "claims": [
                        {
                            "text": evidence[0]["text"].splitlines()[0],
                            "evidence_ids": [evidence[0]["evidenceId"]],
                        }
                    ]
                }
            )
            finish_reason = "stop"

        return Response()


class FabricatingProvider:
    async def chat_with_retry(self, **kwargs):
        class Response:
            content = '{"claims":[{"text":"2027-01-01 malware executed","evidence_ids":["fake"]}]}'
            finish_reason = "stop"

        return Response()


def prepared(tmp_path):
    service = KnowledgeService(
        tmp_path / "workspace", KnowledgeConfig(vector=VectorConfig(enabled=False))
    )
    file = tmp_path / "로그.log"
    file.write_text(
        "로그인 실패 2026-05-07 powershell.exe <script>alert(1)</script>\n", encoding="utf-8"
    )
    assert service.ingest_path(file, case_name="테스트 사건", investigator_name="홍길동").ready
    return service


@pytest.mark.asyncio
async def test_report_exports_same_checked_findings_to_html_pdf_and_audit(tmp_path):
    knowledge = prepared(tmp_path)
    result = await ReportService(
        workspace=knowledge.workspace,
        provider=ExtractiveProvider(),
        model="test",
        knowledge_service=knowledge,
    ).generate_report("테스트-사건")
    assert result["ok"]
    from pathlib import Path

    html = Path(result["exports"]["html"]).read_text(encoding="utf-8")
    assert "&lt;script&gt;" in html and "<script>" not in html
    assert "PARTIAL" in html and "홍길동" in html
    pdf = PdfReader(result["exports"]["pdf"])
    text = "\n".join(page.extract_text() for page in pdf.pages)
    assert "홍길동" in text and "PARTIAL" in text
    audit = json.loads(Path(result["exports"]["json"]).read_text(encoding="utf-8"))
    assert any(section["checks"] for section in audit["sections"])


@pytest.mark.asyncio
async def test_report_excludes_fabricated_claim_from_all_user_facing_exports(tmp_path):
    knowledge = prepared(tmp_path)
    result = await ReportService(
        workspace=knowledge.workspace,
        provider=FabricatingProvider(),
        model="test",
        knowledge_service=knowledge,
    ).generate_report("테스트-사건")
    assert "2027-01-01" not in result["markdown"]
    assert "FLAGGED" in result["markdown"]


@pytest.mark.asyncio
async def test_report_describes_missing_evidence_without_claiming_no_suspicious_activity(tmp_path):
    knowledge = prepared(tmp_path)
    result = await ReportService(
        workspace=knowledge.workspace,
        provider=ExtractiveProvider(),
        model="test",
        knowledge_service=None,
    ).generate_report("테스트-사건")
    assert "특이 발견사항이 확인되지 않았습니다" not in result["markdown"]
    assert "근거" in result["markdown"]


@pytest.mark.asyncio
async def test_report_integrity_table_reflects_source_changed_during_generation(tmp_path):
    from pathlib import Path

    from forensic_claw.utils.hashing import calculate_file_hashes

    class ChangingProvider(ExtractiveProvider):
        async def chat_with_retry(self, *, messages, **kwargs):
            evidence = json.loads(messages[-1]["content"].split("[근거 JSON]\n", 1)[1])
            self.path = Path(evidence[0]["sourcePath"])
            response = await super().chat_with_retry(messages=messages, **kwargs)
            self.path.write_text("changed during report", encoding="utf-8")
            return response

    knowledge = prepared(tmp_path)
    provider = ChangingProvider()
    result = await ReportService(
        workspace=knowledge.workspace, provider=provider, model="test", knowledge_service=knowledge
    ).generate_report("테스트-사건")
    assert "UNVERIFIED" in result["markdown"]
    assert calculate_file_hashes(provider.path)["sha256"] in result["markdown"]
