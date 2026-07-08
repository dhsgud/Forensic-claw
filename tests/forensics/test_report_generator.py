"""Tests for the template-first report generator and service (P2)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from forensic_claw.forensics import CaseStore
from forensic_claw.forensics.report import (
    ReportGenerator,
    ReportService,
    default_template,
    load_template,
)
from forensic_claw.utils.hashing import calculate_file_hashes


class _FakeResponse:
    def __init__(self, content: str, finish_reason: str = "stop"):
        self.content = content
        self.finish_reason = finish_reason


class _FakeProvider:
    """Records prompts and echoes deterministic prose."""

    def __init__(self):
        self.calls: list[list[dict]] = []

    def get_default_model(self) -> str:
        return "fake-model"

    async def chat_with_retry(self, *, messages, tools=None, model=None, temperature=0.1, **_):
        self.calls.append(messages)
        return _FakeResponse("근거에 기반한 서술 본문입니다.")


class _ErrorProvider(_FakeProvider):
    async def chat_with_retry(self, *, messages, tools=None, model=None, temperature=0.1, **_):
        self.calls.append(messages)
        return _FakeResponse("Error calling LLM: upstream failed", finish_reason="error")


class _FakeKnowledge:
    enabled = True

    def __init__(self, with_hits: bool = True, *, case_name: str | None = None):
        self.with_hits = with_hits
        self.case_name = case_name

    def search(self, query, *, limit=8, include_graph=True):
        if not self.with_hits:
            return {"hits": []}
        return {
            "hits": [
                {
                    "text": f"{query} 관련 근거 라인",
                    "sourcePath": "C:/evidence/system.log",
                    "kind": "text_log",
                    "metadata": {"caseName": self.case_name} if self.case_name else {},
                }
            ]
        }


class _MixedCaseKnowledge:
    enabled = True

    def __init__(self, *, case_name: str):
        self.case_name = case_name

    def search(self, query, *, limit=8, include_graph=True):
        return {
            "hits": [
                {
                    "text": f"{query} target case evidence",
                    "sourcePath": "C:/evidence/target.log",
                    "kind": "text_log",
                    "metadata": {"caseName": self.case_name},
                },
                {
                    "text": f"{query} unrelated case evidence",
                    "sourcePath": "C:/evidence/other.log",
                    "kind": "text_log",
                    "metadata": {"caseName": "Other Case"},
                },
            ]
        }


def _make_context(tmp_path: Path):
    store = CaseStore(tmp_path)
    manifest = store.ensure_case(case_name="유출 사건", investigator_name="홍길동")
    case_id = manifest["caseId"]
    case_dir = store.case_dir(case_id)

    evidence_file = case_dir / "evidence" / "e1" / "files" / "system.log"
    evidence_file.parent.mkdir(parents=True, exist_ok=True)
    evidence_file.write_text("boot\n", encoding="utf-8")

    return store, case_id


def test_default_template_has_expected_sections():
    spec = default_template()
    ids = [section.id for section in spec.sections]
    assert ids == [
        "document_info",
        "overview",
        "integrity",
        "environment",
        "method",
        "results",
        "relationships",
        "conclusion",
        "signature",
    ]
    assert load_template("knpa_forensic_report").id == "knpa_forensic_report"


def test_load_template_unknown_raises():
    with pytest.raises(FileNotFoundError):
        load_template("does_not_exist")


@pytest.mark.asyncio
async def test_generate_fills_data_and_llm_sections(tmp_path: Path):
    store, case_id = _make_context(tmp_path)
    context = store.collect_context(case_id)

    generator = ReportGenerator(
        provider=_FakeProvider(),
        model="fake-model",
        knowledge_service=_FakeKnowledge(with_hits=True, case_name=context.case_name),
        app_version="9.9.9",
    )
    report = await generator.generate(context)

    by_id = {section.id: section for section in report.sections}
    # Document info comes straight from the case, no model.
    assert "유출 사건" in by_id["document_info"].markdown
    assert "Forensic-Claw 9.9.9" in by_id["document_info"].markdown
    # Integrity table has the real hash of the evidence file.
    assert "SHA-256" in by_id["integrity"].markdown
    assert "system.log" in by_id["integrity"].markdown
    # LLM sections used the model and cited the source in the results section.
    assert by_id["overview"].used_llm is True
    assert by_id["results"].used_llm is True
    assert "참고 출처" in by_id["results"].markdown
    assert "C:/evidence/system.log" in by_id["results"].markdown

    markdown = report.to_markdown()
    assert markdown.startswith("# 디지털 증거분석 결과보고서")
    assert "## 1. 분석 개요" in markdown


@pytest.mark.asyncio
async def test_llm_sections_fall_back_without_evidence(tmp_path: Path):
    store, case_id = _make_context(tmp_path)
    context = store.collect_context(case_id)

    provider = _FakeProvider()
    generator = ReportGenerator(
        provider=provider,
        model="fake-model",
        knowledge_service=_FakeKnowledge(with_hits=False),
    )
    report = await generator.generate(context)

    by_id = {section.id: section for section in report.sections}
    assert by_id["overview"].used_llm is False
    assert by_id["results"].used_llm is False
    # Without evidence the model is never called (no hallucination).
    assert provider.calls == []


@pytest.mark.asyncio
async def test_report_service_writes_report_md(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    store, case_id = _make_context(tmp_path)
    evidence_file = store.case_dir(case_id) / "evidence" / "e1" / "files" / "system.log"
    expected_sha256 = calculate_file_hashes(evidence_file, ("sha256",))["sha256"]
    original_stat = Path.stat

    def fake_stat(path: Path, *args, **kwargs):
        if str(path) == str(evidence_file):
            values = list(original_stat(path, *args, **kwargs))
            values[6] = 1024 * 1024 * 1024
            return os.stat_result(values)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)

    service = ReportService(
        workspace=tmp_path,
        provider=_FakeProvider(),
        model="fake-model",
        knowledge_service=_FakeKnowledge(
            with_hits=True,
            case_name=store.collect_context(case_id).case_name,
        ),
        app_version="1.0.0",
    )
    seen: list[tuple[int, int, str]] = []

    async def on_section(index, total, title):
        seen.append((index, total, title))

    result = await service.generate_report(case_id, on_section=on_section)

    assert result["ok"] is True
    report_path = Path(result["reportPath"])
    assert report_path.is_file()
    assert report_path.name == "report.md"
    assert "# 디지털 증거분석 결과보고서" in report_path.read_text(encoding="utf-8")
    assert expected_sha256 in report_path.read_text(encoding="utf-8")
    # Progress callback fired once per section.
    assert len(seen) == 9


@pytest.mark.asyncio
async def test_report_service_missing_case(tmp_path: Path):
    service = ReportService(
        workspace=tmp_path,
        provider=_FakeProvider(),
        model="fake-model",
    )
    result = await service.generate_report("no-such-case")
    assert result["ok"] is False
    assert result["error"] == "case_not_found"


@pytest.mark.asyncio
async def test_llm_sections_ignore_hits_from_other_cases(tmp_path: Path):
    store, case_id = _make_context(tmp_path)
    context = store.collect_context(case_id)
    provider = _FakeProvider()

    generator = ReportGenerator(
        provider=provider,
        model="fake-model",
        knowledge_service=_MixedCaseKnowledge(case_name=context.case_name),
    )
    report = await generator.generate(context)

    prompts = "\n".join(message["content"] for call in provider.calls for message in call)
    assert "target.log" in prompts
    assert "target case evidence" in prompts
    assert "other.log" not in prompts
    assert "unrelated case evidence" not in prompts

    by_id = {section.id: section for section in report.sections}
    assert "C:/evidence/target.log" in by_id["results"].markdown
    assert "C:/evidence/other.log" not in by_id["results"].markdown


@pytest.mark.asyncio
async def test_llm_sections_fall_back_when_provider_returns_error(tmp_path: Path):
    store, case_id = _make_context(tmp_path)
    context = store.collect_context(case_id)
    provider = _ErrorProvider()

    generator = ReportGenerator(
        provider=provider,
        model="fake-model",
        knowledge_service=_FakeKnowledge(with_hits=True, case_name=context.case_name),
    )
    report = await generator.generate(context)

    by_id = {section.id: section for section in report.sections}
    assert by_id["overview"].used_llm is False
    assert "Error calling LLM" not in by_id["overview"].markdown
    assert provider.calls
