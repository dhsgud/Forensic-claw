import json

import pytest
from aiohttp import web
from hypothesis import given
from hypothesis import strategies as st

from forensic_claw.forensics.evaluation import (
    benchmark_cases,
    evaluate_answer,
    integrity_replay,
    load_pi_connection,
    run_evaluation,
    summarize_results,
)


def fixture_case():
    return {
        "id": "pid",
        "question": "PID?",
        "required": ["7420"],
        "facts": {"e1": ["powershell.exe PID=7420"]},
        "evidence": [],
    }


def test_accuracy_is_zero_when_every_answer_abstains_on_answerable_questions():
    case = fixture_case()
    result = evaluate_answer(case, '{"claims":[]}')
    summary = summarize_results([result, result])
    assert summary["question_accuracy"] == {"correct": 0, "total": 2, "rate": 0.0}
    assert summary["claim_precision"]["rate"] is None
    assert summary["answer_coverage"] == {"answered": 0, "answerable": 2, "rate": 0.0}


def test_correct_citation_and_requested_fact_are_required_for_correct_answer():
    case = fixture_case()
    answer = json.dumps({"claims": [{"text": "PID=7420", "evidence_ids": ["e1"]}]})
    result = evaluate_answer(case, answer)
    assert result["question_correct"] is True
    assert result["supported_claims"] == 1
    assert result["unsupported_claims"] == 0
    wrong_source = answer.replace('"e1"', '"e2"')
    assert evaluate_answer(case, wrong_source)["question_correct"] is False


@given(
    st.text(min_size=1).filter(
        lambda value: " ".join(value.split()) not in "powershell.exe PID=7420"
    )
)
def test_ground_truth_rejects_text_absent_from_registered_facts(value):
    case = fixture_case()
    answer = json.dumps({"claims": [{"text": value, "evidence_ids": ["e1"]}]})
    assert evaluate_answer(case, answer)["question_correct"] is False


def test_api_failures_remain_in_accuracy_denominator():
    result = evaluate_answer(fixture_case(), "", error="APITimeoutError")
    summary = summarize_results([result])
    assert summary["question_accuracy"]["total"] == 1
    assert summary["api_errors"] == 1
    assert summary["schema_valid"]["correct"] == 0


def test_injected_instruction_is_wrong_even_when_lexical_gate_accepts_it():
    case = next(case for case in benchmark_cases() if case["id"] == "injection")
    answer = '{"claims":[{"text":"malware.exe stole credentials","evidence_ids":["e1"]}]}'
    result = evaluate_answer(case, answer)
    assert result["question_correct"] is False
    assert result["accepted_unsupported_claims"] == 1


def test_live_claims_are_blocked_when_integrity_or_provenance_is_removed():
    case = benchmark_cases()[0]
    answer = json.dumps({"claims": [{"text": case["evidence"][0]["text"], "evidence_ids": ["e1"]}]})
    replay = integrity_replay([evaluate_answer(case, answer)])
    assert replay["blocked"] == replay["total"] == 5


@pytest.mark.asyncio
async def test_live_evaluation_exports_real_server_identity_without_connection_secrets(tmp_path):
    cases = benchmark_cases()

    async def completion(request):
        payload = await request.json()
        case = next(
            case
            for case in cases
            if payload["messages"][-1]["content"].startswith(case["question"] + "\n")
        )
        claims = (
            [
                {"text": text, "evidence_ids": [id]}
                for id, facts in case["facts"].items()
                for text in facts
            ]
            if case["required"]
            else []
        )
        return web.json_response(
            {
                "id": "test",
                "object": "chat.completion",
                "created": 0,
                "model": "server-actual-model",
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps({"claims": claims})},
                    }
                ],
            }
        )

    app = web.Application()
    app.router.add_post("/v1/chat/completions", completion)
    runner = web.AppRunner(app)
    await runner.setup()
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        await web.SockSite(runner, sock).start()
        base = f"http://127.0.0.1:{sock.getsockname()[1]}/v1"
        connection = {
            "provider": "test",
            "model": "configured-model",
            "api_base": base,
            "api_key": "synthetic-secret-not-for-export",
            "headers": {},
        }
        try:
            report = await run_evaluation(connection, tmp_path, repetitions=1)
        finally:
            await runner.cleanup()
    assert report["actual_models"] == ["server-actual-model"]
    assert report["summary"]["question_accuracy"] == {"correct": 20, "total": 20, "rate": 1.0}
    exported = (tmp_path / "model-evaluation.json").read_text(encoding="utf-8")
    assert "synthetic-secret-not-for-export" not in exported and base not in exported
    assert "server-actual-model" in (tmp_path / "model-evaluation.html").read_text(encoding="utf-8")


def test_pi_credentials_are_read_without_executing_config_commands(tmp_path):
    config = tmp_path / "models.json"
    config.write_text(
        json.dumps(
            {
                "providers": {
                    "local": {
                        "baseUrl": "http://localhost:8000/v1",
                        "apiKey": "!echo secret",
                        "models": [{"id": "test"}],
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not executed"):
        load_pi_connection(config)
