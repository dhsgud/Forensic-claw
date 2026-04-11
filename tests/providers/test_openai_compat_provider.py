from __future__ import annotations

from forensic_claw.providers.openai_compat_provider import OpenAICompatProvider


def test_parse_chunks_collects_reasoning_content_from_stream_delta() -> None:
    response = OpenAICompatProvider._parse_chunks(
        [
            {
                "choices": [
                    {
                        "delta": {
                            "reasoning_content": "첫 번째 생각 ",
                            "content": "실시간 ",
                        }
                    }
                ]
            },
            {
                "choices": [
                    {
                        "delta": {
                            "reasoning_content": "두 번째 생각",
                            "content": "답변",
                        },
                        "finish_reason": "stop",
                    }
                ]
            },
        ]
    )

    assert response.reasoning_content == "첫 번째 생각 두 번째 생각"
    assert response.content == "실시간 답변"
    assert response.finish_reason == "stop"
