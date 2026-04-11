from __future__ import annotations

import importlib
from unittest.mock import MagicMock

import forensic_claw.utils.helpers as helpers


def test_estimate_prompt_tokens_chain_prefers_provider_counter() -> None:
    provider = MagicMock()
    provider.estimate_prompt_tokens.return_value = (321, "provider_counter")

    tokens, source = helpers.estimate_prompt_tokens_chain(
        provider,
        "test-model",
        [{"role": "user", "content": "hello world"}],
        None,
    )

    assert tokens == 321
    assert source == "provider_counter"


def test_estimate_prompt_tokens_chain_uses_native_estimate_when_provider_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(helpers, "_get_tiktoken_encoding", lambda: None)
    provider = MagicMock()
    provider.estimate_prompt_tokens.side_effect = RuntimeError("no provider counter")

    tokens, source = helpers.estimate_prompt_tokens_chain(
        provider,
        "test-model",
        [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "안녕하세요 forensic claw"},
        ],
        [{"name": "read_file", "description": "Read a file"}],
    )

    assert tokens > 0
    assert source == "native_estimate"


def test_get_tiktoken_encoding_returns_none_when_module_missing(monkeypatch) -> None:
    helpers._get_tiktoken_encoding.cache_clear()
    real_import_module = importlib.import_module

    def fake_import_module(name: str, package: str | None = None):
        if name == "tiktoken":
            raise ModuleNotFoundError("No module named 'tiktoken'")
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", fake_import_module)

    try:
        assert helpers._get_tiktoken_encoding() is None
    finally:
        helpers._get_tiktoken_encoding.cache_clear()


def test_estimate_message_tokens_without_tiktoken_handles_structured_payload(monkeypatch) -> None:
    monkeypatch.setattr(helpers, "_get_tiktoken_encoding", lambda: None)

    tokens = helpers.estimate_message_tokens({
        "role": "assistant",
        "content": [
            {"type": "text", "text": "보고서 초안입니다."},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,xxx"}},
        ],
        "tool_calls": [{"name": "read_file", "arguments": {"path": "C:/case.txt"}}],
        "reasoning_content": "Need to inspect the case timeline carefully.",
        "name": "planner",
        "tool_call_id": "call-1",
    })

    assert tokens > 10


def test_estimate_prompt_tokens_chain_reports_optional_tiktoken_source(monkeypatch) -> None:
    class DummyEncoding:
        @staticmethod
        def encode(text: str) -> list[int]:
            return list(range(max(1, len(text) // 5)))

    monkeypatch.setattr(helpers, "_get_tiktoken_encoding", lambda: DummyEncoding())
    provider = MagicMock()
    provider.estimate_prompt_tokens.return_value = (0, "")

    tokens, source = helpers.estimate_prompt_tokens_chain(
        provider,
        "test-model",
        [{"role": "user", "content": "hello hello hello hello"}],
        None,
    )

    assert tokens > 0
    assert source == "native_estimate+tiktoken"


def test_extract_think_collects_closed_and_open_blocks() -> None:
    text = "<think>첫 번째</think>답변<think>두 번째"

    assert helpers.extract_think(text) == "첫 번째\n\n두 번째"
