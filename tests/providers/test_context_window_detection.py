from __future__ import annotations

import pytest

from forensic_claw.providers.openai_compat_provider import OpenAICompatProvider


def test_parse_context_window_llamacpp_meta_n_ctx():
    payload = {"data": [{"id": "m.gguf", "meta": {"n_ctx": 64000}}]}
    assert OpenAICompatProvider._parse_context_window(payload, "m.gguf") == 64000


def test_parse_context_window_vllm_max_model_len():
    payload = {"data": [{"id": "qwen", "max_model_len": 32768}]}
    assert OpenAICompatProvider._parse_context_window(payload, "qwen") == 32768


def test_parse_context_window_prefers_matching_model():
    payload = {"data": [
        {"id": "other", "max_model_len": 8192},
        {"id": "wanted", "max_model_len": 131072},
    ]}
    assert OpenAICompatProvider._parse_context_window(payload, "wanted") == 131072


def test_parse_context_window_falls_back_to_first_entry():
    payload = {"data": [{"id": "only", "meta": {"n_ctx": 4096}}]}
    assert OpenAICompatProvider._parse_context_window(payload, "missing-model") == 4096


def test_parse_context_window_returns_none_when_absent():
    assert OpenAICompatProvider._parse_context_window({"data": [{"id": "m"}]}, "m") is None
    assert OpenAICompatProvider._parse_context_window({}, "m") is None


@pytest.mark.asyncio
async def test_base_provider_detect_returns_none(tmp_path):
    # OpenAICompatProvider with an unreachable base must fail soft (None), not raise.
    provider = OpenAICompatProvider(api_base="http://127.0.0.1:1/v1", default_model="m")
    assert await provider.detect_context_window("m") is None
