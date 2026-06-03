from __future__ import annotations

import json
from unittest.mock import MagicMock

from forensic_claw.agent.loop import AgentLoop
from forensic_claw.bus.queue import MessageBus
from forensic_claw.providers.base import GenerationSettings


def _make_loop(tmp_path, *, context_window_tokens: int = 65_536) -> AgentLoop:
    provider = MagicMock()
    provider.get_default_model.return_value = "test-model"
    provider.generation = GenerationSettings(max_tokens=0)
    return AgentLoop(
        bus=MessageBus(),
        provider=provider,
        workspace=tmp_path / "workspace",
        context_window_tokens=context_window_tokens,
        enforce_response_language=False,
    )


def test_provider_messages_strips_graph_and_caps_hits(tmp_path):
    loop = _make_loop(tmp_path)
    payload = {
        "query": "risky behavior",
        "hits": [{"text": f"hit-{i}", "metadata": {}} for i in range(40)],
        "graph": [{"value": f"entity-{i}"} for i in range(500)],
        "graphView": {
            "nodes": [{"id": f"n{i}", "metadata": {"blob": "x" * 200}} for i in range(300)],
            "edges": [{"id": f"e{i}"} for i in range(300)],
        },
    }
    canonical = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "scan my history"},
        {"role": "tool", "name": "knowledge_search", "tool_call_id": "1",
         "content": json.dumps(payload, ensure_ascii=False, indent=2)},
    ]
    before = json.dumps(canonical, ensure_ascii=False)

    outgoing = loop._provider_messages(canonical)

    # Canonical list is untouched (graph panel + persistence still see full payload).
    assert json.dumps(canonical, ensure_ascii=False) == before

    sent = json.loads(outgoing[2]["content"])
    assert "graphView" not in sent
    assert "graph" not in sent
    assert len(sent["hits"]) == AgentLoop._MODEL_SEARCH_HITS
    assert len(outgoing[2]["content"]) <= AgentLoop._TOOL_RESULT_MAX_CHARS


def test_provider_messages_caps_generic_tool_result(tmp_path):
    loop = _make_loop(tmp_path)
    big = "A" * (AgentLoop._TOOL_RESULT_MAX_CHARS + 5000)
    canonical = [
        {"role": "tool", "name": "exec", "tool_call_id": "9", "content": big},
    ]

    outgoing = loop._provider_messages(canonical)

    assert len(outgoing[0]["content"]) <= AgentLoop._TOOL_RESULT_MAX_CHARS + len("\n... (truncated)")
    assert outgoing[0]["content"].endswith("... (truncated)")
    # Original untouched.
    assert len(canonical[0]["content"]) == AgentLoop._TOOL_RESULT_MAX_CHARS + 5000


def test_provider_messages_fit_long_loop_under_budget(tmp_path):
    # Small window so the accumulated tool loop must be compressed.
    loop = _make_loop(tmp_path, context_window_tokens=2_000)
    budget = loop._prompt_token_budget()
    assert budget > 0

    canonical: list[dict] = [{"role": "system", "content": "system prompt"}]
    canonical.append({"role": "user", "content": "scan my entire history for risky behavior"})
    # Simulate many tool-call rounds, each adding a sizeable tool result.
    for i in range(20):
        canonical.append(
            {"role": "assistant", "content": "", "tool_calls": [
                {"id": f"c{i}", "type": "function",
                 "function": {"name": "knowledge_search", "arguments": "{}"}}
            ]}
        )
        canonical.append({
            "role": "tool", "name": "knowledge_search", "tool_call_id": f"c{i}",
            "content": json.dumps({"hits": [{"text": f"row {i} " + "x" * 300}]}),
        })

    before = json.dumps(canonical, ensure_ascii=False)
    outgoing = loop._provider_messages(canonical, tool_defs=None)

    from forensic_claw.utils.helpers import estimate_prompt_tokens

    assert estimate_prompt_tokens(outgoing, None) <= budget
    # Canonical history is never mutated.
    assert json.dumps(canonical, ensure_ascii=False) == before
    # System prompt is always retained.
    assert outgoing[0]["role"] == "system"
    # The most recent tool result is preserved verbatim (not stubbed).
    assert "row 19" in outgoing[-1]["content"]
