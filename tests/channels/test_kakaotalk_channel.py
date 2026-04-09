from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from forensic_claw.bus.events import OutboundMessage
from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.kakaotalk import KakaoTalkChannel


def _make_request(payload: dict, headers: dict[str, str] | None = None):
    async def _json():
        return payload

    return SimpleNamespace(json=_json, headers=headers or {})


def test_pair_command_persists_user(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("forensic_claw.channels.kakaotalk.get_runtime_subdir", lambda _name: tmp_path)

    channel = KakaoTalkChannel(
        {"enabled": True, "allowFrom": [], "pairingCode": "secret"},
        MessageBus(),
    )

    response = channel._handle_pairing_command("user-1", "/pair secret Alice")

    assert response is not None
    assert channel.is_allowed("user-1") is True
    saved = json.loads((tmp_path / "pairs.json").read_text(encoding="utf-8"))
    assert saved["user-1"] == "Alice"


@pytest.mark.asyncio
async def test_skill_request_publishes_bus_message_and_returns_callback_ack(tmp_path, monkeypatch):
    monkeypatch.setattr("forensic_claw.channels.kakaotalk.get_runtime_subdir", lambda _name: tmp_path)
    bus = MessageBus()
    channel = KakaoTalkChannel({"enabled": True, "allowFrom": ["*"]}, bus)

    request = _make_request(
        {
            "userRequest": {
                "utterance": "안녕",
                "callbackUrl": "https://callback.test/kakao",
                "user": {"id": "user-1", "properties": {"botUserKey": "chat-1"}},
            }
        },
        headers={"X-Request-ID": "req-1"},
    )

    response = await channel._handle_skill_request(request)
    payload = json.loads(response.text)

    assert payload["useCallback"] is True
    inbound = await bus.consume_inbound()
    assert inbound.channel == "kakaotalk"
    assert inbound.chat_id == "chat-1"
    assert inbound.metadata["callback_url"] == "https://callback.test/kakao"


@pytest.mark.asyncio
async def test_send_posts_callback_payload(tmp_path, monkeypatch):
    monkeypatch.setattr("forensic_claw.channels.kakaotalk.get_runtime_subdir", lambda _name: tmp_path)
    channel = KakaoTalkChannel({"enabled": True, "allowFrom": ["*"]}, MessageBus())

    seen: dict[str, object] = {}

    class _FakeResponse:
        def raise_for_status(self) -> None:
            return None

    class _FakeHttp:
        async def post(self, url, json=None, headers=None):
            seen["url"] = url
            seen["json"] = json
            seen["headers"] = headers
            return _FakeResponse()

        async def close(self) -> None:
            return None

    channel._http = _FakeHttp()

    await channel.send(
        OutboundMessage(
            channel="kakaotalk",
            chat_id="chat-1",
            content='{"title":"분석 완료","description":"결과 요약","buttons":[{"action":"webLink","label":"열기","webLinkUrl":"https://example.com"}]}',
            metadata={"callback_url": "https://callback.test/kakao", "callback_token": "token-1"},
        )
    )

    assert seen["url"] == "https://callback.test/kakao"
    assert seen["headers"]["X-Kakao-Callback-Token"] == "token-1"
    assert seen["json"]["template"]["outputs"][0]["basicCard"]["title"] == "분석 완료"
