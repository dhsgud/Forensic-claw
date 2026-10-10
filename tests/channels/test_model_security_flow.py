import httpx
from aiohttp.test_utils import TestClient, TestServer

from forensic_claw.bus.queue import MessageBus
from forensic_claw.channels.webui import WebUIChannel
from forensic_claw.config.schema import Config
from forensic_claw.providers.factory import create_provider
from forensic_claw.runtime.model_settings import RuntimeModelSettings


async def test_webui_requires_both_warnings_before_forwarding_to_an_approved_remote_model(
    tmp_path,
    monkeypatch,
):
    config = Config()
    config_path = tmp_path / "config.json"
    service = RuntimeModelSettings(config, config_path=config_path)
    channel = WebUIChannel({"enabled": True}, MessageBus())
    channel.bind_runtime(model_settings=service)
    received = []

    async def fake_http(_transport, request):
        received.append(request.content)
        return httpx.Response(
            200,
            json={
                "id": "synthetic",
                "object": "chat.completion",
                "created": 1,
                "model": "m",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "approved"},
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", fake_http)
    async with TestClient(TestServer(channel.create_app())) as client:
        payload = {"provider": "custom", "model": "m", "apiBase": "https://8.8.8.8/v1"}
        first = await client.patch("/api/model-config", json=payload)
        assert first.status == 409
        data = await first.json()
        assert data["security"]["status"] == "FAIL" and data["confirmation"]["step"] == 1
        assert not config_path.exists()
        second = await client.patch(
            "/api/model-config",
            json={
                **payload,
                "consentToken": data["confirmation"]["token"],
            },
        )
        assert second.status == 409
        data = await second.json()
        assert data["confirmation"]["step"] == 2
        assert not config_path.exists()
        third = await client.patch(
            "/api/model-config",
            json={
                **payload,
                "consentToken": data["confirmation"]["token"],
            },
        )
        assert third.status == 200
        assert (await third.json())["modelConfig"]["security"]["approved"]
        provider = create_provider(config)
        try:
            response = await provider.chat(messages=[{"role": "user", "content": "synthetic"}])
            assert response.content == "approved"
            assert b"synthetic" in received[0]
        finally:
            await provider._client.close()
        # Editing a destination invalidates the previous approval before anything is sent.
        changed = await client.patch(
            "/api/model-config", json={**payload, "apiBase": "https://1.1.1.1/v1"}
        )
        assert changed.status == 409
        assert config.get_api_base() == "https://8.8.8.8/v1"


async def test_webui_rejects_malformed_consent_without_changing_config(tmp_path):
    config = Config()
    service = RuntimeModelSettings(config, config_path=tmp_path / "config.json")
    channel = WebUIChannel({"enabled": True}, MessageBus())
    channel.bind_runtime(model_settings=service)
    original = config.model_dump()
    async with TestClient(TestServer(channel.create_app())) as client:
        response = await client.patch(
            "/api/model-config",
            json={
                "provider": "custom",
                "model": "m",
                "apiBase": "https://8.8.8.8/v1",
                "consentToken": ["invalid"],
            },
        )
        assert response.status == 400
        assert config.model_dump() == original
