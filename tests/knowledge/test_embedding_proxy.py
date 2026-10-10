import httpx

from forensic_claw.knowledge.embeddings import Embedder
from forensic_claw.security.model_proxy import ModelSecurityProxy


def test_remote_embeddings_share_consent_only_for_the_approved_model_endpoint(monkeypatch):
    received = []

    def fake_http(_transport, request):
        received.append(request.content)
        return httpx.Response(200, json={
            "object": "list", "model": "embedding-model",
            "data": [{"object": "embedding", "index": 0, "embedding": [0.25, 0.5]}],
            "usage": {"prompt_tokens": 1, "total_tokens": 1},
        })

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", fake_http)
    embedder = Embedder(model="embedding-model", api_base="https://8.8.8.8/v1")
    assert embedder.embed_one("synthetic") is None
    assert received == []
    embedder.security_proxy = ModelSecurityProxy("https://8.8.8.8/v1", approved=True)
    try:
        assert embedder.embed_one("synthetic") == [0.25, 0.5]
        assert b"synthetic" in received[0]
        embedder.api_base = "https://1.1.1.1/v1"
        assert embedder.embed_one("other destination") is None
        assert len(received) == 1
    finally:
        if embedder._client:
            embedder._client.close()
