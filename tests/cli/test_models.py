from unittest.mock import Mock, patch

from forensic_claw.cli.models import fetch_openai_compatible_models


def test_fetch_openai_compatible_models_uses_normalized_v1_models_endpoint() -> None:
    response = Mock()
    response.json.return_value = {
        "data": [{"id": "model-a"}, {"id": "model-b"}]
    }
    response.raise_for_status.return_value = None

    with patch("forensic_claw.cli.models.httpx.get", return_value=response) as mock_get:
        models = fetch_openai_compatible_models("183.96.3.137:0408")

    assert models == ["model-a", "model-b"]
    mock_get.assert_called_once_with("http://183.96.3.137:0408/v1/models", timeout=5.0)


def test_fetch_openai_compatible_models_returns_empty_on_error() -> None:
    with patch("forensic_claw.cli.models.httpx.get", side_effect=RuntimeError("boom")):
        assert fetch_openai_compatible_models("http://example.com:8000") == []
