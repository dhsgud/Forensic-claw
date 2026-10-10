import json

import pytest

from forensic_claw.config.schema import Config
from forensic_claw.providers.factory import create_provider
from forensic_claw.runtime.model_settings import ModelConsentRequiredError, RuntimeModelSettings


async def challenge(service, **payload):
    with pytest.raises(ModelConsentRequiredError) as required:
        await service.apply(**payload)
    return required.value.confirmation


async def test_remote_model_requires_two_confirmations_before_settings_or_evidence_change(tmp_path):
    config = Config()
    path = tmp_path / "config.json"
    service = RuntimeModelSettings(config, config_path=path)
    original = config.model_dump()
    payload = dict(
        provider="custom",
        model="remote-test",
        api_base="https://8.8.8.8/v1",
        api_base_supplied=True,
    )
    first = await challenge(service, **payload)
    assert first["step"] == 1
    assert "로컬 모델이 아니어도" in first["message"]
    assert config.model_dump() == original and not path.exists()
    second = await challenge(service, **payload, consent_token=first["token"])
    assert second["step"] == 2
    assert "증거가 외부로 전송" in second["message"]
    assert config.model_dump() == original and not path.exists()
    saved = await service.apply(**payload, consent_token=second["token"])
    assert saved["security"]["status"] == "FAIL"
    assert saved["security"]["approved"] and saved["security"]["allowed"]
    reloaded = Config.model_validate(json.loads(path.read_text(encoding="utf-8")))
    assert create_provider(reloaded).security_proxy.assess()["allowed"]


async def test_consent_cannot_be_reused_for_a_changed_model_or_endpoint(tmp_path):
    service = RuntimeModelSettings(Config(), config_path=tmp_path / "config.json")
    payload = dict(
        provider="custom", model="m", api_base="https://8.8.8.8/v1", api_base_supplied=True
    )
    first = await challenge(service, **payload)
    second = await challenge(service, **payload, consent_token=first["token"])
    for replacement in [{"model": "different"}, {"api_base": "https://1.1.1.1/v1"}]:
        with pytest.raises(ValueError, match="동의"):
            await service.apply(**{**payload, **replacement}, consent_token=second["token"])
    # Tokens are single-use, including mismatched attempts.
    with pytest.raises(ValueError, match="동의"):
        await service.apply(**payload, consent_token=second["token"])


async def test_lan_model_applies_without_confirmations(tmp_path):
    service = RuntimeModelSettings(Config(), config_path=tmp_path / "config.json")
    result = await service.apply(
        provider="custom", model="local", api_base="10.0.0.5:8080", api_base_supplied=True
    )
    assert result["security"]["status"] == "PASS"
    assert result["security"]["allowed"] and not result["security"]["approved"]
