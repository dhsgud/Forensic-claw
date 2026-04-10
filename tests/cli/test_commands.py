import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from typer.testing import CliRunner

from forensic_claw.channels.kakaotalk import KakaoTalkConfig
from forensic_claw.cli.commands import _make_provider, _should_enable_onboard_wizard, app
from forensic_claw.config.schema import Config
from forensic_claw.providers.registry import PROVIDERS, find_by_name

runner = CliRunner()


def test_registry_only_exposes_local_providers() -> None:
    names = [spec.name for spec in PROVIDERS]

    assert names == ["custom", "vllm"]
    assert find_by_name("custom").display_name == "Custom (llama.cpp)"
    assert find_by_name("vllm").default_api_base == "http://localhost:8000/v1"


def test_default_config_uses_vllm() -> None:
    config = Config()

    assert config.agents.defaults.provider == "vllm"
    assert config.get_provider_name() == "vllm"
    assert config.get_api_base() == "http://localhost:8000/v1"


def test_default_hosts_bind_to_loopback() -> None:
    config = Config()

    assert config.gateway.host == "127.0.0.1"
    assert KakaoTalkConfig().host == "127.0.0.1"


def test_config_accepts_custom_provider_settings() -> None:
    config = Config.model_validate(
        {
            "agents": {"defaults": {"provider": "custom", "model": "llama.cpp/local"}},
            "providers": {"custom": {"apiBase": "http://127.0.0.1:8080/v1"}},
        }
    )

    assert config.get_provider_name() == "custom"
    assert config.get_api_base() == "http://127.0.0.1:8080/v1"


def test_config_normalizes_human_entered_api_base() -> None:
    config = Config.model_validate(
        {
            "agents": {"defaults": {"provider": "custom", "model": "llama.cpp/local"}},
            "providers": {"custom": {"apiBase": "183.96.3.137:0408"}},
        }
    )

    assert config.get_api_base() == "http://183.96.3.137:0408/v1"


def test_make_provider_passes_extra_headers_to_custom_provider() -> None:
    config = Config.model_validate(
        {
            "agents": {"defaults": {"provider": "custom", "model": "llama.cpp/local"}},
            "providers": {
                "custom": {
                    "apiBase": "https://example.com/v1",
                    "extraHeaders": {"x-session-affinity": "sticky-session"},
                }
            },
        }
    )

    with patch("forensic_claw.providers.openai_compat_provider.AsyncOpenAI") as mock_async_openai:
        _make_provider(config)

    kwargs = mock_async_openai.call_args.kwargs
    assert kwargs["base_url"] == "https://example.com/v1"
    assert kwargs["default_headers"]["x-session-affinity"] == "sticky-session"


def test_onboard_fresh_install_mentions_local_providers(tmp_path, monkeypatch):
    base_dir = tmp_path / "onboard"
    config_file = base_dir / "config.json"
    workspace_dir = base_dir / "workspace"

    monkeypatch.setattr("forensic_claw.config.loader.get_config_path", lambda: config_file)
    monkeypatch.setattr("forensic_claw.cli.commands.get_workspace_path", lambda _workspace=None: workspace_dir)
    monkeypatch.setattr("forensic_claw.channels.registry.discover_all", lambda: {})

    def _save_config(config: Config, config_path: Path | None = None):
        target = config_path or config_file
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(config.model_dump(by_alias=True)), encoding="utf-8")

    monkeypatch.setattr("forensic_claw.config.loader.save_config", _save_config)
    monkeypatch.setattr("forensic_claw.config.loader.load_config", lambda _config_path=None: Config())

    result = runner.invoke(app, ["onboard"])

    assert result.exit_code == 0
    assert "providers.vllm" in result.stdout
    assert "Discord, KakaoTalk" in result.stdout
    assert config_file.exists()
    assert (workspace_dir / "AGENTS.md").exists()


def test_onboard_wizard_auto_detection_prefers_explicit_flag(monkeypatch) -> None:
    monkeypatch.setattr("forensic_claw.cli.commands.sys.stdin", SimpleNamespace(isatty=lambda: False))
    monkeypatch.setattr("forensic_claw.cli.commands.sys.stdout", SimpleNamespace(isatty=lambda: False))

    assert _should_enable_onboard_wizard(True) is True
    assert _should_enable_onboard_wizard(False) is False


def test_onboard_wizard_auto_detection_uses_tty(monkeypatch) -> None:
    monkeypatch.setattr("forensic_claw.cli.commands.sys.stdin", SimpleNamespace(isatty=lambda: True))
    monkeypatch.setattr("forensic_claw.cli.commands.sys.stdout", SimpleNamespace(isatty=lambda: True))
    assert _should_enable_onboard_wizard(None) is True

    monkeypatch.setattr("forensic_claw.cli.commands.sys.stdout", SimpleNamespace(isatty=lambda: False))
    assert _should_enable_onboard_wizard(None) is False


def test_provider_login_is_unavailable() -> None:
    result = runner.invoke(app, ["provider", "login", "custom"])

    assert result.exit_code == 1
    assert "OAuth login is unavailable" in result.stdout


def test_channels_login_requires_channel_name() -> None:
    result = runner.invoke(app, ["channels", "login"])

    assert result.exit_code == 2
