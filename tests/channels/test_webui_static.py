from pathlib import Path

STATIC_ROOT = Path(__file__).resolve().parents[2] / "forensic_claw" / "webui" / "static"


def test_webui_exposes_backend_specific_database_test_controls() -> None:
    html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert 'id="setup-knowledge-backend"' in html
    assert 'id="setup-test-db"' in html
    assert 'id="setup-helix-enabled"' in html
    assert 'id="setup-helix-port"' in html
    assert 'id="setup-helix-api-endpoint"' in html
    assert 'id="knowledge-test"' in html
    assert "Test DB" in html

    assert "setup-test-neo4j" not in html
    assert "setup-test-neo4j" not in app
    assert "Test ${knowledgeBackendLabel(backend)}" in app
    assert "${label} test succeeded" in app


def test_webui_attachment_tray_exposes_upload_hashes() -> None:
    html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert "hash-20260510" in html
    assert "function attachmentHashLabel" in app
    assert "function attachmentHashTitle" in app
    assert "SHA256" in app
    assert "SHA512" in app


def test_webui_slash_menu_is_backed_by_bootstrap_commands() -> None:
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert "state.commands = data.commands || []" in app
    assert "function renderSlashMenu" in app
    assert "applySlashCommand(item.command)" in app
