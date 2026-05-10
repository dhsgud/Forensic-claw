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
