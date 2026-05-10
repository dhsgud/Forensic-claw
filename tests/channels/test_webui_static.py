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

    assert "Neo4j" not in html
    assert "setup-neo4j" not in html
    assert "neo4j-" not in html
    assert "Local RAG + Graph Index" in html
    assert "Test ${knowledgeBackendLabel(backend)}" in app
    assert "${label} test succeeded" in app


def test_webui_attachment_tray_exposes_upload_hashes() -> None:
    html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert "graph-20260510" in html
    assert "function attachmentHashLabel" in app
    assert "function attachmentHashTitle" in app
    assert "SHA256" in app
    assert "SHA512" in app


def test_webui_slash_menu_is_backed_by_bootstrap_commands() -> None:
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")

    assert "state.commands = data.commands || []" in app
    assert "function renderSlashMenu" in app
    assert "applySlashCommand(item.command)" in app


def test_webui_has_graph_inspector_panel_and_message_action() -> None:
    html = (STATIC_ROOT / "index.html").read_text(encoding="utf-8")
    app = (STATIC_ROOT / "app.js").read_text(encoding="utf-8")
    css = (STATIC_ROOT / "styles.css").read_text(encoding="utf-8")

    assert 'id="graph-inspector-panel"' in html
    assert 'id="graph-canvas"' in html
    assert "그래프로 확인하기" in app
    assert "function openGraphPanel" in app
    assert "graphViews" in app
    assert ".graph-node.selected" in css
