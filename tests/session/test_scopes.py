from forensic_claw.bus.events import InboundMessage
from forensic_claw.session.scopes import (
    build_scoped_session_key,
    normalize_scope_id,
    parse_scoped_session_key,
)


def test_normalize_scope_id_cleans_spacing_and_symbols() -> None:
    assert normalize_scope_id("  Case Alpha  ") == "Case-Alpha"
    assert normalize_scope_id("Prefetch #1") == "Prefetch-1"


def test_build_scoped_session_key_keeps_chat_identity() -> None:
    key = build_scoped_session_key(
        "webui",
        "browser-1",
        case_id="Case Alpha",
        artifact_id="Prefetch #1",
    )

    assert key == "webui:browser-1:case:Case-Alpha:artifact:Prefetch-1"


def test_parse_scoped_session_key_extracts_scope_markers() -> None:
    scope = parse_scoped_session_key("webui:browser-1:case:Case-Alpha:artifact:Prefetch-1")

    assert scope.base_key == "webui:browser-1"
    assert scope.case_id == "Case-Alpha"
    assert scope.artifact_id == "Prefetch-1"
    assert scope.is_scoped is True


def test_inbound_message_session_key_uses_case_artifact_metadata() -> None:
    msg = InboundMessage(
        channel="webui",
        sender_id="analyst",
        chat_id="browser-1",
        content="analyze",
        metadata={"caseId": "Case Alpha", "artifactId": "Prefetch #1"},
    )

    assert msg.session_key == "webui:browser-1:case:Case-Alpha:artifact:Prefetch-1"
