from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from forensic_claw.bus.events import InboundMessage
from forensic_claw.command.builtin import cmd_hash, cmd_new, cmd_report, get_builtin_command_specs
from forensic_claw.command.router import CommandContext
from forensic_claw.forensics import CaseStore
from forensic_claw.session.manager import SessionManager


@pytest.mark.asyncio
async def test_cmd_new_flags_webui_browser_session_reset(tmp_path: Path) -> None:
    session_manager = SessionManager(tmp_path)
    session = session_manager.get_or_create("webui:sess_abc")
    session.add_message("user", "hello")
    session_manager.save(session)

    archive_messages = AsyncMock()
    scheduled: list[object] = []

    loop = SimpleNamespace(
        sessions=session_manager,
        memory_consolidator=SimpleNamespace(archive_messages=archive_messages),
        _schedule_background=scheduled.append,
    )
    msg = InboundMessage(channel="webui", sender_id="user", chat_id="sess_abc", content="/new")
    ctx = CommandContext(msg=msg, session=session, key=session.key, raw="/new", loop=loop)

    outbound = await cmd_new(ctx)

    assert outbound.metadata["webui_reset_browser_session"] is True
    assert session_manager.get_or_create(session.key).messages == []
    assert len(scheduled) == 1

    for task in scheduled:
        task.close()


def _hash_ctx(tmp_path: Path, args: str, *, restrict_to_workspace: bool = False) -> CommandContext:
    return CommandContext(
        msg=InboundMessage(
            channel="webui",
            sender_id="user",
            chat_id="sess_hash",
            content=f"/hash {args}".strip(),
        ),
        session=None,
        key="webui:sess_hash",
        raw=f"/hash {args}".strip(),
        args=args,
        loop=SimpleNamespace(workspace=tmp_path, restrict_to_workspace=restrict_to_workspace),
    )


@pytest.mark.asyncio
async def test_cmd_hash_returns_integrity_hashes_for_relative_file(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"hash this evidence")

    outbound = await cmd_hash(_hash_ctx(tmp_path, "evidence.bin"))

    assert "File hash verification:" in outbound.content
    assert f"- file: {evidence}" in outbound.content
    assert "- MD5:" in outbound.content
    assert "- SHA256:" in outbound.content
    assert "- SHA512:" in outbound.content
    assert outbound.metadata == {"render_as": "text"}


@pytest.mark.asyncio
async def test_cmd_hash_finds_unique_file_name_inside_workspace(tmp_path: Path) -> None:
    evidence = tmp_path / "uploads" / "sessions" / "sess_1" / "upl_abc" / "History"
    evidence.parent.mkdir(parents=True)
    evidence.write_bytes(b"chrome history")

    outbound = await cmd_hash(_hash_ctx(tmp_path, "History"))

    assert f"- file: {evidence}" in outbound.content
    assert "- SHA256:" in outbound.content


@pytest.mark.asyncio
async def test_cmd_hash_verifies_expected_sha256_when_supplied(tmp_path: Path) -> None:
    evidence = tmp_path / "artifact.log"
    evidence.write_text("powershell launched", encoding="utf-8")

    first = await cmd_hash(_hash_ctx(tmp_path, "artifact.log"))
    sha256_line = next(line for line in first.content.splitlines() if line.startswith("- SHA256:"))
    expected = sha256_line.split(":", 1)[1].strip()

    outbound = await cmd_hash(_hash_ctx(tmp_path, f"artifact.log sha256={expected.upper()}"))

    assert "- verification: OK" in outbound.content
    assert "SHA256: match" in outbound.content


@pytest.mark.asyncio
async def test_cmd_hash_blocks_outside_file_when_workspace_is_restricted(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-hash.bin"
    outside.write_bytes(b"outside")

    outbound = await cmd_hash(_hash_ctx(tmp_path, str(outside), restrict_to_workspace=True))

    assert "Hash command denied:" in outbound.content
    assert "outside workspace" in outbound.content


@pytest.mark.asyncio
async def test_cmd_report_normalizes_metadata_case_id_when_case_name_absent(tmp_path: Path) -> None:
    store = CaseStore(tmp_path)
    manifest = store.ensure_case(case_name="Case Alpha", investigator_name="Investigator One")
    case_id = manifest["caseId"]
    msg = InboundMessage(
        channel="webui",
        sender_id="user",
        chat_id="sess_report",
        content="/report",
        metadata={"case_id": "Case Alpha"},
    )
    loop = SimpleNamespace(
        provider=object(),
        workspace=tmp_path,
        model="fake-model",
        knowledge_service=None,
    )
    ctx = CommandContext(
        msg=msg,
        session=None,
        key=f"webui:sess_report:case:{case_id}",
        raw="/report",
        loop=loop,
    )

    outbound = await cmd_report(ctx)

    assert outbound.metadata["case_id"] == case_id
    assert (store.case_dir(case_id) / "report.md").is_file()
    assert "case_not_found" not in outbound.content


def test_builtin_command_specs_include_hash_command() -> None:
    commands = {item.command for item in get_builtin_command_specs()}

    assert "/hash" in commands


@pytest.mark.asyncio
async def test_cmd_new_does_not_flag_non_webui_channels(tmp_path: Path) -> None:
    session_manager = SessionManager(tmp_path)
    session = session_manager.get_or_create("cli:test")
    session.add_message("user", "hello")
    session_manager.save(session)

    archive_messages = AsyncMock()
    scheduled: list[object] = []

    loop = SimpleNamespace(
        sessions=session_manager,
        memory_consolidator=SimpleNamespace(archive_messages=archive_messages),
        _schedule_background=scheduled.append,
    )
    msg = InboundMessage(channel="cli", sender_id="user", chat_id="test", content="/new")
    ctx = CommandContext(msg=msg, session=session, key=session.key, raw="/new", loop=loop)

    outbound = await cmd_new(ctx)

    assert "webui_reset_browser_session" not in outbound.metadata

    for task in scheduled:
        task.close()
