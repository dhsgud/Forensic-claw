"""Built-in slash command handlers."""

from __future__ import annotations

import asyncio
import json
import os
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forensic_claw import __version__
from forensic_claw.bus.events import OutboundMessage
from forensic_claw.command.router import CommandContext, CommandRouter
from forensic_claw.utils.hashing import (
    DEFAULT_HASH_ALGORITHMS,
    SUPPORTED_HASH_ALGORITHMS,
    calculate_file_hashes,
    normalize_hash_algorithm,
    verify_hashes,
)
from forensic_claw.utils.helpers import build_status_content


@dataclass(frozen=True)
class BuiltinCommandSpec:
    """Structured metadata for one built-in slash command."""

    command: str
    description: str
    kind: str = "exact"


_BUILTIN_COMMAND_SPECS: tuple[BuiltinCommandSpec, ...] = (
    BuiltinCommandSpec("/new", "Start a new conversation"),
    BuiltinCommandSpec("/reset", "Alias for /new"),
    BuiltinCommandSpec("/stop", "Stop the current task", kind="priority"),
    BuiltinCommandSpec("/restart", "Restart the bot", kind="priority"),
    BuiltinCommandSpec("/status", "Show bot status", kind="priority"),
    BuiltinCommandSpec("/hash", "Calculate MD5, SHA256, and SHA512 for a local file"),
    BuiltinCommandSpec("/model", "Show or change the local model endpoint"),
    BuiltinCommandSpec("/knowledge", "Show or prepare the local RAG and graph evidence store"),
    BuiltinCommandSpec("/help", "Show available commands"),
)

_HASH_SEARCH_SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
_HASH_LENGTH_TO_ALGORITHM = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


def get_builtin_command_specs() -> list[BuiltinCommandSpec]:
    """Return structured metadata for default slash commands."""
    return list(_BUILTIN_COMMAND_SPECS)


async def cmd_stop(ctx: CommandContext) -> OutboundMessage:
    """Cancel all active tasks and subagents for the session."""
    loop = ctx.loop
    msg = ctx.msg
    tasks = loop._active_tasks.pop(msg.session_key, [])
    cancelled = sum(1 for t in tasks if not t.done() and t.cancel())
    for t in tasks:
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass
    sub_cancelled = await loop.subagents.cancel_by_session(msg.session_key)
    total = cancelled + sub_cancelled
    content = f"Stopped {total} task(s)." if total else "No active task to stop."
    return OutboundMessage(channel=msg.channel, chat_id=msg.chat_id, content=content)


async def cmd_restart(ctx: CommandContext) -> OutboundMessage:
    """Restart the process in-place via os.execv."""
    msg = ctx.msg

    async def _do_restart():
        await asyncio.sleep(1)
        os.execv(sys.executable, [sys.executable, "-m", "forensic_claw"] + sys.argv[1:])

    asyncio.create_task(_do_restart())
    return OutboundMessage(channel=msg.channel, chat_id=msg.chat_id, content="Restarting...")


async def cmd_status(ctx: CommandContext) -> OutboundMessage:
    """Build an outbound status message for a session."""
    loop = ctx.loop
    session = ctx.session or loop.sessions.get_or_create(ctx.key)
    ctx_est = 0
    try:
        ctx_est, _ = loop.memory_consolidator.estimate_session_prompt_tokens(session)
    except Exception:
        pass
    if ctx_est <= 0:
        ctx_est = loop._last_usage.get("prompt_tokens", 0)
    return OutboundMessage(
        channel=ctx.msg.channel,
        chat_id=ctx.msg.chat_id,
        content=build_status_content(
            version=__version__, model=loop.model,
            start_time=loop._start_time, last_usage=loop._last_usage,
            context_window_tokens=loop.context_window_tokens,
            session_msg_count=len(session.get_history(max_messages=0)),
            context_tokens_estimate=ctx_est,
        ),
        metadata={"render_as": "text"},
    )


async def cmd_new(ctx: CommandContext) -> OutboundMessage:
    """Start a fresh session."""
    loop = ctx.loop
    session = ctx.session or loop.sessions.get_or_create(ctx.key)
    snapshot = session.messages[session.last_consolidated:]
    session.clear()
    loop.sessions.save(session)
    loop.sessions.invalidate(session.key)
    if snapshot:
        loop._schedule_background(loop.memory_consolidator.archive_messages(snapshot))
    metadata = {}
    if ctx.msg.channel == "webui":
        metadata["webui_reset_browser_session"] = True
    return OutboundMessage(
        channel=ctx.msg.channel, chat_id=ctx.msg.chat_id,
        content="New session started.",
        metadata=metadata,
    )


async def cmd_help(ctx: CommandContext) -> OutboundMessage:
    """Return available slash commands."""
    lines = ["🐈 forensic-claw commands:"]
    lines.extend(f"{item.command} — {item.description}" for item in get_builtin_command_specs())
    return OutboundMessage(
        channel=ctx.msg.channel,
        chat_id=ctx.msg.chat_id,
        content="\n".join(lines),
        metadata={"render_as": "text"},
    )


async def cmd_hash(ctx: CommandContext) -> OutboundMessage:
    """Calculate file hashes from a slash command."""
    msg = ctx.msg
    args = ctx.args.strip()
    if not args:
        return _hash_text_response(
            ctx,
            "Usage:\n"
            "/hash <file path or file name>\n"
            "/hash <file path> sha256=<expected_hash>\n"
            "/hash <file path> <expected_sha256>",
        )

    try:
        tokens = _split_hash_command_args(args)
    except ValueError as exc:
        return _hash_text_response(ctx, f"Hash command error: {exc}")
    if not tokens:
        return _hash_text_response(ctx, "Usage: /hash <file path or file name>")

    raw_path = tokens[0]
    try:
        expected = _parse_expected_hash_tokens(tokens[1:])
        path = _resolve_hash_command_path(
            raw_path,
            workspace=getattr(ctx.loop, "workspace", None),
            restrict_to_workspace=bool(getattr(ctx.loop, "restrict_to_workspace", False)),
        )
        hashes = await asyncio.to_thread(calculate_file_hashes, path, DEFAULT_HASH_ALGORITHMS)
        verification = verify_hashes(hashes, expected)
    except ValueError as exc:
        return _hash_text_response(ctx, f"Hash command error: {exc}")
    except PermissionError as exc:
        return _hash_text_response(ctx, f"Hash command denied: {exc}")
    except FileNotFoundError:
        return _hash_text_response(ctx, f"Hash command error: file not found: {raw_path}")
    except OSError as exc:
        return _hash_text_response(ctx, f"Hash command error: {exc}")

    lines = [
        "File hash verification:",
        f"- file: {path}",
        f"- sizeBytes: {path.stat().st_size}",
    ]
    for algorithm in DEFAULT_HASH_ALGORITHMS:
        lines.append(f"- {algorithm.upper()}: {hashes[algorithm]}")
    if verification["checked"]:
        status = "OK" if verification["ok"] else "FAILED"
        lines.append(f"- verification: {status}")
        for algorithm, result in verification["results"].items():
            match = "match" if result["match"] else "mismatch"
            lines.append(
                f"  - {algorithm.upper()}: {match} "
                f"(expected={result['expected']} actual={result['actual']})"
            )
    lines.append("")
    lines.append("Tip: Local LLM can also call `hash_verify` directly for the same file.")
    return OutboundMessage(
        channel=msg.channel,
        chat_id=msg.chat_id,
        content="\n".join(lines),
        metadata={"render_as": "text"},
    )


def _hash_text_response(ctx: CommandContext, content: str) -> OutboundMessage:
    return OutboundMessage(
        channel=ctx.msg.channel,
        chat_id=ctx.msg.chat_id,
        content=content,
        metadata={"render_as": "text"},
    )


def _split_hash_command_args(args: str) -> list[str]:
    tokens = shlex.split(args, posix=False)
    normalized: list[str] = []
    for token in tokens:
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
            normalized.append(token[1:-1])
        else:
            normalized.append(token)
    return normalized


def _parse_expected_hash_tokens(tokens: list[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator:
            algorithm = normalize_hash_algorithm(key)
            expected[algorithm] = value
            continue

        digest = "".join(char for char in token if char in "0123456789abcdefABCDEF")
        algorithm = _HASH_LENGTH_TO_ALGORITHM.get(len(digest))
        if not algorithm:
            supported = ", ".join(SUPPORTED_HASH_ALGORITHMS)
            raise ValueError(
                f"expected hash '{token}' must be alg=<hash> or a known digest length. Supported: {supported}"
            )
        expected[algorithm] = token
    return expected


def _resolve_hash_command_path(
    raw_path: str,
    *,
    workspace: Any,
    restrict_to_workspace: bool,
) -> Path:
    workspace_path = Path(workspace).resolve() if workspace else None
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute() and workspace_path:
        candidate = workspace_path / candidate
    resolved = candidate.resolve(strict=False)

    if restrict_to_workspace and workspace_path and not _is_under_path(resolved, workspace_path):
        raise PermissionError(f"{raw_path} is outside workspace {workspace_path}")
    if resolved.is_file():
        return resolved

    if workspace_path and _looks_like_file_name(raw_path):
        matches = _find_workspace_files_by_name(workspace_path, raw_path)
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            preview = "\n".join(f"- {item}" for item in matches[:8])
            raise ValueError(f"multiple files named '{raw_path}' were found. Use a path:\n{preview}")

    raise FileNotFoundError(raw_path)


def _looks_like_file_name(value: str) -> bool:
    return bool(value) and not Path(value).is_absolute() and "/" not in value and "\\" not in value


def _find_workspace_files_by_name(workspace: Path, file_name: str) -> list[Path]:
    matches: list[Path] = []
    stack = [workspace]
    while stack and len(matches) <= 8:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir():
                if child.name not in _HASH_SEARCH_SKIP_DIRS:
                    stack.append(child)
                continue
            if child.is_file() and child.name == file_name:
                matches.append(child.resolve())
                if len(matches) > 8:
                    break
    return sorted(matches, key=lambda item: str(item))


def _is_under_path(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _format_model_status(snapshot: dict) -> str:
    lines = [
        "Model settings:",
        f"- provider: {snapshot.get('provider') or 'unknown'}",
        f"- model: {snapshot.get('model') or 'unknown'}",
        f"- apiBase: {snapshot.get('apiBase') or 'unset'}",
    ]
    providers = snapshot.get("availableProviders") or []
    if providers:
        names = ", ".join(item["name"] for item in providers if item.get("name"))
        lines.append(f"- available: {names}")
    profiles = snapshot.get("profiles") or []
    if profiles:
        active = snapshot.get("activeProfile")
        names = ", ".join(
            f"{item['name']}*" if item.get("name") == active else item["name"]
            for item in profiles
            if item.get("name")
        )
        lines.append(f"- profiles: {names}")
    return "\n".join(lines)


async def cmd_model(ctx: CommandContext) -> OutboundMessage:
    """Show or change the active runtime model endpoint."""
    service = getattr(ctx.loop, "model_settings", None)
    if service is None:
        return OutboundMessage(
            channel=ctx.msg.channel,
            chat_id=ctx.msg.chat_id,
            content="Model settings are not available in this process.",
            metadata={"render_as": "text"},
        )

    args = ctx.args.strip()
    if not args or args == "status":
        content = _format_model_status(service.snapshot())
        return OutboundMessage(
            channel=ctx.msg.channel,
            chat_id=ctx.msg.chat_id,
            content=content,
            metadata={"render_as": "text"},
        )

    parts = args.split(maxsplit=2)
    action = parts[0].lower()
    try:
        if action == "test":
            api_base = parts[1] if len(parts) > 1 else None
            result = await service.test_connection(api_base=api_base)
            status = "ok" if result.get("ok") else "failed"
            content = (
                f"Model endpoint test {status}.\n"
                f"- apiBase: {result.get('apiBase') or 'unset'}\n"
                f"- status: {result.get('status') or 'n/a'}"
            )
            if result.get("error"):
                content += f"\n- error: {result['error']}"
            models = result.get("models") or []
            if models:
                content += "\n- models: " + ", ".join(models[:10])
            return OutboundMessage(
                channel=ctx.msg.channel,
                chat_id=ctx.msg.chat_id,
                content=content,
                metadata={"render_as": "text"},
            )

        if action == "profile":
            profile_parts = args.split(maxsplit=2)
            profile_action = profile_parts[1].lower() if len(profile_parts) > 1 else "list"
            if profile_action == "list":
                content = _format_model_status(service.snapshot())
            elif profile_action == "save" and len(profile_parts) >= 3:
                snapshot = service.save_profile(profile_parts[2])
                content = "Model profile saved.\n" + _format_model_status(snapshot)
            elif profile_action == "use" and len(profile_parts) >= 3:
                snapshot = await service.use_profile(profile_parts[2])
                content = "Model profile applied.\n" + _format_model_status(snapshot)
            else:
                raise ValueError("Usage: /model profile list|save|use <name>")
            return OutboundMessage(
                channel=ctx.msg.channel,
                chat_id=ctx.msg.chat_id,
                content=content,
                metadata={"render_as": "text"},
            )

        if action == "use" and len(parts) >= 2:
            snapshot = await service.apply(provider=parts[1])
            content = "Provider updated.\n" + _format_model_status(snapshot)
        elif action == "set" and len(parts) >= 3:
            key = parts[1].replace("-", "_").lower()
            value = parts[2].strip()
            if key in {"apibase", "api_base", "url"}:
                snapshot = await service.apply(api_base=value, api_base_supplied=True)
            elif key == "model":
                snapshot = await service.apply(model=value)
            elif key == "provider":
                snapshot = await service.apply(provider=value)
            else:
                raise ValueError("Usage: /model set provider|model|apiBase <value>")
            content = "Model settings updated.\n" + _format_model_status(snapshot)
        else:
            content = (
                "Usage:\n"
                "/model status\n"
                "/model test [apiBase]\n"
                "/model use <provider>\n"
                "/model profile list|save|use <name>\n"
                "/model set provider <provider>\n"
                "/model set model <model>\n"
                "/model set apiBase <url>"
            )
    except ValueError as exc:
        content = f"Model settings error: {exc}"

    return OutboundMessage(
        channel=ctx.msg.channel,
        chat_id=ctx.msg.chat_id,
        content=content,
        metadata={"render_as": "text"},
    )


async def cmd_knowledge(ctx: CommandContext) -> OutboundMessage:
    """Operate the local RAG and graph store."""
    service = getattr(ctx.loop, "knowledge_service", None)
    if service is None:
        return OutboundMessage(
            channel=ctx.msg.channel,
            chat_id=ctx.msg.chat_id,
            content="Knowledge service is not available in this process.",
            metadata={"render_as": "text"},
        )

    args = ctx.args.strip()
    if not args or args == "status":
        content = service.status()
    else:
        action, _, rest = args.partition(" ")
        action = action.lower()
        if action == "ingest" and rest.strip():
            result = await asyncio.to_thread(
                service.ingest_path,
                rest.strip(),
                case_name=(ctx.msg.metadata or {}).get("case_name"),
                investigator_name=(ctx.msg.metadata or {}).get("investigator_name"),
            )
            return OutboundMessage(
                channel=ctx.msg.channel,
                chat_id=ctx.msg.chat_id,
                content=service.result_to_text(result),
                metadata={"render_as": "text"},
            )
        if action == "search" and rest.strip():
            content = service.search(rest.strip())
        else:
            text = (
                "Usage:\n"
                "/knowledge status\n"
                "/knowledge ingest <path>\n"
                "/knowledge search <query>"
            )
            return OutboundMessage(
                channel=ctx.msg.channel,
                chat_id=ctx.msg.chat_id,
                content=text,
                metadata={"render_as": "text"},
            )

    return OutboundMessage(
        channel=ctx.msg.channel,
        chat_id=ctx.msg.chat_id,
        content=json.dumps(content, ensure_ascii=False, indent=2),
        metadata={"render_as": "text"},
    )


def register_builtin_commands(router: CommandRouter) -> None:
    """Register the default set of slash commands."""
    router.priority("/stop", cmd_stop)
    router.priority("/restart", cmd_restart)
    router.priority("/status", cmd_status)
    router.exact("/new", cmd_new)
    router.exact("/reset", cmd_new)
    router.exact("/status", cmd_status)
    router.exact("/hash", cmd_hash)
    router.prefix("/hash ", cmd_hash)
    router.exact("/model", cmd_model)
    router.prefix("/model ", cmd_model)
    router.exact("/knowledge", cmd_knowledge)
    router.prefix("/knowledge ", cmd_knowledge)
    router.exact("/help", cmd_help)
