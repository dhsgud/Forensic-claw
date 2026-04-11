"""Utility functions for forensic-claw."""

import base64
import importlib
import json
import re
import time
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any


def strip_think(text: str) -> str:
    """Remove <think>…</think> blocks and any unclosed trailing <think> tag."""
    text = re.sub(r"<think>[\s\S]*?</think>", "", text)
    text = re.sub(r"<think>[\s\S]*$", "", text)
    return text.strip()


def extract_think(text: str | None) -> str | None:
    """Extract text inside <think>…</think> blocks, including an open trailing block."""
    if not text:
        return None

    parts = [match.group(1).strip() for match in re.finditer(r"<think>([\s\S]*?)</think>", text)]
    start = text.rfind("<think>")
    end = text.rfind("</think>")
    if start != -1 and start > end:
        trailing = text[start + len("<think>") :].strip()
        if trailing:
            parts.append(trailing)

    deduped: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if part and part not in seen:
            deduped.append(part)
            seen.add(part)

    if not deduped:
        return None
    return "\n\n".join(deduped)


def detect_image_mime(data: bytes) -> str | None:
    """Detect image MIME type from magic bytes, ignoring file extension."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def build_image_content_blocks(raw: bytes, mime: str, path: str, label: str) -> list[dict[str, Any]]:
    """Build native image blocks plus a short text label."""
    b64 = base64.b64encode(raw).decode()
    return [
        {
            "type": "image_url",
            "image_url": {"url": f"data:{mime};base64,{b64}"},
            "_meta": {"path": path},
        },
        {"type": "text", "text": label},
    ]


def ensure_dir(path: Path) -> Path:
    """Ensure directory exists, return it."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def timestamp() -> str:
    """Current ISO timestamp."""
    return datetime.now().isoformat()


def current_time_str(timezone: str | None = None) -> str:
    """Human-readable current time with weekday and UTC offset.

    When *timezone* is a valid IANA name (e.g. ``"Asia/Shanghai"``), the time
    is converted to that zone.  Otherwise falls back to the host local time.
    """
    from zoneinfo import ZoneInfo

    try:
        tz = ZoneInfo(timezone) if timezone else None
    except (KeyError, Exception):
        tz = None

    now = datetime.now(tz=tz) if tz else datetime.now().astimezone()
    offset = now.strftime("%z")
    offset_fmt = f"{offset[:3]}:{offset[3:]}" if len(offset) == 5 else offset
    tz_name = timezone or (time.strftime("%Z") or "UTC")
    return f"{now.strftime('%Y-%m-%d %H:%M (%A)')} ({tz_name}, UTC{offset_fmt})"


_UNSAFE_CHARS = re.compile(r'[<>:"/\\|?*]')
_ASCII_TOKEN_CHUNK = 4


def safe_filename(name: str) -> str:
    """Replace unsafe path characters with underscores."""
    return _UNSAFE_CHARS.sub("_", name).strip()


def _is_cjk_like(ch: str) -> bool:
    """Return whether *ch* is commonly tokenized as a standalone wide glyph."""
    code = ord(ch)
    return (
        0x1100 <= code <= 0x11FF  # Hangul Jamo
        or 0x2E80 <= code <= 0x2EFF  # CJK Radicals Supplement
        or 0x2F00 <= code <= 0x2FDF  # Kangxi Radicals
        or 0x2FF0 <= code <= 0x2FFF  # Ideographic Description Characters
        or 0x3000 <= code <= 0x303F  # CJK Symbols and Punctuation
        or 0x3040 <= code <= 0x30FF  # Hiragana / Katakana
        or 0x3130 <= code <= 0x318F  # Hangul Compatibility Jamo
        or 0x31A0 <= code <= 0x31BF  # Bopomofo Extended
        or 0x31C0 <= code <= 0x31EF  # CJK Strokes
        or 0x3400 <= code <= 0x4DBF  # CJK Unified Ideographs Extension A
        or 0x4E00 <= code <= 0x9FFF  # CJK Unified Ideographs
        or 0xAC00 <= code <= 0xD7A3  # Hangul Syllables
        or 0xF900 <= code <= 0xFAFF  # CJK Compatibility Ideographs
        or 0xFE30 <= code <= 0xFE4F  # CJK Compatibility Forms
        or 0xFF00 <= code <= 0xFFEF  # Halfwidth and Fullwidth Forms
    )


@lru_cache(maxsize=1)
def _get_tiktoken_encoding():
    """Best-effort optional tiktoken loader."""
    try:
        tiktoken = importlib.import_module("tiktoken")
    except Exception:
        return None
    try:
        return tiktoken.get_encoding("cl100k_base")
    except Exception:
        return None


def _estimate_text_tokens_native(text: str) -> int:
    """Approximate token count without external tokenizer dependencies."""
    total = 0
    idx = 0
    while idx < len(text):
        ch = text[idx]
        if ch.isspace():
            idx += 1
            continue
        if ch.isascii() and (ch.isalnum() or ch == "_"):
            end = idx + 1
            while end < len(text):
                nxt = text[end]
                if not (nxt.isascii() and (nxt.isalnum() or nxt == "_")):
                    break
                end += 1
            total += max(1, (end - idx + _ASCII_TOKEN_CHUNK - 1) // _ASCII_TOKEN_CHUNK)
            idx = end
            continue
        if _is_cjk_like(ch):
            end = idx + 1
            while end < len(text) and _is_cjk_like(text[end]):
                end += 1
            total += end - idx
            idx = end
            continue
        total += 1
        idx += 1
    return total


def _append_content_parts(parts: list[str], content: Any, *, include_non_text_parts: bool) -> None:
    """Append textual payloads that materially affect prompt size."""
    if isinstance(content, str):
        parts.append(content)
        return
    if isinstance(content, list):
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                text = part.get("text", "")
                if text:
                    parts.append(text)
            elif include_non_text_parts:
                parts.append(json.dumps(part, ensure_ascii=False))
        return
    if include_non_text_parts and content is not None:
        parts.append(json.dumps(content, ensure_ascii=False))


def _collect_message_parts(
    message: dict[str, Any],
    *,
    include_non_text_parts: bool,
) -> list[str]:
    """Collect message fields that contribute to prompt size."""
    parts: list[str] = []
    _append_content_parts(parts, message.get("content"), include_non_text_parts=include_non_text_parts)

    for key in ("name", "tool_call_id"):
        value = message.get(key)
        if isinstance(value, str) and value:
            parts.append(value)

    tool_calls = message.get("tool_calls")
    if tool_calls:
        parts.append(json.dumps(tool_calls, ensure_ascii=False))

    reasoning_content = message.get("reasoning_content")
    if isinstance(reasoning_content, str) and reasoning_content:
        parts.append(reasoning_content)

    return parts


def _estimate_parts_native(parts: list[str]) -> int:
    """Estimate token count from collected text parts using local heuristics."""
    return sum(_estimate_text_tokens_native(part) for part in parts if part)


def _estimate_parts_with_tiktoken(parts: list[str], *, overhead: int) -> int | None:
    """Optionally refine token estimates when tiktoken is installed."""
    encoding = _get_tiktoken_encoding()
    if encoding is None:
        return None
    payload = "\n".join(part for part in parts if part)
    try:
        return len(encoding.encode(payload)) + overhead
    except Exception:
        return None


def _estimate_prompt_tokens_local(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
) -> tuple[int, str]:
    """Estimate prompt tokens using native heuristics with optional refinement."""
    parts: list[str] = []
    for message in messages:
        parts.extend(_collect_message_parts(message, include_non_text_parts=False))
    if tools:
        parts.append(json.dumps(tools, ensure_ascii=False))

    overhead = len(messages) * 4
    native_estimate = _estimate_parts_native(parts) + overhead
    tiktoken_estimate = _estimate_parts_with_tiktoken(parts, overhead=overhead)
    if tiktoken_estimate is not None:
        return max(native_estimate, tiktoken_estimate), "native_estimate+tiktoken"
    return native_estimate, "native_estimate"


def split_message(content: str, max_len: int = 2000) -> list[str]:
    """
    Split content into chunks within max_len, preferring line breaks.

    Args:
        content: The text content to split.
        max_len: Maximum length per chunk (default 2000 for Discord compatibility).

    Returns:
        List of message chunks, each within max_len.
    """
    if not content:
        return []
    if len(content) <= max_len:
        return [content]
    chunks: list[str] = []
    while content:
        if len(content) <= max_len:
            chunks.append(content)
            break
        cut = content[:max_len]
        # Try to break at newline first, then space, then hard break
        pos = cut.rfind('\n')
        if pos <= 0:
            pos = cut.rfind(' ')
        if pos <= 0:
            pos = max_len
        chunks.append(content[:pos])
        content = content[pos:].lstrip()
    return chunks


def build_assistant_message(
    content: str | None,
    tool_calls: list[dict[str, Any]] | None = None,
    reasoning_content: str | None = None,
    thinking_blocks: list[dict] | None = None,
) -> dict[str, Any]:
    """Build a provider-safe assistant message with optional reasoning fields."""
    msg: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    if reasoning_content is not None:
        msg["reasoning_content"] = reasoning_content
    if thinking_blocks:
        msg["thinking_blocks"] = thinking_blocks
    return msg


def extract_thinking_text(
    reasoning_content: str | None = None,
    thinking_blocks: list[dict] | None = None,
    text_content: str | None = None,
) -> str | None:
    """Flatten provider-specific reasoning fields into one display string."""
    parts: list[str] = []

    if isinstance(reasoning_content, str) and reasoning_content.strip():
        parts.append(reasoning_content.strip())
    think_text = extract_think(text_content)
    if think_text:
        parts.append(think_text)

    for block in thinking_blocks or []:
        if not isinstance(block, dict):
            continue
        for key in ("thinking", "thought", "text", "content"):
            value = block.get(key)
            if isinstance(value, str) and value.strip():
                parts.append(value.strip())
                break

    deduped: list[str] = []
    seen: set[str] = set()
    for part in parts:
        if part not in seen:
            deduped.append(part)
            seen.add(part)

    if not deduped:
        return None
    return "\n\n".join(deduped)


def extract_message_thinking_text(message: dict[str, Any]) -> str | None:
    """Read normalized thinking text from a persisted assistant message."""
    return extract_thinking_text(
        message.get("reasoning_content"),
        message.get("thinking_blocks"),
        message.get("content") if isinstance(message.get("content"), str) else None,
    )


def estimate_prompt_tokens(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
) -> int:
    """Estimate prompt tokens with a built-in heuristic tokenizer."""
    estimated, _source = _estimate_prompt_tokens_local(messages, tools)
    return estimated


def estimate_message_tokens(message: dict[str, Any]) -> int:
    """Estimate prompt tokens contributed by one persisted message."""
    parts = _collect_message_parts(message, include_non_text_parts=True)
    if not parts:
        return 4
    native_estimate = max(4, _estimate_parts_native(parts) + 4)
    tiktoken_estimate = _estimate_parts_with_tiktoken(parts, overhead=4)
    if tiktoken_estimate is not None:
        return max(native_estimate, tiktoken_estimate)
    return native_estimate


def estimate_prompt_tokens_chain(
    provider: Any,
    model: str | None,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]] | None = None,
) -> tuple[int, str]:
    """Estimate prompt tokens via provider counter first, then local fallback."""
    provider_counter = getattr(provider, "estimate_prompt_tokens", None)
    if callable(provider_counter):
        try:
            tokens, source = provider_counter(messages, tools, model)
            if isinstance(tokens, (int, float)) and tokens > 0:
                return int(tokens), str(source or "provider_counter")
        except Exception:
            pass

    estimated, source = _estimate_prompt_tokens_local(messages, tools)
    if estimated > 0:
        return int(estimated), source
    return 0, "none"


def build_status_content(
    *,
    version: str,
    model: str,
    start_time: float,
    last_usage: dict[str, int],
    context_window_tokens: int,
    session_msg_count: int,
    context_tokens_estimate: int,
) -> str:
    """Build a human-readable runtime status snapshot."""
    uptime_s = int(time.time() - start_time)
    uptime = (
        f"{uptime_s // 3600}h {(uptime_s % 3600) // 60}m"
        if uptime_s >= 3600
        else f"{uptime_s // 60}m {uptime_s % 60}s"
    )
    last_in = last_usage.get("prompt_tokens", 0)
    last_out = last_usage.get("completion_tokens", 0)
    ctx_total = max(context_window_tokens, 0)
    ctx_pct = int((context_tokens_estimate / ctx_total) * 100) if ctx_total > 0 else 0
    ctx_used_str = f"{context_tokens_estimate // 1000}k" if context_tokens_estimate >= 1000 else str(context_tokens_estimate)
    ctx_total_str = f"{ctx_total // 1024}k" if ctx_total > 0 else "n/a"
    return "\n".join([
        f"\U0001f408 forensic-claw v{version}",
        f"\U0001f9e0 Model: {model}",
        f"\U0001f4ca Tokens: {last_in} in / {last_out} out",
        f"\U0001f4da Context: {ctx_used_str}/{ctx_total_str} ({ctx_pct}%)",
        f"\U0001f4ac Session: {session_msg_count} messages",
        f"\u23f1 Uptime: {uptime}",
    ])


def sync_workspace_templates(workspace: Path, silent: bool = False) -> list[str]:
    """Sync bundled templates to workspace. Only creates missing files."""
    from importlib.resources import files as pkg_files
    try:
        tpl = pkg_files("forensic_claw") / "templates"
    except Exception:
        return []
    if not tpl.is_dir():
        return []

    added: list[str] = []

    def _write(src, dest: Path):
        if dest.exists():
            return
        dest.parent.mkdir(parents=True, exist_ok=True)
        content = ""
        if src and src.exists():
            content = src.read_text(encoding="utf-8")
        dest.write_text(content, encoding="utf-8")
        added.append(str(dest.relative_to(workspace)))

    for item in tpl.iterdir():
        if item.name.endswith(".md") and not item.name.startswith("."):
            _write(item, workspace / item.name)
    _write(tpl / "memory" / "MEMORY.md", workspace / "memory" / "MEMORY.md")
    _write(None, workspace / "memory" / "HISTORY.md")
    (workspace / "skills").mkdir(exist_ok=True)

    if added and not silent:
        from rich.console import Console
        for name in added:
            Console().print(f"  [dim]Created {name}[/dim]")
    return added
