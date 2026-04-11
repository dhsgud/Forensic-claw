"""Markdown wiki archiving helpers for transient answer flows."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from forensic_claw.session.scopes import parse_scoped_session_key
from forensic_claw.utils.helpers import ensure_dir, safe_filename

_TITLE_CLEAN_RE = re.compile(r"[#`>*_\[\]\(\)]")
_WS_RE = re.compile(r"\s+")


def _compact_line(text: str, *, max_len: int = 80) -> str:
    """Collapse whitespace and strip markdown-ish noise for titles/slugs."""
    cleaned = _TITLE_CLEAN_RE.sub("", text or "")
    cleaned = _WS_RE.sub(" ", cleaned).strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip(" -_:;,./")
    return cleaned or "Untitled Response"


def _slugify(text: str, *, max_len: int = 60) -> str:
    """Generate a filesystem-safe slug from free-form text."""
    safe = safe_filename(_compact_line(text, max_len=max_len)).lower()
    safe = safe.replace(" ", "-").strip("._-")
    if len(safe) > max_len:
        safe = safe[:max_len].rstrip("._-")
    return safe or "entry"


@dataclass(frozen=True)
class WikiArchiveEntry:
    """A saved markdown note."""

    path: Path
    title: str


class WikiArchive:
    """Persist final answers as markdown notes under ``workspace/wiki``."""

    def __init__(self, workspace: Path):
        self.root = ensure_dir(workspace / "wiki")

    def save_final_answer(
        self,
        *,
        session_key: str,
        channel: str,
        chat_id: str,
        request: str,
        answer: str,
    ) -> WikiArchiveEntry:
        """Write one markdown note containing the request and final answer."""
        now = datetime.now()
        title_source = request.strip() or answer.strip() or "Untitled Response"
        title = _compact_line(title_source)
        scope = parse_scoped_session_key(session_key)
        if scope.case_id:
            session_dir = ensure_dir(self.root / "cases" / safe_filename(scope.case_id))
            if scope.artifact_id:
                session_dir = ensure_dir(
                    session_dir / "artifacts" / safe_filename(scope.artifact_id)
                )
        elif scope.artifact_id:
            session_dir = ensure_dir(self.root / "artifacts" / safe_filename(scope.artifact_id))
        else:
            session_dir = ensure_dir(self.root / "sessions" / safe_filename(scope.base_key.replace(":", "_")))
        filename = f"{now:%Y%m%d-%H%M%S-%f}_{_slugify(title_source)}.md"
        path = session_dir / filename

        body = "\n".join(
            [
                "---",
                f"title: {json.dumps(title, ensure_ascii=False)}",
                f"created_at: {json.dumps(now.isoformat(), ensure_ascii=False)}",
                f"session_key: {json.dumps(session_key, ensure_ascii=False)}",
                f"base_session_key: {json.dumps(scope.base_key, ensure_ascii=False)}",
                f"channel: {json.dumps(channel, ensure_ascii=False)}",
                f"chat_id: {json.dumps(chat_id, ensure_ascii=False)}",
                f"case_id: {json.dumps(scope.case_id, ensure_ascii=False)}",
                f"artifact_id: {json.dumps(scope.artifact_id, ensure_ascii=False)}",
                'source: "final_answer"',
                "---",
                "",
                f"# {title}",
                "",
                "## Request",
                "",
                request.strip() or "(empty)",
                "",
                "## Final Answer",
                "",
                answer.strip() or "(empty)",
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        return WikiArchiveEntry(path=path, title=title)
