"""Helpers for case/artifact-scoped session routing."""

from __future__ import annotations

import re
from dataclasses import dataclass

from forensic_claw.utils.helpers import safe_filename

_WS_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[^\w.-]+", re.UNICODE)
_DASH_RE = re.compile(r"-{2,}")


def normalize_scope_id(value: str | None) -> str | None:
    """Normalize free-form case/artifact identifiers into stable key tokens."""
    if value is None:
        return None
    cleaned = safe_filename(str(value).strip())
    cleaned = _WS_RE.sub("-", cleaned)
    cleaned = _TOKEN_RE.sub("-", cleaned).strip("._-")
    cleaned = _DASH_RE.sub("-", cleaned)
    return cleaned or None


def build_scoped_session_key(
    channel: str,
    chat_id: str,
    *,
    case_id: str | None = None,
    artifact_id: str | None = None,
) -> str:
    """Build a session key that keeps chat identity and adds optional scope markers."""
    key = f"{channel}:{chat_id}"
    normalized_case = normalize_scope_id(case_id)
    normalized_artifact = normalize_scope_id(artifact_id)

    if normalized_case:
        key += f":case:{normalized_case}"
    if normalized_artifact:
        key += f":artifact:{normalized_artifact}"
    return key


@dataclass(frozen=True)
class SessionScope:
    """Parsed scope information from a session key."""

    session_key: str
    base_key: str
    case_id: str | None = None
    artifact_id: str | None = None

    @property
    def is_scoped(self) -> bool:
        return bool(self.case_id or self.artifact_id)


def parse_scoped_session_key(session_key: str) -> SessionScope:
    """Parse case/artifact markers from a session key."""
    artifact_match = re.search(r":artifact:([^:]+)$", session_key)
    case_match = re.search(r":case:([^:]+)(?::artifact:[^:]+)?$", session_key)

    artifact_id = artifact_match.group(1) if artifact_match else None
    case_id = case_match.group(1) if case_match else None

    if case_match:
        base_key = session_key[:case_match.start()]
    elif artifact_match:
        base_key = session_key[:artifact_match.start()]
    else:
        base_key = session_key

    return SessionScope(
        session_key=session_key,
        base_key=base_key,
        case_id=case_id,
        artifact_id=artifact_id,
    )
