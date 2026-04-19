"""Helpers that prepare external inputs for case source registration."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from forensic_claw.forensics.hashes import sha256_bytes, sha256_file

IngestPolicy = Literal["copy", "reference"]


@dataclass(frozen=True)
class PreparedSourceIngest:
    label: str
    origin_path: str | None
    sha256: str
    size: int
    storage_policy: IngestPolicy
    raw_files: dict[str, bytes] = field(default_factory=dict)


def _validate_policy(policy: str) -> IngestPolicy:
    if policy not in {"copy", "reference"}:
        raise ValueError("policy must be either 'copy' or 'reference'")
    return policy


def prepare_source_ingest(
    *,
    source_path: str | Path | None = None,
    content: str | bytes | None = None,
    filename: str | None = None,
    label: str | None = None,
    origin_path: str | None = None,
    policy: str = "copy",
) -> PreparedSourceIngest:
    resolved_policy = _validate_policy(policy)

    if (source_path is None) == (content is None):
        raise ValueError("Provide exactly one of source_path or content")

    if source_path is not None:
        path = Path(source_path).expanduser()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Source file not found: {path}")

        resolved_path = path.resolve(strict=False)
        file_label = label or path.name
        file_name = filename or path.name
        if resolved_policy == "copy":
            raw_bytes = path.read_bytes()
            return PreparedSourceIngest(
                label=file_label,
                origin_path=origin_path or str(resolved_path),
                sha256=sha256_bytes(raw_bytes),
                size=len(raw_bytes),
                storage_policy=resolved_policy,
                raw_files={file_name: raw_bytes},
            )

        return PreparedSourceIngest(
            label=file_label,
            origin_path=origin_path or str(resolved_path),
            sha256=sha256_file(path),
            size=path.stat().st_size,
            storage_policy=resolved_policy,
        )

    if resolved_policy == "reference":
        raise ValueError("reference policy requires source_path")
    if not filename:
        raise ValueError("filename is required when content is provided")

    raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
    if raw_bytes is None:
        raise ValueError("content must not be None")

    return PreparedSourceIngest(
        label=label or filename,
        origin_path=origin_path or filename,
        sha256=sha256_bytes(raw_bytes),
        size=len(raw_bytes),
        storage_policy=resolved_policy,
        raw_files={filename: raw_bytes},
    )
