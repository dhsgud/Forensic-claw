"""Integrity hashing tools for local evidence files."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from forensic_claw.agent.tools.base import Tool
from forensic_claw.utils.hashing import (
    DEFAULT_HASH_ALGORITHMS,
    SUPPORTED_HASH_ALGORITHMS,
    calculate_file_hashes,
    normalize_hash_algorithms,
    verify_hashes,
)


def _is_under(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory.resolve())
        return True
    except ValueError:
        return False


class HashVerifyTool(Tool):
    """Calculate hashes and optionally compare them against expected values."""

    def __init__(self, *, workspace: Path | None = None, allowed_dir: Path | None = None) -> None:
        self._workspace = workspace
        self._allowed_dir = allowed_dir

    @property
    def name(self) -> str:
        return "hash_verify"

    @property
    def description(self) -> str:
        return (
            "Calculate file integrity hashes and optionally verify expected values. "
            "Use this for evidence integrity checks before or after analysis. "
            "Returns MD5/SHA1/SHA256/SHA384/SHA512 values as JSON."
        )

    @property
    def parameters(self) -> dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path to hash. Relative paths resolve from the workspace.",
                },
                "algorithms": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(SUPPORTED_HASH_ALGORITHMS)},
                    "description": (
                        "Hash algorithms to calculate. Defaults to "
                        f"{', '.join(DEFAULT_HASH_ALGORITHMS)}."
                    ),
                },
                "expected": {
                    "type": "object",
                    "description": "Optional map of algorithm name to expected hex digest.",
                },
            },
            "required": ["path"],
        }

    async def execute(
        self,
        path: str,
        algorithms: list[str] | None = None,
        expected: dict[str, Any] | None = None,
        **_: Any,
    ) -> str:
        try:
            resolved = self._resolve(path)
            if not resolved.exists():
                return f"Error: File not found: {path}"
            if not resolved.is_file():
                return f"Error: Not a file: {path}"
            requested = list(algorithms or DEFAULT_HASH_ALGORITHMS)
            if expected:
                requested.extend(str(algorithm) for algorithm in expected)
            selected = normalize_hash_algorithms(requested)
            hashes = await asyncio.to_thread(calculate_file_hashes, resolved, selected)
            verification = verify_hashes(hashes, expected)
            payload = {
                "path": str(resolved),
                "fileName": resolved.name,
                "sizeBytes": resolved.stat().st_size,
                "algorithms": selected,
                "hashes": hashes,
                "verification": verification,
            }
            return json.dumps(payload, ensure_ascii=False, indent=2)
        except Exception as exc:
            return f"Error: {exc}"

    def _resolve(self, path: str) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute() and self._workspace:
            candidate = self._workspace / candidate
        resolved = candidate.resolve()
        if self._allowed_dir and not _is_under(resolved, self._allowed_dir):
            raise PermissionError(f"Path {path} is outside allowed directory {self._allowed_dir}")
        return resolved
