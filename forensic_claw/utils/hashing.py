"""File hashing and integrity verification helpers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

SUPPORTED_HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha384", "sha512")
DEFAULT_HASH_ALGORITHMS = ("md5", "sha256", "sha512")
_HEXISH_RE = re.compile(r"[^0-9a-fA-F]")


def normalize_hash_algorithm(name: str) -> str:
    """Normalize human-friendly hash names to hashlib names."""
    normalized = str(name or "").strip().lower().replace("-", "")
    aliases = {
        "sha": "sha1",
        "sha2": "sha256",
        "sha256sum": "sha256",
        "sha512sum": "sha512",
        "md5sum": "md5",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(
            f"Unsupported hash algorithm '{name}'. Supported: {', '.join(SUPPORTED_HASH_ALGORITHMS)}"
        )
    return normalized


def normalize_hash_algorithms(algorithms: list[str] | tuple[str, ...] | None) -> list[str]:
    """Return a de-duplicated list of supported hash algorithms."""
    requested = algorithms or DEFAULT_HASH_ALGORITHMS
    normalized: list[str] = []
    for item in requested:
        algorithm = normalize_hash_algorithm(item)
        if algorithm not in normalized:
            normalized.append(algorithm)
    return normalized


def calculate_file_hashes(
    path: Path,
    algorithms: list[str] | tuple[str, ...] | None = None,
    *,
    chunk_size: int = 1024 * 1024,
) -> dict[str, str]:
    """Calculate multiple hashes for one file in a single streaming pass."""
    selected = normalize_hash_algorithms(algorithms)
    hashers = {algorithm: _new_hasher(algorithm) for algorithm in selected}
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algorithm: hasher.hexdigest() for algorithm, hasher in hashers.items()}


def verify_hashes(
    actual_hashes: dict[str, str],
    expected_hashes: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compare calculated hashes with expected values."""
    expected_hashes = expected_hashes or {}
    results: dict[str, dict[str, Any]] = {}
    for raw_algorithm, raw_expected in expected_hashes.items():
        algorithm = normalize_hash_algorithm(raw_algorithm)
        expected = _normalize_expected_hash(raw_expected)
        actual = str(actual_hashes.get(algorithm) or "").lower()
        results[algorithm] = {
            "expected": expected,
            "actual": actual,
            "match": bool(expected) and actual == expected,
        }
    checked = bool(results)
    return {
        "checked": checked,
        "ok": all(item["match"] for item in results.values()) if checked else None,
        "results": results,
    }


def _new_hasher(algorithm: str) -> "hashlib._Hash":
    try:
        return hashlib.new(algorithm, usedforsecurity=False)
    except TypeError:
        return hashlib.new(algorithm)


def _normalize_expected_hash(value: Any) -> str:
    text = str(value or "").strip()
    if ":" in text:
        text = text.rsplit(":", 1)[-1]
    if "=" in text:
        text = text.rsplit("=", 1)[-1]
    return _HEXISH_RE.sub("", text).lower()
