"""Ensure the repository root is importable during pytest collection."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
root_str = str(ROOT)

if root_str not in sys.path:
    sys.path.insert(0, root_str)


@pytest.fixture
def prefetch_pecmd_runner():
    fixture = ROOT / "tests" / "fixtures" / "windows" / "prefetch" / "pecmd-output.jsonl"

    def _runner(**_: object) -> str:
        return fixture.read_text(encoding="utf-8")

    return _runner
