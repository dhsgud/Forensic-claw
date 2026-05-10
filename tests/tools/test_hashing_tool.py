from __future__ import annotations

import hashlib
import json

import pytest

from forensic_claw.agent.tools.hashing import HashVerifyTool


@pytest.mark.asyncio
async def test_hash_verify_tool_returns_hashes_and_verification_when_expected_matches(tmp_path) -> None:
    evidence = tmp_path / "artifact.bin"
    evidence.write_bytes(b"integrity evidence")
    expected_sha256 = hashlib.sha256(b"integrity evidence").hexdigest()
    tool = HashVerifyTool(workspace=tmp_path, allowed_dir=tmp_path)

    payload = json.loads(
        await tool.execute(
            path="artifact.bin",
            algorithms=["md5", "sha256"],
            expected={"SHA-512": hashlib.sha512(b"integrity evidence").hexdigest()},
        )
    )

    assert payload["path"] == str(evidence)
    assert payload["hashes"]["md5"] == hashlib.md5(b"integrity evidence").hexdigest()
    assert payload["hashes"]["sha256"] == expected_sha256
    assert payload["hashes"]["sha512"] == hashlib.sha512(b"integrity evidence").hexdigest()
    assert payload["verification"]["ok"] is True
    assert payload["verification"]["results"]["sha512"]["match"] is True


@pytest.mark.asyncio
async def test_hash_verify_tool_reports_error_when_path_is_outside_allowed_workspace(tmp_path) -> None:
    outside = tmp_path.parent / "outside.bin"
    outside.write_bytes(b"outside")
    tool = HashVerifyTool(workspace=tmp_path, allowed_dir=tmp_path)

    result = await tool.execute(path=str(outside))

    assert result.startswith("Error:")
    assert "outside allowed directory" in result
