from __future__ import annotations

from forensic_claw.utils.hashing import calculate_file_hashes, verify_hashes


def test_calculate_file_hashes_returns_common_integrity_digests(tmp_path) -> None:
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"forensic-claw")

    hashes = calculate_file_hashes(evidence, ["md5", "sha256", "sha512"])

    assert hashes == {
        "md5": "c59f8f3efc6c46663a6b6e2a42fbbed5",
        "sha256": "bf104522e8dc6035303a700952cf4341ca2f589bba2e48ec6ac0a8399cab8d98",
        "sha512": (
            "71a02364b6d7ca99b09b7ac484d7cb494756bc3683ce6cb2344525c5eb9536fe"
            "64f66d6e65172acd26a32ba99b21f52f9682a4de57d05e4c327377de92a42bbe"
        ),
    }


def test_verify_hashes_reports_matching_and_mismatching_expected_values(tmp_path) -> None:
    evidence = tmp_path / "evidence.txt"
    evidence.write_text("hash me", encoding="utf-8")
    hashes = calculate_file_hashes(evidence, ["sha256", "sha512"])

    verification = verify_hashes(
        hashes,
        {
            "SHA-256": hashes["sha256"].upper(),
            "sha512": "deadbeef",
        },
    )

    assert verification["checked"] is True
    assert verification["ok"] is False
    assert verification["results"]["sha256"]["match"] is True
    assert verification["results"]["sha512"]["match"] is False
