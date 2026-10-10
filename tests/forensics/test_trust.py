from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from forensic_claw.forensics.trust import EvidenceObject, HallucinationDetector, TrustGrade


def evidence(id="a", sha="a" * 64, **changes):
    values = dict(
        id=id,
        source="C:/evidence/log.txt",
        timestamp=datetime.now(UTC).isoformat(),
        hash_verified=True,
        sha256=sha,
        text="2026-05-07 powershell.exe connected to 10.0.0.5",
    )
    return EvidenceObject(**(values | changes))


def test_claim_is_partial_when_one_verified_artifact_supports_it():
    item = evidence()
    result = HallucinationDetector().check(item.text, [item.id], [item])
    assert result.grade == TrustGrade.PARTIAL
    assert result.issues == []


def test_claim_is_verified_when_two_distinct_artifacts_support_it():
    items = [evidence(), evidence(id="b", sha="b" * 64, source="C:/evidence/other.txt")]
    assert (
        HallucinationDetector().check(items[0].text, ["a", "b"], items).grade == TrustGrade.VERIFIED
    )


def test_claim_stays_partial_when_corroboration_is_a_copy_of_same_artifact():
    items = [evidence(), evidence(id="b", source="C:/copy/log.txt")]
    assert (
        HallucinationDetector().check(items[0].text, ["a", "b"], items).grade == TrustGrade.PARTIAL
    )


def test_claim_is_unverified_when_source_integrity_fails():
    item = evidence(hash_verified=False)
    result = HallucinationDetector().check(item.text, ["a"], [item])
    assert result.grade == TrustGrade.UNVERIFIED
    assert not item.eligible


def test_claim_is_flagged_when_timestamp_or_path_is_fabricated():
    result = HallucinationDetector().check(
        "2027-01-01 C:\\missing\\evil.exe executed", ["a"], [evidence()]
    )
    assert result.grade == TrustGrade.FLAGGED
    assert {"timestamp_mismatch", "unconfirmed_path", "unsupported_claim"} <= set(result.issues)


@given(st.sampled_from(["source", "timestamp", "sha256", "id"]), st.sampled_from(["", " "]))
def test_evidence_is_ineligible_when_required_provenance_is_blank(field, value):
    assert not evidence(**{field: value}).eligible


def test_claim_is_flagged_when_citation_is_missing_or_unknown():
    detector = HallucinationDetector()
    assert detector.check(evidence().text, [], [evidence()]).grade == TrustGrade.FLAGGED
    assert detector.check(evidence().text, ["invented"], [evidence()]).grade == TrustGrade.FLAGGED
