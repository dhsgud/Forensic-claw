from hypothesis import given
from hypothesis import strategies as st

from forensic_claw.forensics.evidence_policy import EvidenceProblem, recommend_evidence


def problem():
    return EvidenceProblem.model_validate(
        {
            "checks": [
                {"id": "signature", "cost": 2},
                {"id": "profile", "cost": 1},
                {"id": "row", "cost": 1},
            ],
            "hypotheses": [
                {
                    "id": "same",
                    "verdict": "supported",
                    "outcomes": {
                        "signature": "present",
                        "profile": "match",
                        "row": "match",
                    },
                },
                {
                    "id": "other_profile",
                    "verdict": "refuted",
                    "outcomes": {
                        "signature": "present",
                        "profile": "different",
                        "row": "match",
                    },
                },
                {
                    "id": "other_row",
                    "verdict": "refuted",
                    "outcomes": {
                        "signature": "absent",
                        "profile": "match",
                        "row": "different",
                    },
                },
            ],
        }
    )


def test_plan_resolves_more_worlds_when_a_second_check_is_affordable():
    plan = recommend_evidence(problem(), {}, 2)
    assert plan["status"] == "abstain"
    assert plan["next_check"]["id"] == "profile"
    assert plan["resolved_worlds"] == 3
    assert plan["next_check"]["outcomes"] == {"different": "refuted", "match": "abstain"}


def test_unmodeled_observation_keeps_judgment_open():
    result = recommend_evidence(problem(), {"profile": "unreadable"}, 2)
    assert result["status"] == "inconsistent"
    assert result["next_check"] is None


@given(st.integers(min_value=0, max_value=20))
def test_no_recommendation_exceeds_remaining_budget_when_budget_varies(budget):
    plan = recommend_evidence(problem(), {}, budget)
    check = plan["next_check"]
    if check:
        assert 0 < check["cost"] <= budget
    else:
        assert budget == 0


def test_plan_returns_no_check_when_available_outcomes_cannot_separate_verdicts():
    case = EvidenceProblem.model_validate(
        {
            "checks": [{"id": "copied_hash", "cost": 1}],
            "hypotheses": [
                {"id": "copied_here", "verdict": "supported", "outcomes": {"copied_hash": "same"}},
                {
                    "id": "already_present",
                    "verdict": "refuted",
                    "outcomes": {"copied_hash": "same"},
                },
            ],
        }
    )
    result = recommend_evidence(case, {}, 3)
    assert result["status"] == "abstain"
    assert result["resolved_worlds"] == 0
    assert result["next_check"] is None
