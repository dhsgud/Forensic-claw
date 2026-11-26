"""Recommend read-only evidence checks for a bounded, analyst-specified case model."""

from functools import cache
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Verdict = Literal["supported", "refuted"]


class EvidenceCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    cost: int = Field(gt=0)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    id: str = Field(min_length=1)
    verdict: Verdict
    outcomes: dict[str, str]


class EvidenceProblem(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    checks: list[EvidenceCheck] = Field(min_length=1, max_length=10)
    hypotheses: list[Hypothesis] = Field(min_length=2, max_length=32)

    @model_validator(mode="after")
    def validate_keys(self):
        check_ids = {check.id for check in self.checks}
        if len(check_ids) != len(self.checks):
            raise ValueError("check IDs must be unique")
        if len({world.id for world in self.hypotheses}) != len(self.hypotheses):
            raise ValueError("hypothesis IDs must be unique")
        if any(world.outcomes.keys() != check_ids for world in self.hypotheses):
            raise ValueError("each hypothesis must define an outcome for every check")
        if any(not value.strip() for world in self.hypotheses for value in world.outcomes.values()):
            raise ValueError("outcomes must be non-empty")
        return self


def recommend_evidence(
    problem: EvidenceProblem, observations: dict[str, str], budget: int
) -> dict[str, object]:
    """Maximize resolved hypotheses, then minimize their total modeled query cost."""
    checks = problem.checks
    worlds = problem.hypotheses
    if type(budget) is not int or budget < 0:
        raise ValueError("budget must be a non-negative integer")
    if observations.keys() - {check.id for check in checks}:
        raise ValueError("observations contain an unknown check ID")
    candidates = tuple(
        i
        for i, world in enumerate(worlds)
        if all(world.outcomes[key] == outcome for key, outcome in observations.items())
    )
    available = tuple(i for i, check in enumerate(checks) if check.id not in observations)

    def status(options: tuple[int, ...]) -> str:
        if not options:
            return "inconsistent"
        verdicts = {worlds[i].verdict for i in options}
        return verdicts.pop() if len(verdicts) == 1 else "abstain"

    def partition(options: tuple[int, ...], check_id: str) -> dict[str, tuple[int, ...]]:
        groups: dict[str, list[int]] = {}
        for i in options:
            groups.setdefault(worlds[i].outcomes[check_id], []).append(i)
        return {outcome: tuple(indices) for outcome, indices in groups.items()}

    @cache
    def search(
        options: tuple[int, ...], remaining: tuple[int, ...], funds: int
    ) -> tuple[int, int, int | None]:
        if status(options) != "abstain":
            return len(options), 0, None
        best = (0, 0, None)
        for index in remaining:
            check = checks[index]
            if check.cost > funds:
                continue
            groups = partition(options, check.id)
            if len(groups) < 2:
                continue
            rest = tuple(i for i in remaining if i != index)
            children = [search(group, rest, funds - check.cost) for group in groups.values()]
            resolved = sum(child[0] for child in children)
            cost = check.cost * len(options) + sum(child[1] for child in children)
            if (resolved, -cost) > (best[0], -best[1]):
                best = (resolved, cost, index)
        return best

    resolved, total_cost, selected = search(candidates, available, budget)
    next_check = None
    if selected is not None:
        check = checks[selected]
        next_check = {
            "id": check.id,
            "cost": check.cost,
            "outcomes": {
                outcome: status(group) for outcome, group in partition(candidates, check.id).items()
            },
        }
    return {
        "status": status(candidates),
        "remaining_hypotheses": [worlds[i].id for i in candidates],
        "resolved_worlds": resolved,
        "total_modeled_cost": total_cost,
        "next_check": next_check,
    }
