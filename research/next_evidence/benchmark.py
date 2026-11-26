"""Replay acquired browser observations under a fixed set of query policies."""

import argparse
import itertools
import json
from collections import Counter
from pathlib import Path

from forensic_claw.forensics.evidence_policy import EvidenceProblem, recommend_evidence
from research.next_evidence.capture_browser import model, verdict

BUDGETS = (1, 2, 3, 4, 5)
COST_PROFILES = {
    "standard": {},
    "cheap_full_history": {"full_history": 2},
    "expensive_origin": {"final_origin": 4, "server_log": 2},
}


def replay(case, check_results, budget, policy, order=()):
    observed = {}
    spent = 0
    checks = {check.id: check for check in case.checks}
    while True:
        current = recommend_evidence(case, observed, 0)
        if current["status"] != "abstain":
            return current["status"], spent, list(observed)
        available = [
            key for key in checks if key not in observed and checks[key].cost <= budget - spent
        ]
        if not available:
            return "abstain", spent, list(observed)
        if policy == "lookahead":
            option = recommend_evidence(case, observed, budget - spent)["next_check"]
            if option is None:
                return "abstain", spent, list(observed)
            key = option["id"]
        elif policy == "greedy":
            remaining = [h for h in case.hypotheses if h.id in current["remaining_hypotheses"]]
            pairs = [
                (a, b) for a, b in itertools.combinations(remaining, 2) if a.verdict != b.verdict
            ]
            scores = {
                candidate: sum(a.outcomes[candidate] != b.outcomes[candidate] for a, b in pairs)
                / checks[candidate].cost
                for candidate in available
            }
            key = max(available, key=scores.__getitem__)
            if not scores[key]:
                return "abstain", spent, list(observed)
        else:
            key = next(key for key in order if key in available)
        spent += checks[key].cost
        observed[key] = check_results[key]


def prepare(records):
    expected_digest = records["payload_sha256"]
    return [
        (
            row["trial"],
            verdict(row["profile"], row["server_origin"]),
            {
                "payload": "match" if row["sha256"] == expected_digest else "different",
                "full_history": f"{row['profile']}:{row['origin']}",
                "entry_hint": row["hint"],
                "profile": row["profile"],
                "final_origin": row["origin"],
                "server_log": row["server_origin"] if row["hint"] != "mirror" else "unavailable",
            },
        )
        for row in records["trials"]
    ]


def split_archives(records):
    # These checks read the corresponding profile archive; an absent bundle is observable.
    definition = model()
    definition["checks"] = [
        {"id": "payload", "cost": 1},
        {"id": "profile", "cost": 1},
        {"id": "target_archive", "cost": 2},
        {"id": "other_archive", "cost": 2},
    ]

    def outcomes(observed):
        profile, origin = observed["profile"], observed["final_origin"]
        return {
            "payload": observed["payload"],
            "profile": profile,
            "target_archive": origin if profile == "target" else "unavailable",
            "other_archive": origin if profile == "other" else "unavailable",
        }

    def approved(profile, origin):
        return "supported" if (profile, origin) in {("target", "a"), ("other", "b")} else "refuted"

    for hypothesis in definition["hypotheses"]:
        observed = hypothesis["outcomes"]
        hypothesis["verdict"] = approved(observed["profile"], observed["final_origin"])
        hypothesis["outcomes"] = outcomes(observed)
    samples = [
        (
            row["trial"],
            approved(row["profile"], row["server_origin"]),
            outcomes(
                {
                    "profile": row["profile"],
                    "final_origin": row["origin"],
                    "payload": "match"
                    if row["sha256"] == records["payload_sha256"]
                    else "different",
                }
            ),
        )
        for row in records["trials"]
    ]
    return definition, samples


def evaluate(records):
    rows = []
    scenarios = []
    for profile, changes in COST_PROFILES.items():
        definition = model()
        for check in definition["checks"]:
            check["cost"] = changes.get(check["id"], check["cost"])
        scenarios.append((profile, definition, prepare(records)))
    scenarios.append(("split_archives", *split_archives(records)))

    for profile, definition, samples in scenarios:
        development = [sample for sample in samples if sample[0].startswith("b0-")]
        holdout = [sample for sample in samples if not sample[0].startswith("b0-")]
        assert len(development) == 8 and len(holdout) >= 8
        problem = EvidenceProblem.model_validate(definition)
        fixed = tuple(check.id for check in problem.checks)
        for budget in BUDGETS:

            def development_score(order):
                results = [
                    (replay(problem, data, budget, "fixed", order), truth)
                    for _, truth, data in development
                ]
                return sum(r[0] == truth for r, truth in results), -sum(r[1] for r, _ in results)

            tuned = max(itertools.permutations(fixed), key=development_score)
            for policy, order in (
                ("checklist", fixed),
                ("best_fixed_dev", tuned),
                ("greedy", ()),
                ("lookahead", ()),
            ):
                for trial, truth, data in holdout:
                    status, spent, queried = replay(problem, data, budget, policy, order)
                    rows.append(
                        {
                            "cost_profile": profile,
                            "budget": budget,
                            "policy": policy,
                            "trial": trial,
                            "truth": truth,
                            "verdict": status,
                            "spent": spent,
                            "queried": queried,
                        }
                    )
    return rows


def summarize(rows):
    summary = {}
    for row in rows:
        key = f"{row['cost_profile']}/{row['budget']}/{row['policy']}"
        counts = summary.setdefault(key, Counter())
        counts["trials"] += 1
        counts["correct"] += row["verdict"] == row["truth"]
        counts["abstained"] += row["verdict"] == "abstain"
        counts["incorrect"] += row["verdict"] not in {row["truth"], "abstain"}
        counts["spent"] += row["spent"]
        assert row["spent"] <= row["budget"]
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = json.loads(args.records.read_text(encoding="utf-8"))
    rows = evaluate(data)
    summary = json.dumps(summarize(rows), indent=2)
    records = ",\n".join("    " + json.dumps(row) for row in rows)
    args.output.write_text(
        '{"summary": ' + summary + ', "rows": [\n' + records + "\n]}\n",
        encoding="utf-8",
    )
