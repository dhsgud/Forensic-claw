"""Evaluate direct SQL and provenance requirements using captured lookup records."""

import argparse
import json
from collections import Counter
from pathlib import Path
from statistics import median

from forensic_claw.forensics.evidence_policy import EvidenceProblem, recommend_evidence

PROFILES = ("target", "other")


def planner(origin_by_profile, known_profile=None, manifest=None):
    problem = EvidenceProblem.model_validate(
        {
            "checks": [{"id": "profile_manifest", "cost": 1}],
            "hypotheses": [
                {
                    "id": f"{profile}:{origin}",
                    "verdict": "supported" if origin == "a" else "refuted",
                    "outcomes": {"profile_manifest": profile},
                }
                for profile, origin_set in origin_by_profile.items()
                for origin in origin_set
            ],
        }
    )
    report = recommend_evidence(
        problem, {"profile_manifest": known_profile} if known_profile else {}, 1
    )
    next_check = report["next_check"]
    recommendation = next_check["id"] if next_check else None
    if manifest and recommendation:
        report = recommend_evidence(problem, {"profile_manifest": manifest}, 0)
    result = {"supported": "a", "refuted": "b"}.get(report["status"])
    return result, recommendation


def evaluate(records):
    trials = records["trials"]
    indexed = {
        (row["trial"].split("-")[0], row["profile"], row["download_row"]): row for row in trials
    }
    assert len(indexed) == len(trials)
    details = []
    for row in trials:
        batch = row["trial"].split("-")[0]
        target = row["profile"]
        actual = row["server_origin"]
        accessible = {
            profile: (indexed[batch, profile, row["download_row"]]["direct_origin"],)
            for profile in PROFILES
        }
        assert accessible["target"] != accessible["other"]
        for condition, known, manifest, available in (
            ("identified", target, None, accessible),
            ("ambiguous", None, None, accessible),
            ("manifest_available", None, target, accessible),
            (
                "history_missing",
                target,
                None,
                {
                    **accessible,
                    target: ("a", "b"),
                },
            ),
        ):
            origins = {
                origin
                for profile, values in available.items()
                if profile == known or known is None
                for origin in values
            }
            sql = next(iter(origins)) if len(origins) == 1 else None
            sql_with_manifest = available[manifest][0] if manifest else sql
            recommendation = None
            if condition == "identified":
                forecast = sql
            else:
                forecast, recommendation = planner(available, known, manifest)
            details.append(
                {
                    "trial": row["trial"],
                    "condition": condition,
                    "truth": actual,
                    "direct_sql": sql,
                    "sql_with_manifest": sql_with_manifest,
                    "forensic_claw": forecast,
                    "recommended": recommendation,
                }
            )
    summary = {}
    for row in details:
        count = summary.setdefault(row["condition"], Counter())
        count["trials"] += 1
        for method in ("direct_sql", "sql_with_manifest", "forensic_claw"):
            value = row[method]
            category = (
                "abstain"
                if value is None
                else ("correct" if value == row["truth"] else "incorrect")
            )
            count[f"{method}_{category}"] += 1
    return {
        "browser": records["browser"],
        "lookup_median_us": median(row["direct_lookup_us"] for row in trials),
        "summary": summary,
        "details": details,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    source = json.loads(args.records.read_text(encoding="utf-8"))
    with args.output.open("x", encoding="utf-8") as result:
        json.dump(evaluate(source), result, indent=2)
