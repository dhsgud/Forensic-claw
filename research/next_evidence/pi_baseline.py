"""Ask the configured Pi model for a budget-three policy without revealing test outcomes."""

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

from forensic_claw.forensics.evidence_policy import EvidenceProblem, recommend_evidence
from research.next_evidence.benchmark import prepare, split_archives
from research.next_evidence.capture_browser import model

MODEL = "nvidia/Qwen3.8-Flash-Next-NVFP4-QAD"
PI_MODEL_ALIAS = "llamacpp/coder390"
BUDGET = 3
PROMPT = """Choose a contingent policy to resolve the most equally likely hypotheses
into supported/refuted under budget three. Stop when all compatible hypotheses have
the same verdict. Each check is paid once each time it is performed in a trial.
On a tie prefer the policy with smaller expected total cost. Return JSON only:
{"check":"CHECK_ID","branches":{"OUTCOME":null,"ANOTHER_OUTCOME":{"check":"ID","branches":{}}}}.
Use null to stop. Branch keys must be exact outcome strings. The evaluator
determines the verdict from the available observations. Here is the case model:
"""


def evaluate(raw, definition, samples):
    case = EvidenceProblem.model_validate(definition)
    text = raw.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    tree = json.loads(text)
    checks = {check.id: check.cost for check in case.checks}
    rows = []
    for trial, truth, results in samples:
        observations = {}
        remaining = BUDGET
        node = tree
        policy_error = None
        while node is not None:
            current = recommend_evidence(case, observations, 0)
            if current["status"] != "abstain":
                break
            if not isinstance(node, dict) or not isinstance(node.get("branches"), dict):
                policy_error = "invalid_node"
                break
            check = node.get("check")
            if not isinstance(check, str) or check not in checks or check in observations:
                policy_error = "unknown_or_repeated_check"
                break
            if checks[check] > remaining:
                policy_error = "over_budget"
                break
            remaining -= checks[check]
            observations[check] = results[check]
            if results[check] not in node["branches"]:
                policy_error = "missing_branch"
                break
            node = node["branches"][results[check]]
        status = recommend_evidence(case, observations, 0)["status"]
        rows.append(
            {
                "trial": trial,
                "truth": truth,
                "verdict": status,
                "spent": BUDGET - remaining,
                "policy_error": policy_error,
            }
        )
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("records", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--recorded", type=Path, help="Replay saved model responses without calls")
    args = parser.parse_args()
    records = json.loads(args.records.read_text(encoding="utf-8"))
    cases = {
        "standard": (model(), prepare(records)),
        "split_archives": split_archives(records),
    }
    if args.recorded:
        previous = json.loads(args.recorded.read_text(encoding="utf-8"))
        output = {}
        for name, (definition, samples) in cases.items():
            old = previous[name]
            if definition != old["input"] or old["budget"] != BUDGET:
                parser.error(f"case model or budget differs for {name}")
            holdout = [sample for sample in samples if not sample[0].startswith("b0-")]
            report = {"model": old["model"], "budget": BUDGET}
            if "rows" in old:
                report["rows"] = evaluate(old["response"], definition, holdout)
            elif "recovered_rows" in old:
                blocks = re.findall(r"```json\s*([\s\S]*?)```", old["response"])
                if len(blocks) != 1:
                    parser.error(f"expected one JSON block for {name}")
                report["error"] = old["error"]
                report["recovered_rows"] = evaluate(blocks[0], definition, holdout)
            else:
                report["error"] = old["error"]
            output[name] = report
        with args.output.open("x", encoding="utf-8") as file:
            json.dump(output, file, ensure_ascii=False, indent=2)
        parser.exit()

    shim, node = shutil.which("pi.cmd"), shutil.which("node")
    if not shim or not node:
        parser.error("Pi and Node.js must be available")
    entry = Path(shim).parent / "node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js"
    output = {}
    for name, (definition, samples) in cases.items():
        prompt = PROMPT + json.dumps(definition)
        result = subprocess.run(
            [
                node,
                str(entry),
                "-p",
                "--offline",
                "--no-tools",
                "--no-extensions",
                "--no-mcp",
                "--no-skills",
                "--no-context-files",
                "--no-session",
                "--model",
                PI_MODEL_ALIAS,
                "--thinking",
                "low",
                "--",
                prompt,
            ],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
        )
        response = result.stdout.strip()
        report = {
            "model": MODEL,
            "pi_model_alias": PI_MODEL_ALIAS,
            "budget": BUDGET,
            "input": definition,
            "response": response,
        }
        if result.returncode:
            report["error"] = f"Pi exit code {result.returncode}"
        else:
            try:
                report["rows"] = evaluate(
                    response,
                    definition,
                    [sample for sample in samples if not sample[0].startswith("b0-")],
                )
            except (ValueError, IndexError):
                report["error"] = "invalid JSON"
        output[name] = report
    with args.output.open("x", encoding="utf-8") as file:
        json.dump(output, file, ensure_ascii=False, indent=2)
