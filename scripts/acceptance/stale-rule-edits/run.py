#!/usr/bin/env python3
"""Check stale rule edits through the packaged API and an independent TCP receiver."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
NAME = "stale-rule-edits"


def exercise(case):
    from scenarios import A

    allow = case.rule("allow")
    block = case.edit(allow, action="block")
    assert (block["id"], block["version"], block["action"]) == (
        allow["id"], allow["version"] + 1, "block"
    ), block
    original_generation = case.api()["generation"]

    def refusal(label, rule, generation, code):
        state = case.api()
        assert (generation != state["generation"], rule["version"] != block["version"]) == (
            code == "generation_conflict", code == "version_conflict"
        ), (label, generation, rule, state["generation"], block)
        request = {
            "operation": "rule-save",
            "generation": generation,
            "zone_revision": state["network_zones"]["revision"],
            "id": rule["id"],
            "expected_version": rule["version"],
            "rule": {**rule, "action": "allow"},
        }
        # The normal lab client raises on API errors. Read this expected error
        # via the same enrolled user's guest-side API channel.
        response = case.api.channel.call(**request)
        case.record(label, {"request": request, "current_generation": state["generation"],
                            "stored_version": block["version"], "response": response})
        assert response.get("error_code") == code and response.get("error"), response
        assert not response.get("saved_rule"), response
        saved = case.rules()[block["id"]]
        assert saved == block, saved
        case.record("stored-block", saved)
        attempt = case.dial(A, label)
        case.denied(attempt, rule=block["id"])
        verdict = case.log(attempt, action="block", rule=block["id"], source="rule")
        assert verdict["generation"] == state["generation"], verdict
        assert str(verdict["decision"]["rule"]["version"]) == str(block["version"]), verdict
        receiver = case.count(attempt["label"])
        assert receiver["count"] == 0, receiver
        case.record("blocked-probe", {"label": label, "flow": attempt, "client": case.status(attempt),
                                     "final": verdict, "receiver": receiver})
        case.close(attempt)

    refusal("stale-version", allow, original_generation, "version_conflict")
    case.restart(block)
    active_generation = case.api()["generation"]
    assert active_generation != original_generation, active_generation
    refusal("stale-generation", block, original_generation, "generation_conflict")

    saved = case.edit(block, action="allow")
    assert (saved["id"], saved["version"], saved["action"]) == (
        block["id"], block["version"] + 1, "allow"
    ), saved
    attempt = case.allowed(A, saved["id"], "current-edit")
    verdict = case.log(attempt, action="allow", rule=saved["id"], source="rule")
    assert str(verdict["decision"]["rule"]["version"]) == str(saved["version"]), verdict
    receiver = case.count(attempt["label"])
    assert receiver["count"] == 1, receiver
    case.record("allowed-control", {"rule": saved, "flow": attempt, "client": case.status(attempt),
                                    "final": verdict, "receiver": receiver})
    case.close(attempt)


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="debian-13", choices=("debian-13", "ubuntu-26.04", "fedora-45"))
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--installer-sha256", required=True)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.lab.resolve()))
    import lab
    import vm

    vm.RUNS = ROOT / ".workspace/stale-rule-edits/runs"
    lab.RULE_CASES[NAME] = exercise
    lab.SCENARIOS[NAME] = exercise
    lab.RESTART_CASES.add(NAME)
    args.profile = args.lab / "profiles" / (args.profile + ".json")
    args.scenario = [NAME]
    args.keep_failed = False
    return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
