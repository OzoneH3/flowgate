#!/usr/bin/env python3
"""Check rule edit guards through the packaged API and an independent TCP receiver."""
import argparse
from contextlib import ExitStack
from functools import partial
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
NAME = "stale-rule-edits"
MONITOR_CASE = "monitor-socket-rule-edit"
PRIMARY_SOCKET = "/run/flowgate-api/daemon.sock"


def rule_probe(case, rule, generation, label):
    from scenarios import A

    attempt = case.dial(A, label)
    if rule["action"] == "block":
        case.denied(attempt, rule=rule["id"])
    else:
        case.delivered(attempt)
    verdict = case.log(attempt, action=rule["action"], rule=rule["id"], source="rule")
    assert verdict["generation"] == generation, verdict
    assert str(verdict["decision"]["rule"]["version"]) == str(rule["version"]), verdict
    receiver = case.count(attempt["label"])
    assert receiver["count"] == (1 if rule["action"] == "allow" else 0), receiver
    case.record(label, {"rule": rule, "flow": attempt, "client": case.status(attempt),
                        "final": verdict, "receiver": receiver})
    case.close(attempt)


def exercise(case):
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
        rule_probe(case, block, state["generation"], "blocked-probe-" + label)

    refusal("stale-version", allow, original_generation, "version_conflict")
    case.restart(block)
    active_generation = case.api()["generation"]
    assert active_generation != original_generation, active_generation
    refusal("stale-generation", block, original_generation, "generation_conflict")

    saved = case.edit(block, action="allow")
    assert (saved["id"], saved["version"], saved["action"]) == (
        block["id"], block["version"] + 1, "allow"
    ), saved
    rule_probe(case, saved, active_generation, "allowed-control")


def exercise_monitor(case, monitor):
    block = case.rule("block")
    assert block["action"] == "block", block
    primary = case.api()
    generation = primary["generation"]
    rule_probe(case, block, generation, "initial-block")

    observed = monitor.call(operation="list")
    assert not observed.get("error"), observed.get("error")
    assert observed["generation"] == generation
    assert observed["peer_uid"] == primary["peer_uid"] == case.probe.hello["uid"] != 0
    assert not primary["read_only"] and observed["read_only"]
    assert primary["permissions"]["role"] == observed["permissions"]["role"] == "administrator"
    assert primary["permissions"]["can_manage_rules"] and not observed["permissions"]["can_manage_rules"]
    assert next(rule for rule in observed["rules"] if rule["id"] == block["id"]) == block
    for channel, state in ((case.api.channel, primary), (monitor, observed)):
        case.record("socket-read", {"socket": channel.hello["socket"], **{
            field: state[field] for field in ("peer_uid", "generation", "read_only", "permissions")
        }})
    assert case.api.channel.hello["socket"] == PRIMARY_SOCKET
    assert monitor.hello["socket"] == PRIMARY_SOCKET + ".monitor"

    fields = dict(generation=generation, zone_revision=primary["network_zones"]["revision"],
                  id=block["id"], expected_version=block["version"],
                  rule={**block, "action": "allow"})
    preview = case.api("rule-preview", **fields)["saved_rule"]
    assert (preview["id"], preview["action"], preview["filter"]) == (
        block["id"], "allow", block["filter"]
    ), preview
    request = {"operation": "rule-save", **fields}
    refused = monitor.call(**request)
    case.record("monitor-edit", {"request": request, "response": refused})
    assert (refused.get("error_code"), refused.get("error")) == ("read_only", "read-only API"), refused
    assert not refused.get("saved_rule"), refused
    assert case.rules()[block["id"]] == block
    case.record("stored-block-after-refusal", block)
    rule_probe(case, block, generation, "after-monitor-refusal")

    current = case.api()
    assert current["generation"] == generation
    assert next(rule for rule in current["rules"] if rule["id"] == block["id"]) == block
    response = case.api.channel.call(**request)
    case.record("primary-edit", {"request": request, "response": response})
    assert not response.get("error"), response
    saved = response["saved_rule"]
    assert (saved["id"], saved["version"], saved["action"], saved["filter"]) == (
        block["id"], block["version"] + 1, "allow", block["filter"]
    ), saved
    assert case.rules()[saved["id"]] == saved
    rule_probe(case, saved, generation, "after-primary-save")


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=(NAME, MONITOR_CASE), default=NAME)
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

    vm.RUNS = ROOT / ".workspace" / args.case / "runs"
    args.profile = args.lab / "profiles" / (args.profile + ".json")
    args.scenario = [args.case]
    args.keep_failed = False
    with ExitStack() as channels:
        if args.case == MONITOR_CASE:
            configure_sut = lab.configure_sut

            def configure_monitor(sut):
                configure_sut(sut)
                # Track this SSH transport before the runner activates protection.
                monitor = sut.channel(f"python3 fg-lab/guest_tools.py flowgate {PRIMARY_SOCKET}.monitor",
                                      "monitor-api")
                channels.callback(monitor.close)
                lab.RULE_CASES[MONITOR_CASE] = lab.SCENARIOS[MONITOR_CASE] = partial(
                    exercise_monitor, monitor=monitor
                )

            lab.configure_sut = configure_monitor
        else:
            lab.RULE_CASES[NAME] = exercise
            lab.SCENARIOS[NAME] = exercise
            lab.RESTART_CASES.add(NAME)
        return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
