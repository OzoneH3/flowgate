#!/usr/bin/env python3
"""Verify the non-purge Fedora upgrade path with the two shipped RC8 pairs."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
NAME = "fedora-collector-upgrade"
ARCHIVE = "flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
INSTALLER = "flowgate-release.py"
OLD = (
    "7b3e8e51460bbe1858323027dd6573031b8f791d",
    "492dda11bf7386d8ffdda6c6fffe18a3eda8a0de8bf587bfe1414b3fc217b7f8",
    "7cd138504a541887afd6d55eb3451fdc7070825c828f8337d1e42b65b210bf45",
)
NEW = (
    "64a07da1ebdf7033622c8e77385bc99265f19279",
    "55f522e7f12f87f91bbcc5ab7c170c846abeed3f26ee8975b9b579b5b0fb01af",
    "94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c",
)


def package(folder, reference):
    source, archive_hash, installer_hash = reference
    return argparse.Namespace(archive=folder / ARCHIVE, installer=folder / INSTALLER,
                              archive_sha256=archive_hash, installer_sha256=installer_hash,
                              source=source)


def exercise(lab, vm, sut, receiver, old, new, evidence):
    from scenarios import A, Scenario

    directory = sut.directory
    record = lab.recorder(directory / f"{NAME}.jsonl")
    report = {"scenario": NAME, "result": "fail", "checks": {}}
    checks = report["checks"]
    try:
        assert evidence["installed_sha"] == old["source"] == OLD[0]
        report["old"] = {key: evidence[key] for key in
                         ("installed_sha", "archive_sha256", "installer_sha256", "installed_path")}
        (directory / "old-install.json").write_text((directory / "install.json").read_text())
        assert sut.run("getenforce").stdout.strip() == "Enforcing"
        lab.check_digest(new.archive, new.archive_sha256)
        lab.check_digest(new.installer, new.installer_sha256)
        candidate = lab.manifest(new.archive)
        assert candidate["source"] == new.source, candidate["source"]
        sut.upload(new.archive, "candidate.tar.gz")
        sut.upload(new.installer, "candidate.py")
        lab.configure_sut(sut)
        preflight = ("cd fg-lab && sudo -n /usr/bin/python3 -I -B ./candidate.py preflight "
                     f"--bundle candidate.tar.gz --sha256 {new.archive_sha256}")

        def preflight_result(name, expect_success=False):
            op = sut.run(preflight, check=False, timeout=90)
            checks[name] = {"exit": op.returncode, "stdout": op.stdout, "stderr": op.stderr}
            if expect_success:
                assert op.returncode == 0 and "Preflight passed" in op.stdout, checks[name]
            else:
                assert op.returncode != 0 and "Current collector is not settled" in op.stderr, checks[name]

        with sut.multiplex(), ExitStack() as stack:
            def channel(command, label):
                connection = sut.channel(command, label)
                stack.callback(connection.close)
                return connection

            endpoint = "python3 fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock"
            api = lab.FlowGate(channel(endpoint, "old-api"), record)
            case = Scenario(api, None, receiver, record)
            # This old service cannot reliably observe the probe's socket
            # under init_t. Use the administrator's exact TCP endpoint API.
            draft = {"action": "allow", "remote_address": A,
                     "remote_port": receiver.hello["port"], "expires": "0001-01-01T00:00:00Z"}
            fields = {"generation": api()["generation"], "endpoint_draft": draft}
            preview = api("endpoint-rule-preview", **fields)["endpoint_preview"]
            rule = api("endpoint-rule-save", preview_token=preview["token"], **fields)["saved_rule"]
            assert case.rules()[rule["id"]] == rule
            report["saved_rule_before"] = rule

            def collector(current_api, state):
                def read():
                    answer = current_api("traffic-status")
                    return answer if answer["traffic_monitor"]["state"] == state else None
                return vm.wait_for(read, 18, f"collector never reached {state}")

            failed = collector(api, "failed")
            checks["old_collector"] = failed["traffic_monitor"]
            assert failed["traffic_monitor"]["reason_code"] == "permission_required", failed
            assert "permission denied" in failed["traffic_monitor"]["reason"], failed
            preflight_result("preflight_with_failed_collector")
            stopped = api("traffic-stop", generation=failed["generation"],
                          collector_generation=failed["traffic_monitor"]["generation"])
            assert stopped["traffic_monitor"]["state"] == "disabled", stopped
            checks["explicit_collector_stop"] = collector(api, "disabled")["traffic_monitor"]
            preflight_result("preflight_with_disabled_collector")
            recovery = sut.run("sudo -n /usr/local/sbin/flowgate-recover", timeout=110)
            checks["monitoring_recovery"] = recovery.stdout
            again = collector(api, "failed")
            assert again["generation"] != failed["generation"], again
            assert case.rules()[rule["id"]] == rule
            checks["collector_after_recovery"] = again["traffic_monitor"]
        # The lab installer uploads files using scp, so leave the SSH mux
        # before removing the old release and installing the verified one.
        removal = sut.run("sudo -n /usr/local/sbin/flowgate-uninstall", timeout=100)
        checks["uninstall_preserving_state"] = removal.stdout
        state = sut.run("sudo -n test -s /var/lib/flowgate/rules.db && "
                        "sudo -n test ! -e /var/lib/flowgate/standalone.json && "
                        "test ! -e /usr/local/lib/flowgate/current && "
                        "sudo -n /usr/bin/sha256sum /var/lib/flowgate/rules.db")
        checks["preserved_database"] = state.stdout.strip()
        preflight_result("preflight_after_uninstall", expect_success=True)
        new_evidence = {"archive_sha256": new.archive_sha256, "installer_sha256": new.installer_sha256}
        lab.install(sut, new, candidate, new_evidence)
        report["new"] = new_evidence
        assert new_evidence["installed_sha"] == NEW[0], new_evidence
        with sut.multiplex(), ExitStack() as stack:
            connection = sut.channel(endpoint, "new-api")
            stack.callback(connection.close)
            api = lab.FlowGate(connection, record)
            probe = sut.channel("fg-lab/fg-lab-probe fg-lab/guest_tools.py probe 10.80.0.1", "new-probe")
            stack.callback(probe.close)
            case = Scenario(api, probe, receiver, record)
            active = collector(api, "active")
            assert active["generation"] != again["generation"], active
            lab.verify_build(active["build"], candidate)
            checks["new_collector"] = active["traffic_monitor"]
            report["saved_rule_after"] = case.rules()[rule["id"]]
            assert report["saved_rule_after"] == rule, report["saved_rule_after"]
            lab.activate(api, candidate)
            attempt = case.dial(A, "allow-after-fedora-upgrade")
            case.delivered(attempt)
            def outcome():
                page = api("decision-log", decision_query={"limit": 50, "direction": "outgoing"})
                return next((row for row in page["decision_log"]["records"] or []
                             if row["kind"] == "final" and case.matches(row, attempt)), None)

            final = vm.wait_for(outcome, 7, "missing Decision Log verdict for the labeled connection")
            win = final["decision"]["rule"]
            assert final["decision"]["action"] == "allow" and final["decision"]["source"] == "rule", final
            assert (win["id"], str(win["version"])) == (rule["id"], str(rule["version"])), final
            checks["rule_effect"] = {"flow": attempt, "decision": final,
                                     "receiver": case.count(attempt["label"])}
            case.close(attempt)
            assert sut.run("getenforce").stdout.strip() == "Enforcing"
        report["result"] = evidence["scenarios"][NAME] = "pass"
        print(f"PASS {NAME}", flush=True)
    except Exception as exc:
        report["error"] = str(exc) or repr(exc)
        evidence["scenarios"][NAME] = "fail"
        raise
    finally:
        lab.save(directory / f"{NAME}.json", report)


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--old-dir", type=Path, default=ROOT / "build/dist/fg-lab-fedora")
    parser.add_argument("--new-dir", type=Path, default=ROOT / "build/dist/fg-lab-fedora-guard-final")
    paths = parser.parse_args()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(paths.lab.resolve()))
    import lab
    import vm

    vm.RUNS = ROOT / ".workspace/fedora-collector-upgrade/runs"
    old = package(paths.old_dir, OLD)
    new = package(paths.new_dir, NEW)
    old.profile = paths.lab / "profiles/fedora-45.json"
    old.scenario = [NAME]
    old.keep_failed = False
    lab.run_cases = lambda pair, sut, names, release, evidence, host: exercise(
        lab, vm, sut, host, release, new, evidence)
    return lab.run(old)


if __name__ == "__main__":
    sys.exit(main())
