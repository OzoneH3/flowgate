#!/usr/bin/env python3
"""Check the pinned standalone Debian upgrade and rollback with one host receiver."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
NAME = "standalone-lifecycle"
ARCHIVE = "flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
INSTALLER = "flowgate-release.py"
INSTALLER_DIGEST = "94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c"
PREDECESSOR = (
    "13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7",
    "f49a4c48b62f63d59b643829a8a52af5b9e4b140af74cb8715a6936cc041aa46",
)
CANDIDATE = (
    "7511ac1764c8a922c1ad259747338973adf197f2",
    "112995add59425a674ce7f25e9af220f5e96188e39d08f64aa7044cfcd33041d",
)
CURRENT = "/usr/local/lib/flowgate/current"
API = "python3 fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock"
PROBE = "fg-lab/fg-lab-probe fg-lab/guest_tools.py probe 10.80.0.1"


def verified_package(lab, directory, pinned):
    source, digest = pinned
    package = argparse.Namespace(
        archive=directory / ARCHIVE,
        installer=directory / INSTALLER,
        archive_sha256=digest,
        installer_sha256=INSTALLER_DIGEST,
    )
    lab.check_digest(package.archive, package.archive_sha256)
    lab.check_digest(package.installer, package.installer_sha256)
    manifest = lab.manifest(package.archive)
    assert manifest["source"] == source, manifest["source"]
    return package, manifest


def exercise(lab, sut, receiver, candidate, new_release, old_release, evidence):
    from scenarios import A, Scenario

    directory = sut.directory
    record = lab.recorder(directory / f"{NAME}.jsonl")
    stages = {}
    report = {"result": "fail", "stages": stages}
    phase = "predecessor"

    def guest_step(name, command):
        result = sut.run(command, check=False, timeout=sut.config["installer_timeout_seconds"])
        outcome = {"command": command, "exit_code": result.returncode,
                   "stdout": result.stdout, "stderr": result.stderr}
        stages[name] = outcome
        record(name, outcome)
        assert result.returncode == 0, outcome

    def snapshot(api, release, expected):
        state = api()
        binary = json.loads(sut.run(f"{CURRENT}/flowgate version").stdout)
        release_path = sut.run(f"readlink -f {CURRENT}").stdout.strip()
        lab.verify_build(binary, release)
        lab.verify_build(state["build"], release)
        assert Path(release_path).name == release["release"], release_path
        protection = state["protection"]
        assert (protection["state"], protection["desired_mode"]) == expected, protection
        return {"source": binary["source"], "generation": state["generation"],
                "release_path": release_path, "protection": protection}

    def verify_block(case, saved, name):
        assert case.rules().get(saved["id"]) == saved, "saved Block changed"
        attempt = case.dial(A, name)
        try:
            case.denied(attempt, rule=saved["id"])
            final = case.log(attempt, action="block", rule=saved["id"], source="rule")
            winner = final["decision"]["rule"]
            assert str(winner["version"]) == str(saved["version"]), final
            count = case.count(attempt["label"])
            assert count["count"] == 0, count
            return {"label": attempt["label"], "receiver_count": count["count"],
                    "client": case.status(attempt), "decision": final}
        finally:
            case.close(attempt)

    try:
        report["predecessor_package"] = {
            key: evidence[key] for key in ("installed_sha", "archive_sha256", "installer_sha256")
        }
        report["candidate_package"] = {
            "source": new_release["source"], "archive_sha256": candidate.archive_sha256,
            "installer_sha256": candidate.installer_sha256,
        }
        assert evidence["installed_sha"] == old_release["source"] == PREDECESSOR[0]
        report["debian_version"] = sut.run("cat /etc/debian_version").stdout.strip()
        sut.upload(candidate.archive, "candidate.tar.gz")
        sut.upload(candidate.installer, "candidate.py")
        lab.configure_sut(sut)
        with sut.multiplex(), ExitStack() as stack:
            def channel(command, name):
                conn = sut.channel(command, name)
                stack.callback(conn.close)
                return conn

            # Retain the management transport and probe executable while the
            # service changes generation. Each API operation opens its own socket.
            probe = channel(PROBE, "lifecycle-probe")
            api = lab.FlowGate(channel(API, "lifecycle-api"), record)
            case = Scenario(api, probe, receiver, record)
            assert probe.hello["uid"] != 0, probe.hello
            initial = snapshot(api, old_release, ("stopped", "monitoring"))
            stages["predecessor_installed"] = initial
            lab.activate(api, old_release)
            before = snapshot(api, old_release, ("active", "both"))
            saved = case.rule("block")
            assert saved["action"] == "block" and saved["filter"]["direction"] == "outgoing", saved
            report["saved_rule"] = saved
            stages["predecessor_block"] = {**before, **verify_block(case, saved, "predecessor-block")}

            phase = "upgrade"
            guest_step(
                "candidate_digests",
                "cd fg-lab && /usr/bin/sha256sum -c <<'SHA256'\n"
                f"{candidate.archive_sha256}  candidate.tar.gz\n"
                f"{candidate.installer_sha256}  candidate.py\nSHA256",
            )
            installer = "cd fg-lab && sudo -n /usr/bin/python3 -I ./candidate.py"
            options = f"--bundle ./candidate.tar.gz --sha256 {candidate.archive_sha256}"
            guest_step("upgrade_preflight", f"{installer} preflight {options}")
            guest_step("upgrade_install", f"{installer} install {options}")
            upgraded = snapshot(api, new_release, ("active", "both"))
            stages["upgrade_running"] = upgraded
            assert upgraded["generation"] != before["generation"], upgraded
            stages["upgrade_block"] = verify_block(case, saved, "upgraded-block")

            phase = "rollback"
            guest_step("rollback_command", "sudo -n /usr/local/sbin/flowgate-recover --rollback")
            rolled_back = snapshot(api, old_release, ("stopped", "monitoring"))
            stages["rollback_running"] = rolled_back
            assert rolled_back["generation"] not in {upgraded["generation"], before["generation"]}
            assert case.rules().get(saved["id"]) == saved, "rollback changed saved Block"
            lab.activate(api, old_release)
            stages["rollback_block"] = {
                **snapshot(api, old_release, ("active", "both")),
                **verify_block(case, saved, "rollback-block"),
            }
            phase = "rule-cleanup"
            case.cleanup()
            assert saved["id"] not in case.rules(), "disposable Block survived cleanup"

        report["result"] = evidence["scenarios"][NAME] = "pass"
        print(f"PASS {NAME}", flush=True)
    except Exception as exc:
        report.update(phase=phase, error=str(exc) or repr(exc))
        evidence["scenarios"][NAME] = "fail"
        raise
    finally:
        lab.save(directory / f"{NAME}.json", report)


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--old-dir", type=Path, default=ROOT / "build/dist/rc8-13e3029a")
    parser.add_argument("--new-dir", type=Path, default=(
        ROOT / ".workspace/public-audit-01a1ff88/source/build/dist/rc8"))
    paths = parser.parse_args()

    sys.dont_write_bytecode = True
    sys.path.insert(0, str(paths.lab.resolve()))
    import lab
    import vm

    vm.RUNS = ROOT / ".workspace/standalone-lifecycle/runs"
    old, old_release = verified_package(lab, paths.old_dir, PREDECESSOR)
    new, new_release = verified_package(lab, paths.new_dir, CANDIDATE)
    old.profile = paths.lab / "profiles/debian-13.json"
    old.scenario = [NAME]
    old.keep_failed = False
    def run_lifecycle(_guest, sut, _names, release, evidence, host, *, diagnose_rule_delete=False):
        exercise(lab, sut, host, new, new_release, release, evidence)

    lab.run_cases = run_lifecycle
    assert old_release["release"] != new_release["release"]
    return lab.run(old)


if __name__ == "__main__":
    sys.exit(main())
