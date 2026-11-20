#!/usr/bin/env python3
"""Run the Fedora protected-boot fixture, then the committed lab UDP case."""
from contextlib import ExitStack
import json
from pathlib import Path
import re
import shlex
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STATE = "/var/lib/flowgate-guard-acceptance"
HELPER = "/usr/local/libexec/flowgate-guard-acceptance.py"


def digest(path):
    return path.with_name(path.name + ".sha256").read_text().split()[0]


def guarded(sut, nic, release, evidence, lab, vm, pair):
    prefix = "guard-" + uuid.uuid4().hex
    record = lab.recorder(sut.directory / "protected-start-api.jsonl")
    sut.upload(HERE / "guest.py", "guard-acceptance.py")
    with ExitStack() as stack:
        host = vm.Channel([sys.executable, "-B", vm.ROOT / "guest_tools.py", "host-peer"],
                          sut.directory / "guard-peer-stderr.log")
        stack.callback(host.close)
        args = shlex.join((nic, str(host.hello["port"]), prefix))
        commands = f"""set -eu
sudo -n install -d -m 0700 {STATE}
sudo -n install -d -m 0755 /usr/local/libexec /etc/systemd/system/flowgate.service.d
sudo -n install -m 0755 fg-lab/guard-acceptance.py {HELPER}
sudo -n tee /etc/systemd/system/flowgate-test-early.service >/dev/null <<'UNIT'
[Unit]
DefaultDependencies=no
After=flowgate-guard.service
Before=NetworkManager.service
[Service]
Type=oneshot
ExecStart=/usr/bin/env /usr/bin/python3 {HELPER} early {args}
[Install]
WantedBy=multi-user.target
UNIT
sudo -n tee /etc/systemd/system/flowgate.service.d/test-witness.conf >/dev/null <<'UNIT'
[Service]
ExecStartPre=/usr/bin/env /usr/bin/python3 {HELPER} pre {args}
ExecStopPost=/usr/bin/env /usr/bin/python3 {HELPER} stop {args}
UNIT
sudo -n tee /etc/systemd/system/flowgate-test-finish.service >/dev/null <<'UNIT'
[Unit]
After=flowgate.service
[Service]
Type=oneshot
ExecStart=/usr/bin/env /usr/bin/python3 {HELPER} finish {args}
TimeoutStartSec=120s
[Install]
WantedBy=multi-user.target
UNIT
sudo -n systemctl daemon-reload
sudo -n systemctl enable flowgate-test-early.service flowgate-test-finish.service
"""
        sut.run(commands)
        with sut.multiplex(), ExitStack() as connections:
            channel = sut.channel("python3 fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock", "guard-api")
            connections.callback(channel.close)
            api = lab.FlowGate(channel, record)
            draft = {"action": "allow", "remote_address": "10.79.0.2", "remote_port": host.hello["port"],
                     "expires": "0001-01-01T00:00:00Z"}
            fields = {"generation": api()["generation"], "endpoint_draft": draft}
            approved = api("endpoint-rule-preview", **fields)["endpoint_preview"]
            allow = api("endpoint-rule-save", preview_token=approved["token"], **fields)["saved_rule"]
            lab.activate(api, release)
            assert api()["protection"]["desired_mode"] == "both"
            boot = sut.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
            sut.run("sudo -n systemctl --no-block poweroff", check=False)
        guest = pair.info["guests"]["sut"]
        vm.wait_for(lambda: pair.virsh("domstate", guest["uuid"]).stdout.strip() == "shut off",
                    80, "guest did not power off before the cold boot")
        pair.start()
        sut = pair.ssh("sut")
        new_boot = sut.run("cat /proc/sys/kernel/random/boot_id").stdout.strip()
        assert boot != new_boot, "expected a new kernel boot"
        journal = sut.run("sudo -n journalctl -b -o short-monotonic --no-pager -u flowgate-guard.service "
                          "-u flowgate.service -u NetworkManager.service -u flowgate-test-early.service "
                          "-u flowgate-test-finish.service", check=False).stdout
        (sut.directory / "protected-start-journal.txt").write_text(journal)
        value = json.loads(sut.run(f"sudo -n cat {STATE}/result.json").stdout)
        rows = [json.loads(line) for line in sut.run(f"sudo -n cat {STATE}/witness.jsonl").stdout.splitlines()]
        value.update(boot_ids=[boot, new_boot], allow_rule=allow, witnesses=rows)
        output = sut.directory / "protected-start.json"
        lab.save(output, value)
        assert value["result"] == "pass" and not value.get("stop_error"), value
        assert [row["stage"] for row in rows] == ["early", "pre", "pre"], rows
        assert all(row["result"] == "pass" for row in rows), rows
        assert rows[0]["monotonic_usec"] < value["network_manager_start_usec"], value
        assert rows[0]["guard"] == rows[1]["guard"], "boot ExecStartPre did not verify early guard identity"
        assert value["boot_guard_unit"].split("ExecStart=", 1)[1].startswith(
            "{ path=/usr/local/lib/flowgate/current/flowgate ; argv[]=/usr/local/lib/flowgate/current/flowgate protection-guard")
        for report in (value["boot_exec_start_pre"], value["restart_exec_start_pre"]):
            assert re.search(r"path=/usr/local/lib/flowgate/current/flowgate ; argv\[\]=[^;]+ protection-guard [^}]+code=exited ; status=0(?:/0)? \}", report), report
        before_restart = value["before_restart"]
        assert before_restart["boot_id"] == new_boot, before_restart
        assert rows[1]["monotonic_usec"] < before_restart["monotonic_usec"] < rows[2]["monotonic_usec"]
        if before_restart["guard"] is not None:
            assert rows[2]["guard"] == before_restart["guard"], "restart did not verify the existing guard"
        value["invocations"] = {
            "early_boot_unit": "installed",
            "cold_boot_exec_start_pre": "verified",
            "restart_exec_start_pre": "verified" if before_restart["guard"] is not None else "installed",
        }
        observations = [(row["probe"]["label"], 0) for row in rows] + [
            (value["boot_control"]["label"], 1), (value["restart_control"]["label"], 1)]
        for label, count in observations:
            reply = host.call(label=label)
            if count:
                reply = vm.wait_for(lambda: (r if (r := host.call(label=label))["count"] else None),
                                    6, f"no receiver observation for {label}")
            assert reply["count"] == count, (label, reply)
            value.setdefault("receiver_counts", {})[label] = reply
        lab.save(output, value)
        print("PASS protected cold boot and restart", flush=True)

        sut.run("""set -eu
sudo -n systemctl disable flowgate-test-early.service flowgate-test-finish.service
sudo -n rm /etc/systemd/system/flowgate-test-early.service /etc/systemd/system/flowgate-test-finish.service /etc/systemd/system/flowgate.service.d/test-witness.conf
sudo -n systemctl daemon-reload
""")
        with ExitStack() as connections:
            channel = sut.channel("python3 fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock", "guard-cleanup-api")
            connections.callback(channel.close)
            api = lab.FlowGate(channel, record)
            api("rule-delete", generation=api()["generation"], id=allow["id"], expected_version=allow["version"])
        return sut


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled")
    sys.dont_write_bytecode = True
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "build/dist/fg-lab-fedora-guard")
    args = parser.parse_args()
    sys.path.insert(0, str(args.lab.resolve()))
    import lab
    import vm
    vm.RUNS = ROOT / ".workspace/fedora-guard/runs"
    system = lab.system
    verify_udp = lab.run_udp_case

    def fedora(sut):
        info = system(sut)
        info["selinux"] = sut.run("getenforce").stdout.strip()
        assert info["selinux"] == "Enforcing", info
        return info

    def exercise(sut, nic, release, evidence):
        pair = vm.Lab(sut.directory.name)
        installer = (f"cd fg-lab && sudo -n /usr/bin/python3 -I installer.py preflight "
                     f"--bundle release.tar.gz --sha256 {evidence['archive_sha256']}")
        preflight = sut.run(installer, timeout=80).stdout
        (sut.directory / "preflight.txt").write_text(preflight)
        assert "unconfined_service_t" in preflight and "init_t" in preflight, preflight
        sut = guarded(sut, nic, release, evidence, lab, vm, pair)
        sut.configure(pair.info["guests"]["sut"]["host_mac"], down=True)
        verify_udp(sut, nic, release, evidence)

    lab.system = fedora
    lab.run_udp_case = exercise
    args.profile = args.lab / "profiles/fedora-45.json"
    args.archive = args.artifact_dir / "flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
    args.installer = args.artifact_dir / "flowgate-release.py"
    args.archive_sha256 = digest(args.archive)
    args.installer_sha256 = digest(args.installer)
    args.scenario = ["udp-fast-path"]
    args.keep_failed = False
    return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
