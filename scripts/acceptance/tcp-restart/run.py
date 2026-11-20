#!/usr/bin/env python3
"""Exercise retained TCP sockets through the existing flowgate-lab runner."""
import argparse
from contextlib import ExitStack
import errno
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
NAME = "established-disconnect-after-restart"
PRESERVED = 0x20000000
APPROVED = 0x10000000
MASK = PRESERVED | APPROVED
TERMINATED = {errno.ECONNABORTED, errno.ECONNRESET, errno.EPIPE, errno.ENOTCONN}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def run_case(runner, lab, sut, names, release, evidence, host, helper):
    from lease_case import GUEST, HOST
    from rule_cases import RuleCase
    from scenarios import Scenario
    from vm import wait_for

    require(tuple(names) == (NAME,) and host is not None, "expected single-guest host-receiver mode")
    runner.configure_sut(sut)
    sut.upload(helper, "conntrack-mark")
    sut.run("chmod 700 fg-lab/conntrack-mark && cp fg-lab/fg-lab-probe fg-lab/fg-lab-other-probe")
    # Use the second private SLIRP gateway on the management adapter. Both
    # guest destinations proxy the receiver's loopback port on the lab host.
    internet = "10.0.2.2"
    route = json.loads(sut.run(f"ip -j -4 route get {internet}").stdout)[0]
    internet_source = route["prefsrc"]
    sut.run("""printf '%s\n' '{"local":["10.80.0.0/24"],"internet":["10.0.2.2/32"]}' |
        sudo -n tee /etc/flowgate/zones.json >/dev/null &&
        sudo -n systemctl restart flowgate.service""", timeout=60)
    directory = lab.directory
    report = {"scenario": NAME, "sha": release["source"], "variants": {}, "result": "fail"}
    evidence["scenarios"][NAME] = "fail"
    record = runner.recorder(directory / f"{NAME}.jsonl")

    class Retained(RuleCase):
        def dial(self, address, purpose, **options):
            attempt = Scenario.dial(self, address, purpose, **options)
            self.attempts[attempt["label"]] = attempt
            return attempt

        def delivery(self, label, expected):
            if expected:
                wait_for(lambda: self.count(label)["count"] >= expected,
                         7, f"missing host receiver observation for {label}")
            observed = self.count(label)
            require(observed["count"] == expected, f"unexpected receiver count for {label}: {observed}")
            endpoint = f"127.0.0.1:{host.hello['port']}"
            require(all(row["destination"] == endpoint for row in observed["deliveries"]), observed)
            return observed

        def open_stream(self, address, source, purpose, rule, zone):
            stream = self.dial(address, purpose, port=host.hello["port"], source=source)
            row = self.log(stream, action="allow", rule=rule["id"], source="rule", zone=zone)
            require(row["application"]["key"] == rule["filter"]["application"]
                    and row["application"]["executable"] == self.probe.hello["exe"], row)
            delivered = self.delivery(stream["label"], 1)
            status = self.status(stream)
            require(status["status"] == "written" and stream["inode"] == status["inode"], status)
            return stream, {"socket": stream, "decision": row, "receiver": delivered}

        def send(self, stream, purpose, disconnect=False):
            label, status = self.rewrite(stream, purpose)
            if disconnect:
                require(status["status"] == "socket-error" and status.get("errno") in TERMINATED,
                        f"original target socket stayed open after winning Block: {status}")
            else:
                require(status["status"] == "written", f"unexpected control disconnect: {status}")
            return {"label": label, "client": status, "receiver": self.delivery(label, int(not disconnect))}

        def mark(self, stream, want, original=None):
            row = json.loads(sut.run("sudo -n fg-lab/conntrack-mark "
                                     f"{stream['local']} {stream['remote']}", timeout=10).stdout)
            row["mark_hex"] = f"0x{row['mark']:08x}"
            record("conntrack", row)
            require(row["state"] == 3 and (row["mark"] & MASK) == want,
                    f"expected established conntrack mark bits {want:#x}, observed {row}")
            if original:
                require((row["id"], row["zone"]) == (original["id"], original["zone"]),
                        f"conntrack identity changed across restart: {original}, {row}")
            return row

        def enable(self, rule):
            updated = self.edit(rule, disabled=False)
            require(updated["id"] == rule["id"] and updated["version"] == rule["version"] + 1
                    and not updated["disabled"] and updated["filter"] == rule["filter"], updated)
            return updated

    try:
        with sut.multiplex(), ExitStack() as stack:
            def channel(command, name):
                result = sut.channel(command, name)
                stack.callback(result.close)
                return result

            alpha = channel(f"fg-lab/fg-lab-probe fg-lab/guest_tools.py probe {GUEST}", "target-probe")
            beta = channel(f"fg-lab/fg-lab-other-probe fg-lab/guest_tools.py probe {GUEST}", "other-probe")
            ctrl = channel("python3 fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock", "api")
            service = channel("python3 fg-lab/guest_tools.py service", "restart-service")
            api = runner.FlowGate(ctrl, record)
            runner.activate(api, release)
            evidence["phase"] = "scenarios"

            def restart():
                # Installation and fixture setup already started this unit
                # several times. Reset its disposable-guest start counter so
                # the restart under test is never rejected by systemd.
                sut.run("sudo -n systemctl reset-failed flowgate.service")
                record("restart-command", service.call())

            target, other = (Retained(api, probe, host, record, restart) for probe in (alpha, beta))
            report["processes"] = [alpha.hello, beta.hello]
            require(alpha.hello["exe"] != beta.hello["exe"]
                    and alpha.hello["uid"] == beta.hello["uid"] != 0, report["processes"])
            checks = []
            for variant, send_before_edit in (("preserved-only", False), ("preserved-and-approved", True),
                                              ("losing-block", False)):
                details = report["variants"][variant] = {}
                allow = target.rule("allow")
                block = target.rule("block", zone="local", disabled=True)
                other_allow = other.rule("allow")
                require(allow["filter"]["application"] == block["filter"]["application"]
                        != other_allow["filter"]["application"], "probe rules did not have distinct identities")
                losing = variant == "losing-block"
                if losing:
                    allow = target.edit(allow, priority=block["priority"] + 100)
                details["rules_before"] = {"target_allow": allow, "local_block": block, "other_allow": other_allow}
                lan, details["local"] = target.open_stream(HOST, GUEST,
                                                            f"{variant}-lan", allow, "local")
                nonlocal_stream, details["internet"] = target.open_stream(internet, internet_source,
                                                                          f"{variant}-internet", allow, "internet")
                other_lan, details["other_local"] = other.open_stream(HOST, GUEST, f"{variant}-other",
                                                                      other_allow, "local")
                details["mark_before_restart"] = target.mark(lan, APPROVED)
                before = api()["generation"]
                target.restart(allow, block, other_allow)
                details["generations"] = {"before": before, "after": api()["generation"]}
                require(details["generations"]["after"] != before, "daemon generation did not change")
                details["mark_after_restart"] = target.mark(lan, PRESERVED, details["mark_before_restart"])
                if send_before_edit:
                    details["target_after_restart"] = target.send(lan, f"{variant}-before-edit")
                details["mark_before_edit"] = target.mark(
                    lan, MASK if send_before_edit else PRESERVED, details["mark_before_restart"])
                details["enabled_block"] = block = target.enable(block)
                details["target_after_edit"] = target.send(lan, f"{variant}-after-edit", disconnect=not losing)
                details["internet_after_edit"] = target.send(nonlocal_stream, f"{variant}-internet-control")
                details["other_after_edit"] = other.send(other_lan, f"{variant}-other-control")

                checks.append((details["target_after_edit"]["label"], int(losing)))
                if losing:
                    fresh, details["fresh_local"] = target.open_stream(HOST, GUEST, "losing-fresh", allow, "local")
                else:
                    fresh = target.dial(HOST, f"{variant}-fresh", port=host.hello["port"], source=GUEST)
                    row = target.log(fresh, action="block", rule=block["id"], source="rule", zone="local")
                    client = wait_for(lambda: (status if (status := target.status(fresh))["status"] != "in-flight"
                                               else None), 28, "fresh blocked TCP dial never completed")
                    require(client["status"] == "deadline" or client.get("errno") in TERMINATED | {
                        errno.EPERM, errno.EACCES}, f"unexpected result for fresh blocked dial: {client}")
                    details["fresh_local"] = {"socket": fresh, "decision": row, "client": client,
                                              "receiver": target.delivery(fresh["label"], 0)}
                    checks.append((fresh["label"], 0))
                for stream in (lan, nonlocal_stream, fresh):
                    target.close(stream)
                other.close(other_lan)
                target.cleanup()
                other.cleanup()
                for label, count in checks:
                    target.delivery(label, count)
                details["result"] = "pass"
                print(f"PASS {NAME}: {variant}", flush=True)
            report["result"] = evidence["scenarios"][NAME] = "pass"
    except Exception as exc:
        report["error"] = str(exc) or repr(exc)
        raise
    finally:
        runner.save(directory / f"{NAME}.json", report)


def main():
    if not __debug__:
        raise SystemExit("Run without Python optimization to keep lab assertions enabled")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", choices=("debian-13", "ubuntu-26.04"))
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--artifact-dir", type=Path, default=ROOT / "build/dist/fg-lab-apparmor")
    args = parser.parse_args()
    helper = ROOT / "build/tcp-restart-acceptance/conntrack-mark"
    require(helper.is_file(), "build the read-only conntrack-mark helper first (see README)")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.lab.resolve()))
    import lab
    import vm

    # Use the runner's host-receiver case slot. Startup, installation, digest
    # verification, host receiver and teardown remain owned by lab.py.
    vm.RUNS = ROOT / ".workspace/tcp-lab"
    lab.LEASE_NAME = NAME
    lab.run_cases = lambda env, sut, peer, names, release, evidence, host=None: run_case(
        lab, env, sut, names, release, evidence, host, helper)
    args.profile = args.lab / "profiles" / (args.profile + ".json")
    args.archive = args.artifact_dir / "flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
    args.installer = args.artifact_dir / "flowgate-release.py"
    args.archive_sha256 = "d4e5d958420a01a808ba5de133de02cd35bc855a92508e75648ef7a8b9e9a197"
    args.installer_sha256 = "39cf8211010c761f5089f32f35c2bb13cdf2633e51eff21c8940a0a29e9653ee"
    args.scenario = [NAME]
    args.keep_failed = False
    return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
