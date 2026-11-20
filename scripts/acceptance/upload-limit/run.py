#!/usr/bin/env python3
"""Measure the packaged per-application upload cap in one disposable Debian guest."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from receiver import Receiver

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = "10.80.0.1"
DESTINATION = "10.80.0.2"
BUILD = "13e3029ac2e4d2695b851cfb09710d9ab4bb8bf7"
NAME = "application-upload-limit"
RELEASE = "/usr/local/lib/flowgate/current"
API = "/run/flowgate-api/daemon.sock"
ARCHIVE = "flowgate-0.1.0-rc.8-linux-x86_64.tar.gz"
ARCHIVE_SHA256 = "f49a4c48b62f63d59b643829a8a52af5b9e4b140af74cb8715a6936cc041aa46"
INSTALLER_SHA256 = "94a2956bf3477875aa63eafc3f2abd555160837d220f8449b3dfe3cbc349124c"
WINDOW = 7
WARMUP = 3
CAP_TOLERANCE = (0.75, 1.20)
BASELINE_TOLERANCE = (0.70, 1.30)
MIN_CAP = 4_000_000
MAX_CAP = 20_000_000
HEADROOM = 5


class Inconclusive(RuntimeError):
    pass


def build_probes():
    build = ROOT / "build"
    output = build / "acceptance" / NAME
    for path in (output, build / "tmp", build / "go-cache", build / "go"):
        path.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH="amd64",
               GOPATH=str(build / "go"), GOCACHE=str(build / "go-cache"),
               GOTMPDIR=str(build / "tmp"), TMPDIR=str(build / "tmp"))
    for label in "AB":
        subprocess.run(["go", "build", "-trimpath", "-ldflags", f"-X main.probeName={label}",
                        "-o", output / f"upload-{label}", HERE / "probe.go"], env=env, check=True)
    return output


def measure(probe, receiver, label, *, warmup=WARMUP, window=WINDOW):
    probe.call(op="start")
    try:
        time.sleep(warmup)
        before = receiver.sample(label)
        time.sleep(window)
        after = receiver.sample(label)
    finally:
        probe.call(op="stop")
    assert before["connections"] == after["connections"] == 1, (before, after)
    elapsed = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
    delivered = after["bytes"] - before["bytes"]
    return {"bytes": delivered, "seconds": elapsed, "bits_per_second": delivered * 8 / elapsed,
            "start": before, "end": after}


def in_range(value, target, tolerance):
    return tolerance[0] * target <= value <= tolerance[1] * target


def select_rate(baselines):
    weakest = min(row["bits_per_second"] for row in baselines.values())
    rate = min(MAX_CAP, int(weakest / HEADROOM / 1_000_000) * 1_000_000)
    if rate < MIN_CAP:
        raise Inconclusive(f"weakest unrestricted route {weakest / 1e6:.3f} Mbit/s is below "
                           f"the required {HEADROOM * MIN_CAP / 1e6:.0f} Mbit/s")
    return rate


def setup_interface(sut, record):
    ip = shlex.quote(DESTINATION)
    addresses = json.loads(sut.run(f"ip -j route get {ip} from {SOURCE}").stdout)
    nic = addresses[0]["dev"]
    sut.run("""set -eu
if ! sudo -n /bin/sh -c 'command -v ethtool >/dev/null'; then
    # The netinst base can retain only a cdrom source. Keep the fixture's
    # network source private to these two commands and use Debian's trust root.
    source=$(mktemp --suffix=.list "$PWD/fg-lab/apt-XXXXXX")
    trap 'rm -f "$source"' EXIT
    printf '%s\\n' 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian trixie main' > "$source"
    chmod 644 "$source"
    apt_get() {
        sudo -n apt-get -o "Dir::Etc::sourcelist=$source" -o Dir::Etc::sourceparts=- \\
            -o Acquire::Retries=0 -o Acquire::http::Timeout=10 "$@"
    }
    apt_get update --error-on=any
    apt_get install -y --no-install-recommends ethtool
fi""", timeout=120)
    offloads = sut.run(f"sudo -n ethtool -k {shlex.quote(nic)}", check=False)
    record("ethtool", {"exit_code": offloads.returncode, "stdout": offloads.stdout, "stderr": offloads.stderr})
    preflight = sut.run(f"sudo -n /usr/bin/python3 -I {RELEASE}/controller.py --preflight "
                        f"--host-trial --interface {shlex.quote(nic)} --helpers {RELEASE} "
                        "--state /var/lib/flowgate/upload-experiment")
    compatibility = json.loads(preflight.stdout)
    record("interface-preflight", {"route": addresses, "interface": nic, "compatibility": compatibility})
    if not compatibility["supported"]:
        raise Inconclusive(f"unsupported test interface {nic}: {compatibility['reasons']}")
    config = shlex.quote(json.dumps({"interface": nic}))
    sut.run(f"printf '%s\\n' {config} | sudo -n tee /etc/flowgate/shaping.json >/dev/null "
            "&& sudo -n chmod 0600 /etc/flowgate/shaping.json "
            "&& sudo -n systemctl restart flowgate.service", timeout=55)
    return nic


def verify_stream(api, probe, stream, wait_for):
    hello = probe.hello

    def current():
        activity = api()["activity"]
        for row in activity["rows"]:
            sock = row["socket"]
            if (sock["local"], sock["remote"], sock["inode"], sock["state"]) != (
                stream["local"], stream["remote"], stream["inode"], 1
            ):
                continue
            if row.get("ownership_category") != "visible-holder" or len(row.get("owners", [])) != 1:
                continue
            process = activity["processes"][row["owners"][0]]
            app = process["application"]
            if ((process["pid"], process["uid"], process["start_ticks"], process["executable"])
                    == (hello["pid"], hello["uid"], hello["start_ticks"], hello["exe"])
                    and app["kind"] == "native" and app.get("key") and app.get("revision")):
                return {"process": process, "socket": sock}
        return None

    return wait_for(current, 15, f"unverified native TCP stream for probe {hello['probe']}")


def exercise(api, probes, receiver, nic, record, report, stack):
    from scenarios import Scenario
    from vm import wait_for

    generation = api()["generation"]

    def status():
        result = api("upload-status", generation=generation)["upload_shaping"]
        assert result["interface"] == nic, result
        return result

    def configure(caps):
        old = status()
        changed = api("upload-configure", generation=generation, expected_version=old["version"],
                      upload_config={"enabled": bool(caps), "caps": caps})["upload_shaping"]
        assert changed["version"] == old["version"] + 1, changed

        def applied():
            state = status()
            if state["status"] == "Unsupported":
                raise RuntimeError(f"upload controller fault: {state.get('last_error')}")
            return state if state["applied_version"] == changed["version"] else None

        state = wait_for(applied, 30, "upload configuration did not settle")
        assert state["enabled"] == bool(caps), state
        return state

    initial = status()
    assert initial["status"] == "Disabled" and not initial["enabled"] and not initial.get("configured_caps"), initial
    scenarios = {label: Scenario(api, probe, None, record) for label, probe in probes.items()}
    for scenario in scenarios.values():
        stack.callback(scenario.cleanup)
    allowed = {label: scenario.rule("allow") for label, scenario in scenarios.items()}
    identities = {}
    for label, probe in probes.items():
        stream = probe.call(op="open", label=label)
        proof = verify_stream(api, probe, stream, wait_for)
        p, sock = proof["process"], proof["socket"]
        assert (p["uid"], p["application"]["key"]) == (
            allowed[label]["filter"]["uid"], allowed[label]["filter"]["application"]
        ), proof
        assert sock["remote"] == f"{DESTINATION}:{receiver.port}" and sock["local"].startswith(SOURCE + ":"), sock
        assert sock.get("cookie"), sock
        identities[label] = proof
        record("stream", {"label": label, "probe": probe.hello, **proof, "allow_rule": allowed[label]})
    a, b = (identities[label]["process"] for label in "AB")
    assert a["uid"] == b["uid"] != 0 and a["executable"] != b["executable"]
    assert a["application"]["key"] != b["application"]["key"]

    phases = report["phases"]

    def phase(name, cap=None):
        state_before = status()
        row = {"configured_bits_per_second": cap, "status_before": state_before, "receiver": {}}
        phases[name] = row
        for label, probe in probes.items():
            if name == "limit-removed" and label == "B":
                continue
            row["receiver"][label] = measure(probe, receiver, label)
            row["status_after_" + label] = status()
        record("phase", {"phase": name, **row})
        return row

    baseline = phase("baseline")["receiver"]
    cap = select_rate(baseline)
    caps = [{"uid": a["uid"], "application": a["application"]["key"], "bits_per_second": cap}]
    cleanup = True
    try:
        record("limit-applied", configure(caps))

        def a_covered():
            current = status()
            if current["status"] == "Unsupported":
                raise RuntimeError(f"upload controller fault: {current.get('last_error')}")
            kernel = current.get("kernel") or {}
            for binding in kernel.get("bindings") or []:
                if (binding["covered"] and binding["upload_class"]
                        and binding["cookie"] == identities["A"]["socket"]["cookie"]
                        and binding["app"] == f'{a["uid"]}:{a["application"]["key"]}'):
                    return current
            return None

        coverage = wait_for(a_covered, 25, "the original A socket did not obtain upload coverage")
        record("a-covered", coverage)
        limited = phase("a-limited", cap)
        record("limit-removed", configure([]))
        cleanup = False
        recovered = phase("limit-removed")
    finally:
        if cleanup:
            record("cleanup-shaping", configure([]))

    verdicts = {
        "a_near_cap": in_range(limited["receiver"]["A"]["bits_per_second"], cap, CAP_TOLERANCE),
        "b_near_baseline": in_range(limited["receiver"]["B"]["bits_per_second"],
                                    baseline["B"]["bits_per_second"], BASELINE_TOLERANCE),
        "a_recovered": in_range(recovered["receiver"]["A"]["bits_per_second"],
                                baseline["A"]["bits_per_second"], BASELINE_TOLERANCE),
    }
    report["verdicts"] = verdicts
    assert all(verdicts.values()), verdicts


def run_case(lab, sut, names, release, evidence, unused_host, *, diagnose_rule_delete=False):
    from lab import FlowGate, activate, configure_sut, recorder, save

    report = {"phases": {}, "verdict": "fail"}
    output = lab.directory / f"{NAME}.json"
    record = recorder(output.with_suffix(".jsonl"))
    record("criteria", {"cap_ratio": CAP_TOLERANCE, "baseline_ratio": BASELINE_TOLERANCE,
                        "warmup_s": WARMUP, "window_s": WINDOW, "headroom": HEADROOM,
                        "min_cap_bps": MIN_CAP, "max_cap_bps": MAX_CAP})
    try:
        assert names == [NAME] and release["source"] == BUILD
        configure_sut(sut)
        nic = setup_interface(sut, record)
        for label in "AB":
            sut.upload(PROBES / f"upload-{label}", f"upload-{label}")
        sut.run("chmod 700 fg-lab/upload-A fg-lab/upload-B")
        with ExitStack() as stack:
            receiver = stack.enter_context(Receiver("AB"))

            def channel(command, label):
                ch = sut.channel(command, label)
                stack.callback(ch.close)
                return ch

            probes = {label: channel(f"fg-lab/upload-{label} {SOURCE} {DESTINATION}:{receiver.port}",
                                     f"upload-{label}") for label in "AB"}
            api = FlowGate(channel(f"python3 fg-lab/guest_tools.py flowgate {API}", "api"), record)
            activate(api, release)
            evidence["phase"] = "scenarios"
            exercise(api, probes, receiver, nic, record, report, stack)
        report["verdict"] = "pass"
        evidence["scenarios"][NAME] = "pass"
        print(f"PASS {NAME}", flush=True)
    except Inconclusive as exc:
        report.update(verdict="inconclusive", reason=str(exc))
        evidence["scenarios"][NAME] = "inconclusive"
        raise
    finally:
        save(output, report)


def local_check(folder, vm):
    with Receiver("AB") as receiver, ExitStack() as stack:
        probes = {}
        for label in "AB":
            probe = vm.Channel([folder / f"upload-{label}", "127.0.0.1", f"127.0.0.1:{receiver.port}"],
                               folder / f"local-{label}.log")
            stack.callback(probe.close)
            assert probe.hello["probe"] == label
            probe.call(op="open", label=label)
            probes[label] = probe
        measurements = {label: measure(probe, receiver, label, warmup=0.2, window=0.5)
                        for label, probe in probes.items()}
        assert all(row["bytes"] > 0 for row in measurements.values()), measurements
        assert probes["A"].hello["exe"] != probes["B"].hello["exe"]
        assert select_rate({label: {"bits_per_second": 30_000_000} for label in probes}) == 6_000_000
        assert in_range(4_000_000, 4_000_000, CAP_TOLERANCE)
        print(json.dumps(measurements, indent=2))


def main():
    if not __debug__:
        raise SystemExit("Run with assertions enabled.")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab", type=Path, default=ROOT.parent / "flowgate-lab")
    parser.add_argument("--profile", type=Path, default=ROOT.parent / "flowgate-lab/profiles/debian-13.json")
    parser.add_argument("--dist", type=Path, default=ROOT / "build/dist/rc8-13e3029a")
    parser.add_argument("--local-check", action="store_true")
    args = parser.parse_args()
    sys.path.insert(0, str(args.lab.resolve()))
    import lab
    import vm

    global PROBES
    PROBES = build_probes()
    if args.local_check:
        return local_check(PROBES, vm)
    vm.RUNS = ROOT / ".workspace" / NAME / "runs"
    lab.run_cases = run_case
    args.archive = args.dist / ARCHIVE
    args.archive_sha256 = ARCHIVE_SHA256
    args.installer = args.dist / "flowgate-release.py"
    args.installer_sha256 = INSTALLER_SHA256
    args.scenario = [NAME]
    args.keep_failed = False
    return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
