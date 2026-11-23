#!/usr/bin/env python3
"""Measure a packaged per-application bandwidth cap in one disposable Debian guest."""
import argparse
from contextlib import ExitStack
from functools import partial
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

from receiver import Receiver
from download_trace import REFERENCE_IFB, continuous

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


def measure(probe, receiver, label, *, direction, warmup=WARMUP, window=WINDOW):
    host_before = receiver.sample(label)
    assert host_before["connections"] == 1, host_before
    if direction == "download":
        receiver.start(label)
        sample = lambda: probe.call(op="sample")
    else:
        probe.call(op="start")
        sample = lambda: receiver.sample(label)
    try:
        time.sleep(warmup)
        before = sample()
        time.sleep(window)
        after = sample()
    finally:
        if direction == "download":
            receiver.stop(label)
        else:
            probe.call(op="stop")
    host_after = receiver.sample(label)
    assert host_after["connections"] == 1 and host_after["peer"] == host_before["peer"], host_after
    elapsed = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
    delivered = after["bytes"] - before["bytes"]
    return {"bytes": delivered, "seconds": elapsed, "bits_per_second": delivered * 8 / elapsed,
            "start": before, "end": after, "host_start": host_before, "host_end": host_after}


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


def exercise(api, probes, receiver, nic, record, report, stack, direction, diagnostics=None,
             compare_reference=False):
    from scenarios import Scenario
    from vm import FixtureError, wait_for

    context = api()
    generation = context["generation"]
    if f"experimental-native-{direction}-v1" not in context["capabilities"]:
        raise Inconclusive(f"the installed daemon lacks the {direction} limiter capability")

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
        wait_for(lambda: receiver.sample(label)["connections"] == 1, 5,
                 f"host service did not receive probe {label}'s stream label")
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

    app = f'{a["uid"]}:{a["application"]["key"]}'

    def phase(name, cap=None, extra=0, reference=False):
        state_before = status()
        row = {"configured_bits_per_second": cap, "status_before": state_before, "receiver": {}}
        phases[name] = row
        for label, probe in probes.items():
            if name.endswith("removed") and label == "B" and direction == "upload":
                continue
            if diagnostics is None:
                row["receiver"][label] = measure(probe, receiver, label, direction=direction)
            else:
                endpoints = {key: identities[label]["socket"][key] for key in ("local", "remote")}
                target = {}
                if cap:
                    if reference:
                        target = {"ifb": REFERENCE_IFB, "reference": True, "interface": nic}
                    else:
                        kernel = state_before["kernel"]
                        target = {"ifb": kernel["download"]["interface"], "minor": kernel["apps"][app]["minor"],
                                  "interface": nic}
                windows = continuous(probe, receiver, label, diagnostics, endpoints, target,
                                     WARMUP, WINDOW, extra if label == "A" else 0)
                row["receiver"][label] = windows[0]
                if target and label == "A":
                    row["windows"] = windows
                elif target:
                    row["b_windows"] = windows
            row["status_after_" + label] = status()
        record("phase", {"phase": name, **row})
        return row

    baseline = phase("baseline")["receiver"]
    cap = select_rate(baseline)
    if diagnostics and cap != MAX_CAP:
        raise Inconclusive("the route has less than 5× headroom for the original 20 Mbit/s case")
    rate_field = "download_bits_per_second" if direction == "download" else "bits_per_second"
    caps = [{"uid": a["uid"], "application": a["application"]["key"], rate_field: cap}]
    cleanup = True
    try:
        applied = configure(caps)
        assert len(applied["configured_caps"]) == 1
        configured = applied["configured_caps"][0]
        assert all(configured[key] == val for key, val in caps[0].items()), configured
        if direction == "download":
            assert configured.get("bits_per_second", 0) == 0, configured
        record("limit-applied", applied)

        def a_covered():
            current = status()
            if current["status"] == "Unsupported":
                raise RuntimeError(f"upload controller fault: {current.get('last_error')}")
            kernel = current.get("kernel") or {}
            for binding in kernel.get("bindings") or []:
                if (binding["covered"] and binding[f"{direction}_class"]
                        and (direction == "upload" or binding["download"])
                        and binding["cookie"] == identities["A"]["socket"]["cookie"]
                        and binding["app"] == f'{a["uid"]}:{a["application"]["key"]}'):
                    return current
            return None

        def confirm_coverage():
            missing = f"the original A socket did not obtain {direction} coverage"
            try:
                coverage = wait_for(a_covered, 25, missing)
            except FixtureError as exc:
                if direction != "download" or str(exc) != missing:
                    raise
                record("missing-download-coverage", status())
                raise Inconclusive(str(exc)) from exc
            record("a-covered", coverage)

        confirm_coverage()
        if compare_reference:
            ifb = status()["kernel"]["download"]["interface"]
            report["flowgate_tc"] = diagnostics.call(op="inspect", interface=nic, ifb=ifb)
            record("flowgate-tc", report["flowgate_tc"])
        limited = phase("a-limited", cap, extra=5 if diagnostics and not compare_reference else 0)
        if direction == "download":
            if diagnostics:
                first = limited["windows"][0]
                before = first["boundary_start"]["guest"]["redirected"]
                after = first["boundary_end"]["guest"]["redirected"]
            else:
                before = limited["status_before"]["kernel"]["download"]["redirected"]
                after = limited["status_after_A"]["kernel"]["download"]["redirected"]
            delta = {key: after[key] - before[key] for key in ("bytes", "packets")}
            report["download_redirected_delta"] = delta
            record("download-redirected-delta", delta)
        record("limit-removed", configure([]))
        cleanup = False
        recovered = phase("limit-removed")
        if compare_reference:
            reference_comparison(diagnostics, nic, cap, baseline, limited, recovered, identities, phase,
                                 record, report)
        elif diagnostics and not in_range(limited["receiver"]["A"]["bits_per_second"], cap, CAP_TOLERANCE):
            # Compare the same sockets with receive aggregation disabled on
            # the guest fixture only, after the owned shaping tree is gone.
            offloads = diagnostics.call(op="gro-off", interface=nic)
            record("gro-off-control", offloads)
            if offloads["exit_code"] == 0 and "generic-receive-offload: off" in offloads["offloads"]:
                cleanup = True
                record("gro-off-limit-applied", configure(caps))
                confirm_coverage()
                phase("gro-off-a-limited", cap)
                record("gro-off-limit-removed", configure([]))
                cleanup = False
                phase("gro-off-limit-removed")
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
    if direction == "download":
        verdicts["download_counters_advanced"] = all(val > 0 for val in delta.values())
        verdicts["b_recovered"] = in_range(recovered["receiver"]["B"]["bits_per_second"],
                                            baseline["B"]["bits_per_second"], BASELINE_TOLERANCE)
    assert all(verdicts.values()), verdicts


def reference_comparison(diagnostics, nic, cap, baseline, limited, recovered, identities, phase, record, report):
    clean = diagnostics.call(op="inspect", interface=nic)
    assert recovered["status_before"]["status"] == "Disabled"
    assert report["flowgate_tc"]["offloads"] == clean["offloads"], "interface offloads changed"
    assert not clean["ingress"] and not clean["egress"]
    report["flowgate_removed_tc"] = clean
    original = limited["windows"][0]["boundary_start"]["guest"]
    socket = identities["A"]["socket"]

    def rate_ok(row, label, target, tolerance):
        return in_range(row["receiver"][label]["bits_per_second"], target, tolerance)

    a_in_band = rate_ok(limited, "A", cap, CAP_TOLERANCE)
    b_in_band = rate_ok(limited, "B", baseline["B"]["bits_per_second"], BASELINE_TOLERANCE)
    for variant, mirror in (("reference", False), ("reference-matched-egress", True)):
        actual = diagnostics.call(op="reference-start", interface=nic, local=socket["local"],
                                  remote=socket["remote"], mtu=clean[nic]["link"]["mtu"],
                                  htb=original["htb"], leaf=original["leaf"]["options"],
                                  mirror_egress=mirror)
        try:
            assert actual["offloads"] == clean["offloads"], "interface offloads changed"
            report[variant + "_tc"] = actual
            record(variant + "-tc", actual)
            sample = phase(variant + "-limited", cap, reference=True)
            observed = sample["windows"][0]["boundary_start"]["guest"]
            keys = ("rate", "ceil", "burst", "cburst", "quantum", "prio", "linklayer")
            assert all(observed["htb"][key] == original["htb"][key] for key in keys)
            assert observed["leaf"]["options"] == original["leaf"]["options"]
        finally:
            diagnostics.call(op="reference-stop")
        after = diagnostics.call(op="inspect", interface=nic)
        assert after["offloads"] == clean["offloads"], "interface offloads changed"
        assert not after["ingress"] and not after["egress"]
        assert [q["kind"] for q in after[nic]["qdisc"]] == [q["kind"] for q in clean[nic]["qdisc"]]
        recovered_ref = phase(variant + "-removed")
        verdicts = {
            "a_near_cap": rate_ok(sample, "A", cap, CAP_TOLERANCE),
            "b_near_baseline": rate_ok(sample, "B", baseline["B"]["bits_per_second"], BASELINE_TOLERANCE),
            "a_recovered": rate_ok(recovered_ref, "A", baseline["A"]["bits_per_second"], BASELINE_TOLERANCE),
            "b_recovered": rate_ok(recovered_ref, "B", baseline["B"]["bits_per_second"], BASELINE_TOLERANCE),
        }
        report[variant + "_verdicts"] = verdicts
        # A's result alone cannot rule out an effect from replacing the NIC's
        # egress root on B, which must never enter A's IFB class.
        if b_in_band and (a_in_band or not verdicts["a_near_cap"]):
            break


def run_case(lab, sut, names, release, evidence, unused_host, *, direction, binaries,
             diagnose_download=False, compare_reference=False, diagnose_rule_delete=False):
    from lab import FlowGate, activate, configure_sut, recorder, save

    name = f"application-{direction}-limit"
    report = {"phases": {}, "verdict": "fail", "direction": direction}
    output = lab.directory / f"{name}.json"
    record = recorder(output.with_suffix(".jsonl"))
    record("criteria", {"cap_ratio": CAP_TOLERANCE, "baseline_ratio": BASELINE_TOLERANCE,
                        "warmup_s": WARMUP, "window_s": WINDOW, "headroom": HEADROOM,
                        "min_cap_bps": MIN_CAP, "max_cap_bps": MAX_CAP})
    try:
        assert names == [name] and release["source"] == BUILD
        configure_sut(sut)
        nic = setup_interface(sut, record)
        for label in "AB":
            sut.upload(binaries / f"upload-{label}", f"{direction}-{label}")
        sut.run(f"chmod 700 fg-lab/{direction}-A fg-lab/{direction}-B")
        if diagnose_download:
            sut.upload(HERE / "download_trace.py", "download_trace.py")
        with ExitStack() as stack:
            receiver = stack.enter_context(Receiver("AB", download=direction == "download"))

            def channel(command, label):
                ch = sut.channel(command, label)
                stack.callback(ch.close)
                return ch

            probes = {label: channel(f"fg-lab/{direction}-{label} {SOURCE} "
                                     f"{DESTINATION}:{receiver.port} {direction}",
                                     f"{direction}-{label}") for label in "AB"}
            api = FlowGate(channel(f"python3 fg-lab/guest_tools.py flowgate {API}", "api"), record)
            diagnostics = (channel("python3 -B fg-lab/download_trace.py", "download-trace")
                           if diagnose_download else None)
            activate(api, release)
            evidence["phase"] = "scenarios"
            exercise(api, probes, receiver, nic, record, report, stack, direction, diagnostics,
                     compare_reference)
        report["verdict"] = "pass"
        evidence["scenarios"][name] = "pass"
        print(f"PASS {name}", flush=True)
    except Inconclusive as exc:
        report.update(verdict="inconclusive", reason=str(exc))
        evidence["scenarios"][name] = "inconclusive"
        raise
    finally:
        save(output, report)


def local_check(folder, vm, direction):
    with Receiver("AB", download=direction == "download") as receiver, ExitStack() as stack:
        probes = {}
        for label in "AB":
            probe = vm.Channel([folder / f"upload-{label}", "127.0.0.1",
                                f"127.0.0.1:{receiver.port}", direction],
                               folder / f"local-{direction}-{label}.log")
            stack.callback(probe.close)
            assert probe.hello["probe"] == label
            probe.call(op="open", label=label)
            vm.wait_for(lambda: receiver.sample(label)["connections"] == 1, 3, "stream label lost")
            probes[label] = probe
        measurements = {label: measure(probe, receiver, label, direction=direction, warmup=0.2, window=0.5)
                        for label, probe in probes.items()}
        again = measure(probes["A"], receiver, "A", direction=direction, warmup=0.2, window=0.5)
        assert all(row["bytes"] > 0 for row in measurements.values()), measurements
        assert again["bytes"] > 0 and again["host_end"]["peer"] == measurements["A"]["host_end"]["peer"], again
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
    parser.add_argument("--direction", choices=("upload", "download"), default="upload")
    parser.add_argument("--diagnose-download", action="store_true")
    parser.add_argument("--compare-reference", action="store_true",
                        help="compare with a guest-only tc flower/IFB cap on the same TCP sockets")
    args = parser.parse_args()
    if (args.diagnose_download or args.compare_reference) and args.direction != "download":
        parser.error("download diagnostics require --direction download")
    sys.path.insert(0, str(args.lab.resolve()))
    import lab
    import vm

    binaries = build_probes()
    if args.local_check:
        return local_check(binaries, vm, args.direction)
    name = f"application-{args.direction}-limit"
    vm.RUNS = ROOT / ".workspace" / name / "runs"
    lab.run_cases = partial(run_case, direction=args.direction, binaries=binaries,
                            diagnose_download=args.diagnose_download or args.compare_reference,
                            compare_reference=args.compare_reference)
    args.archive = args.dist / ARCHIVE
    args.archive_sha256 = ARCHIVE_SHA256
    args.installer = args.dist / "flowgate-release.py"
    args.installer_sha256 = INSTALLER_SHA256
    args.scenario = [name]
    args.keep_failed = False
    return lab.run(args)


if __name__ == "__main__":
    sys.exit(main())
