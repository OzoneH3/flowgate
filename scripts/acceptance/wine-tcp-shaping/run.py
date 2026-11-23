"""Installed Wine TCP shaping workflow for the private-Ethernet matrix."""

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import shlex
import time

NAME = "wine-tcp-shaping"
HOST = "198.18.42.1"
GUEST = "198.18.42.2"
RELEASE = "/usr/local/lib/flowgate/current"
CAPABILITY = "experimental-wine-tcp-shaping-v1"
TARGET = 20_000_000
LABELS = "ABC"
PREFIXES = {"A": "prefix-a", "B": "prefix-b", "C": "prefix-a"}
IMAGES = {"A": "alpha.exe", "B": "alpha.exe", "C": "beta.exe"}


def wait_for(read, message, timeout=45):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if result := read():
            return result
        time.sleep(.5)
    raise AssertionError(message)


def run_case(guest, sut, names, release, evidence, _, *, relay, receiver, probe, runtime, prepare):
    from lab import FlowGate, configure_sut, recorder, save

    assert names == [NAME]
    report = {"source": release["source"], "phases": {}, "verdict": "fail", "proton": "not tested"}
    path = guest.directory / f"{NAME}.json"
    record = recorder(path.with_suffix(".jsonl"))
    configure_sut(sut)
    report["management_before"] = sut.run('printf "%s\n" "$SSH_CONNECTION"; ip -j route show default').stdout
    nic = sut.configure(guest.info["guests"]["sut"]["private_ethernet_mac"], (f"{GUEST}/30",), disable_ra=True)
    route = json.loads(sut.run(f"ip -j route get {HOST} from {GUEST}").stdout)
    assert route[0]["dev"] == nic and not route[0].get("gateway"), route
    report["route"] = route
    prepare(sut, record)
    sut.upload(runtime, "wine-runtime.tar.gz")
    sut.upload(probe, "wine-stream.exe")
    sut.run(
        'set -eu; cd fg-lab; mkdir -p wine-runtime prefix-a prefix-b; '
        'tar -xzf wine-runtime.tar.gz -C wine-runtime --strip-components=1; '
        'cp wine-stream.exe alpha.exe; cp wine-stream.exe beta.exe; '
        'for p in prefix-a prefix-b; do '
        'WINEARCH=win64 WINEPREFIX="$PWD/$p" WINEDEBUG=-all WINEDLLOVERRIDES="mscoree,mshtml=" '
        'wine-runtime/bin/wineboot -u; '
        'WINEPREFIX="$PWD/$p" wine-runtime/bin/wineserver -w; done',
        timeout=180,
    )
    report["runtime"] = sut.run("fg-lab/wine-runtime/bin/wine --version").stdout.strip()
    assert report["runtime"] == "wine-11.2 (Staging)", report
    home = sut.run('printf "%s\n" "$HOME"').stdout.strip()
    wc = json.dumps({"schema": 1, "runtime_bins": [f"{home}/fg-lab/wine-runtime/bin"],
                     "prefixes": [f"{home}/fg-lab/prefix-{suffix}" for suffix in "ab"]})
    sc = json.dumps({"interface": nic})
    for name, config in (("wine", wc), ("shaping", sc)):
        sut.run(f"printf '%s\n' {shlex.quote(config)} | sudo -n tee /etc/flowgate/{name}.json >/dev/null"
                f" && sudo -n chmod 600 /etc/flowgate/{name}.json")
    sut.run("sudo -n systemctl restart flowgate", timeout=50)
    sessions = ExitStack()
    channel = None

    def connect():
        nonlocal channel
        if channel is not None:
            channel.close()
        channel = sut.channel(
            "python3 -B fg-lab/guest_tools.py flowgate /run/flowgate-api/daemon.sock",
            f"wine-api-{time.monotonic_ns()}")
        sessions.callback(channel.close)
        client = FlowGate(channel, record)
        reply = client()
        assert CAPABILITY in reply["capabilities"], reply.get("capabilities")
        assert reply["build"]["source"] == release["source"], reply["build"]
        return client, reply["generation"]

    api, generation = connect()

    def status():
        s = api("upload-status", generation=generation)["upload_shaping"]
        assert s["status"] != "Unsupported", s
        return s

    def configure(caps=(), budget=0):
        old = status()
        result = api("upload-configure", generation=generation, expected_version=old["version"],
                     upload_config=dict(schema=4, enabled=bool(caps), caps=list(caps),
                                        upload_budget_bits_per_second=budget,
                                        download_budget_bits_per_second=budget))["upload_shaping"]
        return wait_for(lambda: (s if (s := status())["applied_version"] == result["version"] else None),
                        "shaping configuration did not settle")

    def read_connection(host_receiver, label, require_owner):
        sample = host_receiver.sample(label)
        if not sample["connections"]:
            return
        ip, port = sample["peer"]
        assert ip == GUEST
        activity = api()["activity"]
        for row in activity["rows"] or []:
            sock = row["socket"]
            if (sock["local"], sock["remote"], sock["state"]) != (f"{ip}:{port}", f"{HOST}:{host_receiver.port}", 1):
                continue
            app = row.get("runtime_application")
            if require_owner and not app:
                return
            return dict(socket=sock, owner=app)

    @contextmanager
    def stream(direction, label, host_receiver, attempt):
        image, prefix = IMAGES[label], PREFIXES[label]
        log = f"wine-{attempt}-{label}.log"
        command = (f'cd fg-lab && exec env WINEPREFIX="$PWD/{prefix}" WINEDEBUG=-all '
                   f'FG_TEST_HOST={HOST} FG_TEST_PORT={host_receiver.port} FG_TEST_LABEL={label} '
                   f'FG_TEST_MODE={direction} wine-runtime/bin/wine "$PWD/{image}" > {log}')
        # Shell PID becomes the launcher. Stop the entire isolated Wine prefix
        # after the phase and wait before reusing its receiver label.
        sut.run(f"setsid sh -c {shlex.quote(command)} </dev/null >/dev/null 2>&1 &")
        try:
            def sample():
                if direction == "upload":
                    row = host_receiver.sample(label)
                    return row["bytes"], row["monotonic_ns"]
                output = sut.run(f"tail -n 3 fg-lab/{log}").stdout.splitlines()
                for line in reversed(output):
                    fields = line.split()
                    if len(fields) == 2 and all(word.isdecimal() for word in fields):
                        size, tick = map(int, fields)
                        return size, tick * 1_000_000
                raise AssertionError(f"no Windows receiver samples in {log}")
            yield sample
        finally:
            sut.run(f'cd fg-lab; WINEPREFIX="$PWD/{prefix}" wine-runtime/bin/wineserver -k; '
                    f'WINEPREFIX="$PWD/{prefix}" wine-runtime/bin/wineserver -w', timeout=20)

    def phase(name, direction, wanted=None, restart=False, identify=False):
        nonlocal api, generation
        report["phases"][name] = output = {}
        with relay.listener(guest) as sender, ExitStack() as stack:
            receiver.make_listener = sender.dup
            peer = stack.enter_context(receiver.Receiver(LABELS, download=direction == "download"))
            samples = {label: stack.enter_context(stream(direction, label, peer, name)) for label in LABELS}
            identities = {label: wait_for(lambda: read_connection(peer, label, identify),
                                          f"missing socket identity for {label}") for label in LABELS}
            output["identities"] = identities
            key = identities["A"]["socket"]["cookie"]
            if restart:
                before = generation
                sut.run("sudo -n systemctl restart flowgate", timeout=50)
                api, generation = connect()
                assert before != generation
                output["generation_before_restart"] = before
            output["generation"] = generation
            if wanted:
                def covered():
                    snapshot = status()
                    binds = (snapshot.get("kernel") or {}).get("bindings", [])
                    other = {identities[c]["socket"]["cookie"] for c in "BC"}
                    assert all(b["cookie"] not in other for b in binds), binds
                    return snapshot if any(b.get("wine") and b["cookie"] == key
                                           and b["app"] == wanted and b["covered"] for b in binds) else None
                output["coverage_before"] = wait_for(covered, "target Wine socket never received coverage")
            if direction == "download":
                for label in LABELS:
                    peer.start(label)
                    stack.callback(peer.stop, label)
            time.sleep(3)
            start = {label: sample() for label, sample in samples.items()}
            time.sleep(7)
            end = {label: sample() for label, sample in samples.items()}
            output["receiver"] = {}
            for label in LABELS:
                delivered = end[label][0] - start[label][0]
                elapsed = (end[label][1] - start[label][1]) / 1e9
                assert delivered > 0 and elapsed > 0
                output["receiver"][label] = dict(bytes=delivered, seconds=elapsed,
                                                  bits_per_second=delivered * 8 / elapsed)
            if wanted:
                output["coverage_after"] = wait_for(covered, "target coverage did not survive renewal")
        if wanted:
            wait_for(lambda: all(b["cookie"] != key for b in (status().get("kernel") or {}).get("bindings", [])),
                     "Wine socket binding survived process exit")
        return output

    try:
        for direction in ("upload", "download"):
            baseline = phase(direction + "-baseline", direction, identify=True)
            target = baseline["identities"]["A"]["owner"]
            assert target["application"]["kind"] == "wine", target
            keys = {entry["owner"]["application"]["key"] for entry in baseline["identities"].values()}
            assert len(keys) == 3, keys
            cap = dict(uid=target["uid"], application=target["application"]["key"],
                       bits_per_second=TARGET, download_bits_per_second=TARGET)
            wanted = f'{cap["uid"]}:{cap["application"]}'
            assert not (status().get("kernel") or {}).get("bindings")
            version = configure([cap])["version"]
            previous = baseline["identities"]["A"]["socket"]["cookie"]
            for step in ("first-launch", "relaunch", "daemon-restart"):
                observed = phase(f"{direction}-{step}", direction, wanted, restart=step == "daemon-restart")
                cookie = observed["identities"]["A"]["socket"]["cookie"]
                assert cookie != previous
                assert status()["configured_caps"] == [cap]
                if step != "daemon-restart":
                    assert status()["version"] == version
                previous = cookie
                rates = observed["receiver"]
                assert .75 * TARGET <= rates["A"]["bits_per_second"] <= 1.2 * TARGET, rates
                for label in "BC":
                    assert rates[label]["bits_per_second"] >= .70 * baseline["receiver"][label]["bits_per_second"], rates
            configure()
            configure([dict(cap, bits_per_second=0, download_bits_per_second=0, traffic_priority="high")],
                      budget=40_000_000)
            priority = phase(direction + "-priority", direction, wanted)["receiver"]
            assert priority["A"]["bits_per_second"] > max(priority[c]["bits_per_second"] for c in "BC"), priority
            configure()
        evidence["scenarios"][NAME] = "pass"
        report["verdict"] = "pass"
    finally:
        try:
            configure()
            report["management_after"] = sut.run('printf "%s\n" "$SSH_CONNECTION"; ip -j route show default').stdout
            assert report["management_before"] == report["management_after"]
            assert sut.run("sudo -n test ! -e /var/lib/flowgate/upload-experiment/owner.json").returncode == 0
        finally:
            sessions.close()
            save(path, report)
