"""Aligned application, IFB, and TCP observations for the download diagnosis."""
import json
import re
import subprocess
import sys
import time

RELEASE = "/usr/local/lib/flowgate/current"
JOURNAL = "/var/lib/flowgate/upload-experiment/owner.json"


def guest_sample(local, remote, ifb=None, minor=None):
    def run(*args):
        return subprocess.check_output(args, text=True, timeout=3)

    out = {}
    if ifb is not None:
        journal = json.loads(run("sudo", "-n", "cat", JOURNAL))
        assert journal["ifb"] == ifb and re.fullmatch(r"/sys/fs/bpf/fg-m1-[a-f0-9]+", journal["pin"])
        classid = f'{journal["dl_major"]:x}:{minor:x}'
        began = time.monotonic_ns()
        classes = json.loads(run("sudo", "-n", "tc", "-s", "-d", "-j", "class", "show", "dev", ifb))
        class_at = time.monotonic_ns()
        qdiscs = json.loads(run("sudo", "-n", "tc", "-s", "-d", "-j", "qdisc", "show", "dev", ifb))
        counters = json.loads(run("sudo", "-n", RELEASE + "/kernel", "stats", journal["pin"]))
        out.update(
            classid=classid, began_ns=began, class_ns=class_at, ended_ns=time.monotonic_ns(),
            wall_ns=time.time_ns(),
            htb=next(row for row in classes if row.get("handle") == classid and row["class"] == "htb"),
            leaf=next(row for row in qdiscs if row.get("parent") == classid),
            redirected=counters[5],
        )
    out["tcp"] = run("ss", "-tinme", f"src {local} and dst {remote}")
    return out


def guest_loop():
    print(json.dumps({"role": "download-trace"}), flush=True)
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if request.pop("op", None) == "gro-off":
                result = subprocess.run(["sudo", "-n", "ethtool", "-K", request["interface"], "gro", "off"],
                                        capture_output=True, text=True, timeout=5)
                output = dict(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr)
                output["offloads"] = subprocess.check_output(
                    ["sudo", "-n", "ethtool", "-k", request["interface"]], text=True, timeout=5
                )
            else:
                output = guest_sample(**request)
        except (AssertionError, KeyError, OSError, ValueError, StopIteration, subprocess.SubprocessError) as exc:
            output = {"fixture_error": repr(exc)}
        print(json.dumps(output), flush=True)


def rate(start, end):
    elapsed = (end["monotonic_ns"] - start["monotonic_ns"]) / 1e9
    received = end["bytes"] - start["bytes"]
    return {"bytes": received, "seconds": elapsed, "bits_per_second": received * 8 / elapsed,
            "start": start, "end": end}


def continuous(probe, peer, label, diagnostics, endpoints, target, warmup, window, extra):
    def boundary():
        before = probe.call(op="sample")
        guest = diagnostics.call(**endpoints, **target)
        after = probe.call(op="sample")
        return {"before": before, "after": after, "guest": guest, "host": peer.sender_stats(label)}

    peer.start(label)
    try:
        time.sleep(warmup)
        interval_start = time.monotonic()
        samples = [boundary()]
        for i in range(1, 2 + extra):
            time.sleep(max(0, interval_start + i * window - time.monotonic()))
            samples.append(boundary())
    finally:
        peer.stop(label)
    return [{"offset_seconds": i * window, **rate(a["before"], b["before"]),
             "boundary_start": a, "boundary_end": b}
            for i, (a, b) in enumerate(zip(samples, samples[1:]))]


if __name__ == "__main__":
    guest_loop()
