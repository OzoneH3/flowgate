"""Aligned application, IFB, and TCP observations for the download diagnosis."""
import json
import re
import subprocess
import sys
import time
from ipaddress import IPv4Address

RELEASE = "/usr/local/lib/flowgate/current"
JOURNAL = "/var/lib/flowgate/upload-experiment/owner.json"
REFERENCE_IFB = "fgdlref"
REFERENCE_ROOT = "10:"
REFERENCE_CLASS = REFERENCE_ROOT + "1"


def run(*args):
    return subprocess.check_output(args, text=True, timeout=3)


def tc(*args):
    return run("sudo", "-n", "tc", *args)


def inspect_tc(interface, ifb=None):
    evidence = {"offloads": run("sudo", "-n", "ethtool", "-k", interface)}
    for device in (interface, ifb):
        if device:
            evidence[device] = {
                measure: json.loads(tc("-s", "-d", "-j", measure, "show", "dev", device))
                for measure in ("qdisc", "class")
            }
            evidence[device]["link"] = json.loads(run("ip", "-d", "-j", "link", "show", "dev", device))[0]
    for direction in ("ingress", "egress"):
        evidence[direction] = json.loads(tc("-s", "-d", "-j", "filter", "show", "dev", interface, direction))
    return evidence


class Reference:
    def __init__(self):
        self.interface = None
        self.ifb_added = False
        self.ingress_added = False
        self.egress_added = False

    def start(self, interface, local, remote, mtu, htb, leaf, mirror_egress=False):
        assert self.interface is None
        assert re.fullmatch(r"[\w.-]{1,15}", interface)
        src, sport = remote.rsplit(":", 1)
        dst, dport = local.rsplit(":", 1)
        src, dst = str(IPv4Address(src)), str(IPv4Address(dst))
        assert all(1 <= int(p) <= 65535 for p in (sport, dport))
        clean = inspect_tc(interface)
        # Use only a clean ingress hook, leaving the test NIC root untouched.
        assert not clean["ingress"] and not clean["egress"]
        assert not any(q["kind"] in ("ingress", "clsact") for q in clean[interface]["qdisc"])
        self.interface = interface
        self.mtu = str(mtu)
        try:
            run("sudo", "-n", "ip", "link", "add", REFERENCE_IFB, "type", "ifb")
            self.ifb_added = True
            run("sudo", "-n", "ip", "link", "set", "dev", REFERENCE_IFB, "mtu", self.mtu, "up")
            self.tree(REFERENCE_IFB)
            tc("class", "add", "dev", REFERENCE_IFB, "parent", REFERENCE_ROOT + "fff0", "classid", REFERENCE_CLASS, "htb",
               "rate", f'{htb["rate"] * 8}bit', "ceil", f'{htb["ceil"] * 8}bit',
               "burst", str(htb["burst"]), "cburst", str(htb["cburst"]),
               "quantum", str(htb["quantum"]), "prio", str(htb["prio"]))
            tc("qdisc", "add", "dev", REFERENCE_IFB, "parent", REFERENCE_CLASS, "handle", "1:", "fq_codel",
               "limit", str(leaf["limit"]), "memory_limit", str(leaf["memory_limit"]),
               "flows", str(leaf["flows"]), "quantum", str(leaf["quantum"]),
               "target", "5ms", "interval", "100ms",
               "ecn" if leaf["ecn"] else "noecn", "drop_batch", str(leaf["drop_batch"]))
            tc("qdisc", "add", "dev", interface, "clsact")
            self.ingress_added = True
            tc("filter", "add", "dev", interface, "ingress", "protocol", "ip", "pref", "10000",
               "flower", "skip_hw", "ip_proto", "tcp", "src_ip", src, "dst_ip", dst,
               "src_port", sport, "dst_port", dport, "action", "skbedit", "priority", REFERENCE_CLASS, "pipe",
               "action", "mirred", "egress", "redirect", "dev", REFERENCE_IFB)
            if mirror_egress:
                self.tree(interface, "replace")
            return inspect_tc(interface, REFERENCE_IFB)
        except BaseException:
            self.stop()
            raise

    def tree(self, device, operation="add"):
        tc("qdisc", operation, "dev", device, "root", "handle", REFERENCE_ROOT, "htb", "default", "fff1")
        if device == self.interface:
            self.egress_added = True
        for minor, parent in (("fff0", REFERENCE_ROOT), ("fff1", REFERENCE_ROOT), ("fffe", REFERENCE_ROOT + "fff0")):
            tc("class", "add", "dev", device, "parent", parent, "classid", REFERENCE_ROOT + minor,
               "htb", "rate", "100gbit", "ceil", "100gbit", "quantum", self.mtu)
        tc("qdisc", "add", "dev", device, "parent", REFERENCE_ROOT + "fffe", "handle", "fffe:", "fq_codel")

    def stop(self):
        if self.ingress_added:
            tc("qdisc", "del", "dev", self.interface, "clsact")
            self.ingress_added = False
        if self.egress_added:
            tc("qdisc", "del", "dev", self.interface, "root")
            self.egress_added = False
        if self.ifb_added:
            run("sudo", "-n", "ip", "link", "del", REFERENCE_IFB)
            self.ifb_added = False
        self.interface = None


def guest_sample(local, remote, ifb=None, minor=None, reference=False, interface=None):
    out = {}
    if ifb is not None:
        if reference:
            assert ifb == REFERENCE_IFB
            classid = REFERENCE_CLASS
        else:
            journal = json.loads(run("sudo", "-n", "cat", JOURNAL))
            assert journal["ifb"] == ifb and re.fullmatch(r"/sys/fs/bpf/fg-m1-[a-f0-9]+", journal["pin"])
            classid = f'{journal["dl_major"]:x}:{minor:x}'
        began = time.monotonic_ns()
        classes = json.loads(tc("-s", "-d", "-j", "class", "show", "dev", ifb))
        class_at = time.monotonic_ns()
        qdiscs = json.loads(tc("-s", "-d", "-j", "qdisc", "show", "dev", ifb))
        out.update(
            classid=classid, began_ns=began, class_ns=class_at, ended_ns=time.monotonic_ns(),
            wall_ns=time.time_ns(),
            htb=next(row for row in classes if row.get("handle") == classid and row["class"] == "htb"),
            leaf=next(row for row in qdiscs if row.get("parent") == classid),
        )
        if not reference:
            out["redirected"] = json.loads(run("sudo", "-n", RELEASE + "/kernel", "stats", journal["pin"]))[5]
    if interface:
        out["nic_qdisc"] = json.loads(tc("-s", "-j", "qdisc", "show", "dev", interface))
        out["nic_classes"] = json.loads(tc("-s", "-j", "class", "show", "dev", interface))
    out["tcp"] = run("ss", "-tinme", f"src {local} and dst {remote}")
    return out


def guest_loop():
    print(json.dumps({"role": "download-trace"}), flush=True)
    reference = Reference()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            operation = request.pop("op", None)
            if operation == "inspect":
                output = inspect_tc(**request)
            elif operation == "reference-start":
                output = reference.start(**request)
            elif operation == "reference-stop":
                reference.stop()
                output = {}
            elif operation == "gro-off":
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
    reference.stop()


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
