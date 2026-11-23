#!/usr/bin/env python3
"""Replay a packaged daemon restart in an unprivileged private namespace.

Usage: python3 -B scripts/checks/test-shaping-restart.py ARCHIVE EMPTY_WORK_DIR
"""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def request(sock_path, operation, expect_error=None, **fields):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(4)
        sock.connect(str(sock_path))
        sock.sendall((json.dumps(dict(version=1, operation=operation, **fields)) + "\n").encode())
        reply = json.loads(sock.makefile("rb").readline())
    assert reply.get("error_code") == expect_error, reply
    return reply


def run(work, parent_netns):
    root = work / "root"
    assert os.getuid() == 0 and os.readlink("/proc/self/ns/net") != parent_netns
    subprocess.run(["mount", "-o", "bind,ro", "/usr", root / "usr"], check=True)
    subprocess.run(["mount", "-t", "proc", "proc", root / "proc"], check=True)
    api = root / "api/s"

    def launch(log):
        with (work / log).open("w") as output:
            process = subprocess.Popen(
                ["chroot", root, "/payload/flowgate", "serve", "--administrator", "--uid", "0",
                 "--socket", "/api/s", "--database", "/state/rules.db",
                 "--experimental-upload-interface", "isolated0",
                 "--experimental-upload-helpers", "/payload",
                 "--experimental-upload-state", "/state/shaping",
                 "--experimental-upload-parent-netns", parent_netns],
                stdout=output, stderr=output,
            )
        for _ in range(100):
            try:
                generation = request(api, "list")["generation"]
                return process, request(api, "upload-status", generation=generation)
            except OSError:
                if process.poll() is not None:
                    break
                time.sleep(.05)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        raise RuntimeError((work / log).read_text())

    wine = dict(uid=0, application="fixture-ambiguous-wine-prefix-a", scope="local",
                bits_per_second=8_000_000, download_bits_per_second=16_000_000,
                traffic_priority="high")
    removed = dict(uid=0, application="fixture-ambiguous-wine-prefix-b", scope="local")
    hosted = dict(uid=0, application="fixture-best-effort-electron", bits_per_second=4_000_000)
    other_user = wine | dict(uid=1000)
    other_zone = wine | dict(scope="internet")
    latest = wine | dict(bits_per_second=10_000_000, download_bits_per_second=24_000_000,
                         traffic_priority="low")

    process, first = launch("before.log")
    try:
        generation = first["generation"]
        snapshot = first["upload_shaping"]
        assert not snapshot["configured_caps"] and not snapshot["enabled"], snapshot
        for edit in (wine, removed | dict(bits_per_second=6_000_000), hosted, other_user,
                     other_zone, latest, removed):
            snapshot = request(
                api, "upload-configure", generation=generation, expected_version=snapshot["version"],
                upload_config=dict(schema=4, enabled=False, caps=[], stored_edit=edit),
            )["upload_shaping"]
        before = snapshot["configured_caps"]
        assert before == [cap | dict(stored_only=True)
                          for cap in (hosted, other_user, other_zone, latest)], before
    finally:
        # A successful acknowledgement must also survive abrupt daemon exit.
        process.kill()
        process.wait(timeout=10)

    process, second = launch("after.log")
    try:
        assert generation != second["generation"], second
        request(api, "upload-status", expect_error="stale_generation", generation=generation)
        after = second["upload_shaping"]
        assert after["configured_caps"] == before, after
        assert not after["enabled"] and after["status"] == "Disabled" and not after.get("kernel"), after
        assert not (root / "state/shaping").exists(), after
        result = dict(source=second["build"]["source"], before_generation=generation,
                      after_generation=second["generation"], before=before,
                      after=after["configured_caps"], status=after["status"], kernel=after.get("kernel"))
        (work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
    finally:
        process.terminate()
        assert process.wait(timeout=10) == 0


def main(archive, work):
    work.mkdir(mode=0o700, exist_ok=True)
    if any(work.iterdir()):
        raise ValueError("Select an empty fixture directory")
    root = work / "root"
    root.mkdir(mode=0o700)
    for name in ("api", "state", "usr", "proc", "payload", "dev", "run", "sys"):
        (root / name).mkdir(mode=0o700)
    for name in ("bin", "sbin", "lib", "lib64"):
        (root / name).symlink_to("usr/" + name)
    subprocess.run(["tar", "-xzf", archive, "-C", root / "payload", "--strip-components=1",
                    "--wildcards", "backend/*"], check=True)
    subprocess.run(["unshare", "-Urmnpf", "--", sys.executable, "-B", __file__, "--isolated",
                    work, os.readlink("/proc/self/ns/net")], check=True)


if __name__ == "__main__":
    if sys.argv[1] == "--isolated":
        run(Path(sys.argv[2]), sys.argv[3])
    else:
        main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
