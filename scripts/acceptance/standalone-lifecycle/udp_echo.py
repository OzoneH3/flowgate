"""Labeled UDP exchange and socket accounting assertions for standalone lifecycle."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time
import uuid

# Same header as flowgate-lab/udp_probe.py. Echoes retain the label, sequence
# and timestamp but are shorter so the two byte counters cannot be swapped.
HEADER = struct.Struct("<16sQQ")
REQUEST_SIZE = 1200
REPLY_SIZE = 400


def receive_batch(sock, count, on_datagram):
    """Record raw arrivals, including duplicates, through a brief quiet period."""
    arrivals = []
    deadline = time.monotonic() + 5
    while (remaining := deadline - time.monotonic()) > 0:
        sock.settimeout(min(remaining, .35) if len(arrivals) >= count else remaining)
        try:
            packet, peer = sock.recvfrom(2048)
        except TimeoutError:
            break
        arrivals.append(on_datagram(packet, peer))
    return arrivals


def echo(sock, label, count):
    def receive(packet, peer):
        wire_label, seq, _ = HEADER.unpack_from(packet)
        assert wire_label == label.encode() and len(packet) == REQUEST_SIZE, (wire_label, len(packet))
        sent = sock.sendto(packet[:REPLY_SIZE], peer)
        return {"sequence": seq, "received_bytes": len(packet), "sent_bytes": sent}

    return receive_batch(sock, count, receive)


def guest_probe(source):
    from guest_tools import bind, endpoint, reply_loop

    assert os.geteuid() != 0
    with bind(source, 0) as marker, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        marker.listen()
        sock.bind((source, 0))
        stat = Path("/proc/self/stat").read_text()
        print(json.dumps({
            "pid": os.getpid(), "uid": os.getuid(), "start_ticks": stat.rsplit(")", 1)[1].split()[19],
            "exe": os.readlink("/proc/self/exe"),
            "anchor": endpoint(marker.getsockname()), "anchor_inode": os.fstat(marker.fileno()).st_ino,
            "udp_socket": {
                "local": endpoint(sock.getsockname()), "inode": os.fstat(sock.fileno()).st_ino,
                "cookie": sock.getsockopt(socket.SOL_SOCKET, 57, 8).hex(),  # Linux SO_COOKIE
                "netns": os.readlink("/proc/self/ns/net"), "protocol": "udp",
            },
        }), flush=True)

        def exchange(label, host, port, count):
            peer = (host, port)
            requests = [HEADER.pack(label.encode(), seq, time.monotonic_ns()).ljust(REQUEST_SIZE, b"\0")
                        for seq in range(count)]
            sent = []
            for packet in requests:
                sent.append(sock.sendto(packet, peer))
                time.sleep(.025)

            def receive(packet, sender):
                _, seq, _ = HEADER.unpack_from(packet)
                assert sender == peer and 0 <= seq < count, (sender, seq)
                assert packet == requests[seq][:REPLY_SIZE], (seq, len(packet))
                return {"sequence": seq, "received_bytes": len(packet)}

            return {"sent_bytes": sent, "echoes": receive_batch(sock, count, receive)}

        reply_loop(exchange)


def verify(sut, api, record, result, daemon_generation, collector_generation):
    from scenarios import A
    from udp_case import COUNT, UDPScenario, timestamp
    from vm import TCP_SOURCES, wait_for

    script = Path(__file__).name
    sut.upload(Path(__file__), script)
    # Give the UDP policy its own observed executable identity so the saved
    # application Block on the TCP probe applies throughout the lifecycle.
    sut.run("cp fg-lab/fg-lab-probe fg-lab/fg-lab-udp-probe")
    source = TCP_SOURCES[A]
    label = uuid.uuid4().hex[:16]
    expected = {"uploaded": COUNT * REQUEST_SIZE, "downloaded": COUNT * REPLY_SIZE}
    result.update(label=label, host_uid=os.geteuid(), expected_bytes=expected, expected_datagrams=COUNT,
                  request_payload_bytes=REQUEST_SIZE, echo_payload_bytes=REPLY_SIZE)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as host:
        host.bind(("127.0.0.1", 0))
        port = host.getsockname()[1]
        probe = sut.channel(f"fg-lab/fg-lab-udp-probe -B fg-lab/{script} {source}", "lifecycle-udp")
        case = UDPScenario(api, probe, None, record)
        try:
            identity = probe.hello["udp_socket"]
            result.update(socket=identity, guest_uid=probe.hello["uid"], remote=f"{A}:{port}")
            result["allow_rule"] = case.port_rule("allow", port)

            def sample():
                state = api()
                assert state["generation"] == daemon_generation, "daemon changed during UDP exchange"
                monitor = state["traffic_monitor"]
                assert (monitor["state"], monitor["generation"]) == ("active", collector_generation), monitor
                activity = state["activity"]
                udp = activity.get("udp") or {}
                if (udp.get("state"), udp.get("generation")) != ("active", collector_generation):
                    return None
                rows = [row for row in activity["rows"] or []
                        if all(row["socket"][key] == value for key, value in identity.items())]
                if not rows:
                    return None
                row, = rows
                traffic = row["traffic"]
                if not traffic["available"] or traffic["definition"] != "udp-api-reported":
                    return None
                return {"id": row["id"], "traffic": traffic, "collector": udp,
                        "snapshot_at": state["snapshot_at"]}

            before = result["before"] = wait_for(sample, 15, "no registered UDP probe counters")
            record("udp_accounting_baseline", before)
            with ThreadPoolExecutor(max_workers=1) as worker:
                host_result = worker.submit(echo, host, label, COUNT)
                result["guest"] = probe.call(label=label, host=A, port=port, count=COUNT)
                result["host"] = host_result.result()
            record("udp_accounting_delivery", {"label": label, "guest": result["guest"], "host": result["host"]})
            boundary = timestamp(api("traffic-status")["server_time"]) + timedelta(milliseconds=300)

            def fresh_sample():
                now = sample()
                if now and (now["collector"]["sample_ns"] > before["collector"]["sample_ns"]
                            and timestamp(now["collector"]["collected"]) >= boundary):
                    return now

            after = result["after"] = wait_for(fresh_sample, 12, "no fresh post-exchange UDP sample")
            assert after["id"] == before["id"], (before, after)
            assert after["traffic"]["since"] == before["traffic"]["since"], (before, after)
            observed = result["observed_bytes"] = {
                field: after["traffic"][field] - before["traffic"][field] for field in expected
            }
            record("udp_accounting_delta", {"label": label, "expected": expected, "observed": observed})
            assert observed == expected, (expected, observed)

            guest, arrivals = result["guest"], result["host"]
            assert guest["sent_bytes"] == [REQUEST_SIZE] * COUNT, guest
            assert sorted(row["sequence"] for row in arrivals) == list(range(COUNT)), arrivals
            assert all((row["received_bytes"], row["sent_bytes"]) == (REQUEST_SIZE, REPLY_SIZE)
                       for row in arrivals), arrivals
            echoes = guest["echoes"]
            assert sorted(row["sequence"] for row in echoes) == list(range(COUNT)), echoes
            assert all(row["received_bytes"] == REPLY_SIZE for row in echoes), echoes
            result["datagrams"] = {"guest_sent": len(guest["sent_bytes"]), "host_received": len(arrivals),
                                   "host_echoed": len(arrivals), "guest_received": len(echoes)}
        finally:
            try:
                case.cleanup()
            finally:
                probe.close()


if __name__ == "__main__":
    guest_probe(sys.argv[1])
