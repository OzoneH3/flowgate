#!/usr/bin/python3
"""Disposable guest witnesses. Invoked by test units, never by FlowGate."""
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

STATE = Path("/var/lib/flowgate-guard-acceptance")
RECORD = Path("/run/flowgate-enforcement/guard.json")
DEST = "10.79.0.2"
SOURCE = "10.79.0.1"


def run(*args, timeout=12):
    return subprocess.check_output(args, text=True, timeout=timeout)


def api(operation="list", **fields):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect("/run/flowgate-api/daemon.sock")
        sock.sendall((json.dumps(dict(version=1, operation=operation, **fields)) + "\n").encode())
        value = json.loads(sock.makefile("rb").readline())
    if value.get("error"):
        raise RuntimeError(value)
    return value


def dial(label, port, source_port=0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.8)
        sock.bind((SOURCE, source_port))
        try:
            sock.connect((DEST, port))
            sock.sendall(label.encode() + b"\n")
        except TimeoutError:
            return {"client": "timeout", "label": label}
        except OSError as err:
            return {"client": "socket-error", "errno": err.errno, "label": label}
    return {"client": "written", "label": label}


def observe(stage, nic, port, prefix):
    value = {"stage": stage, "monotonic_usec": time.monotonic_ns() // 1000,
             "selinux": run("getenforce").strip(), "result": "fail"}
    try:
        assert value["selinux"] == "Enforcing", value
        value["guard"] = json.loads(RECORD.read_text())
        value["table"] = table = json.loads(run("nft", "-j", "list", "table", "inet", "flowgate_guard"))
        entries = table["nftables"]
        expected = "flowgate:guard:" + value["guard"]["token"]
        assert any(row.get("table", {}).get("comment") == expected for row in entries), table
        assert len(value["guard"]["digest"]) == 64, value["guard"]
        for name in ("input", "output"):
            assert any(row.get("chain", {}).get("hook") == name
                       and row["chain"]["prio"] == 9 for row in entries), table
            assert any(row.get("rule", {}).get("chain") == name
                       and any("drop" in expr for expr in row["rule"]["expr"])
                       for row in entries), table
        if stage == "early":
            start = run("systemctl", "show", "-P", "ExecMainStartTimestampMonotonic", "NetworkManager.service")
            value["network_manager_start_usec"] = int(start)
            assert value["network_manager_start_usec"] == 0, value
        run("ip", "link", "set", nic, "up")
        run("ip", "address", "replace", SOURCE + "/24", "dev", nic)
        value["route"] = run("ip", "-4", "route", "get", DEST, "from", SOURCE).strip()
        # Witness this exact SYN on both sides of the guard's output hook.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as spare:
            spare.bind((SOURCE, 0))
            source_port = spare.getsockname()[1]
        match = f"ip saddr {SOURCE} ip daddr {DEST} tcp sport {source_port} tcp dport {port}"
        rules = f"""add table inet flowgate_test_witness
add chain inet flowgate_test_witness before_guard {{ type filter hook output priority 8; policy accept; }}
add chain inet flowgate_test_witness after_guard {{ type filter hook output priority 10; policy accept; }}
add rule inet flowgate_test_witness before_guard {match} counter
add rule inet flowgate_test_witness after_guard {match} counter
"""
        subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True, timeout=10)
        try:
            label = f"{prefix}-{stage}-{time.monotonic_ns()}"
            value["probe"] = dial(label, port, source_port)
            rows = json.loads(run("nft", "-j", "list", "table", "inet", "flowgate_test_witness"))["nftables"]
            value["counters"] = counters = {
                row["rule"]["chain"]: row["rule"]["expr"][-1]["counter"]["packets"]
                for row in rows if "rule" in row
            }
            assert counters["before_guard"] > 0 and counters["after_guard"] == 0, counters
            assert value["probe"]["client"] != "written", value["probe"]
        finally:
            run("nft", "delete", "table", "inet", "flowgate_test_witness")
        value["result"] = "pass"
    except Exception as exc:
        value["error"] = str(exc) or repr(exc)
        raise
    finally:
        with (STATE / "witness.jsonl").open("a") as evidence:
            evidence.write(json.dumps(value) + "\n")


def guard_table_present():
    tables = json.loads(run("nft", "-j", "list", "tables"))["nftables"]
    return any(row.get("table", {}).get("name") == "flowgate_guard" for row in tables)


def observe_stop():
    guarded = guard_table_present()
    (STATE / "before-restart.json").write_text(json.dumps({
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "monotonic_usec": time.monotonic_ns() // 1000,
        "guard": json.loads(RECORD.read_text()) if guarded else None,
    }) + "\n")


def check_guard_removed():
    assert not guard_table_present(), "guard table remained after handoff"


def finish(nic, port, prefix):
    report = {"result": "fail"}
    try:
        # Both units finished their start transaction before this witness runs.
        guard = run("systemctl", "show", "flowgate-guard.service",
                    "-p", "ExecStart", "-p", "ExecMainStatus", "-p", "Result",
                    "-p", "ActiveEnterTimestampMonotonic")
        boot_pre = run("systemctl", "show", "flowgate.service", "-p", "ExecStartPre")
        nm_started = int(run("systemctl", "show", "-P", "ExecMainStartTimestampMonotonic",
                             "NetworkManager.service"))
        report.update(boot_guard_unit=guard, boot_exec_start_pre=boot_pre, network_manager_start_usec=nm_started)
        assert "ExecMainStatus=0" in guard and "Result=success" in guard, guard
        assert nm_started > 0, nm_started
        cold = api()
        report["boot_generation"] = cold["generation"]
        assert cold["protection"]["state"] == "active", cold["protection"]
        assert cold["protection"]["profile"] == "both", cold["protection"]
        check_guard_removed()
        run("ip", "link", "set", nic, "up")
        run("ip", "address", "replace", SOURCE + "/24", "dev", nic)
        report["boot_control"] = dial(prefix + "-boot-allow", port)
        assert report["boot_control"]["client"] == "written", report["boot_control"]

        run("systemctl", "reset-failed", "flowgate.service")
        run("systemctl", "restart", "flowgate.service", timeout=85)
        report["before_restart"] = json.loads((STATE / "before-restart.json").read_text())
        report["restart_exec_start_pre"] = run("systemctl", "show", "flowgate.service", "-p", "ExecStartPre")
        after = api()
        report["restart_generation"] = after["generation"]
        assert cold["generation"] != after["generation"], after["generation"]
        assert after["protection"]["state"] == "active" and after["protection"]["profile"] == "both"
        check_guard_removed()
        report["restart_control"] = dial(prefix + "-restart-allow", port)
        assert report["restart_control"]["client"] == "written", report["restart_control"]
        report["result"] = "pass"
    except Exception as exc:
        report["error"] = str(exc) or repr(exc)
        raise
    finally:
        try:
            # Restore management reachability after both protected checks.
            status = api()
            if status["protection"]["state"] != "stopped":
                api("protection-stop", generation=status["generation"], protection_id=status["protection"]["id"])
        except Exception as exc:
            report["stop_error"] = str(exc) or repr(exc)
            # The guard may intentionally block SSH after a failed handoff.
            # Use the installed rescue path so the host can collect evidence.
            try:
                run("/usr/local/libexec/flowgate/rescue", "--stop-only", timeout=45)
            except Exception as recovery:
                report["recovery_error"] = str(recovery) or repr(recovery)
        (STATE / "result.json").write_text(json.dumps(report) + "\n")


if __name__ == "__main__":
    if not __debug__:
        raise SystemExit("Run the fixture with assertions enabled")
    stage, nic, port, prefix = sys.argv[1:]
    if stage == "finish":
        finish(nic, int(port), prefix)
    elif stage == "stop":
        observe_stop()
    else:
        observe(stage, nic, int(port), prefix)
