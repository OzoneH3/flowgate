#!/usr/bin/env python3
"""Delete stored FlowGate rules through the running daemon's API.

Uses only the conditional `rule-delete` operation: each request carries the
generation and exact version from the listed snapshot, so a rule edited after
listing is reported as a conflict instead of being deleted. Essential system
networking (preset) rules are kept unless --include-essential is given.
Deletion is permanent; removed rules are not archived.
"""
import argparse
import json
import socket
import sys

DEFAULT_SOCKET = '/run/flowgate-api/daemon.sock'
CAPABILITY = 'conditional-rule-delete-v1'


def call(path, request, timeout=10.0):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall((json.dumps(request) + '\n').encode())
        data = b''
        while not data.endswith(b'\n'):
            chunk = s.recv(1 << 20)
            if not chunk:
                break
            data += chunk
    return json.loads(data)


def describe(rule):
    f = rule.get('filter') or {}
    target = 'all programs' if f.get('all_programs') else (rule.get('executable') or f.get('application') or '?')
    remote = f.get('remote') or f.get('remote_address') or 'any'
    disabled = ' (disabled)' if rule.get('disabled') else ''
    return f"{rule.get('action', '?'):5} {f.get('direction', '?'):8} {f.get('protocol', '*'):3} {target} -> {remote}{disabled}"


def main(argv=None, out=sys.stdout, ask=input):
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--socket', default=DEFAULT_SOCKET, help=f'daemon control socket (default {DEFAULT_SOCKET})')
    p.add_argument('--include-essential', action='store_true', help='also delete Essential system networking rules (may break DNS/DHCP under protection)')
    p.add_argument('--dry-run', action='store_true', help='list what would be deleted; change nothing')
    p.add_argument('--yes', action='store_true', help='do not ask for confirmation')
    a = p.parse_args(argv)

    listing = call(a.socket, {'version': 1, 'operation': 'list'})
    if listing.get('error'):
        print(f"list failed: {listing.get('error_code') or ''} {listing['error']}", file=out)
        return 2
    if CAPABILITY not in (listing.get('capabilities') or []):
        print('daemon does not support conditional rule deletion; nothing deleted', file=out)
        return 2
    generation = listing.get('generation')
    rules = listing.get('rules') or []
    selected = [r for r in rules if a.include_essential or not r.get('preset')]
    kept = len(rules) - len(selected)

    print(f'{len(selected)} rule(s) to delete' + (f'; {kept} Essential rule(s) kept' if kept else ''), file=out)
    for r in selected:
        print('  ' + describe(r), file=out)
    if not selected or a.dry_run:
        if a.dry_run:
            print('dry run: nothing deleted', file=out)
        return 0
    if listing.get('read_only'):
        print('this socket is read-only; nothing deleted', file=out)
        return 2
    if not a.yes and ask('Type "clear" to permanently delete these rules: ').strip() != 'clear':
        print('cancelled; nothing deleted', file=out)
        return 1

    deleted = failed = 0
    for r in selected:
        response = call(a.socket, {'version': 1, 'operation': 'rule-delete', 'generation': generation,
                                   'id': r['id'], 'expected_version': int(r.get('version') or 0)})
        if response.get('deleted_rule'):
            deleted += 1
            continue
        failed += 1
        code = response.get('error_code') or 'error'
        print(f"  not deleted {r['id']}: {code}: {response.get('error', '')}", file=out)
        if code == 'unavailable':
            print('  rules can only be changed while protection is active', file=out)
            break
        if code == 'generation_conflict':
            print('  the daemon restarted; run this script again', file=out)
            break
    remaining = len(selected) - deleted
    print(f'deleted {deleted} rule(s)' + (f'; {remaining} not deleted' if remaining else ''), file=out)
    return 1 if remaining else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as e:
        print(f'cannot talk to the FlowGate daemon: {e}', file=sys.stderr)
        sys.exit(2)
