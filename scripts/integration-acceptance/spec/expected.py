#!/usr/bin/env python3
"""Derive per-cell expected results for the 144-cell core matrix (RESEARCH, spec v2).

Expectations come from the INTENDED contract (docs/TRAFFIC-PRIORITY.txt, ZONE-SHAPING.txt,
DOWNLOAD-LIMITER.txt, experiments/socket-auth/CONTRACT.txt). Where the frozen code
deviates or the capability is absent, the field says so explicitly ("known_defect",
"unsupported", "experimental"); code behaviour is never silently adopted as the spec.
Usage: expected.py [matrix.json] > matrix-v2.json   (also prints a diff vs. matrix.json fields to stderr)
"""
import itertools, json, sys, pathlib

MODES = ('fast', 'protected', 'off')
LIMITS = ('none', 'ul', 'dl', 'both')
PRIOS = ('low', 'normal', 'high')
BUDGETS = ('none', 'ul', 'dl', 'both')
CAP = 2_000_000
BUDGET = 16_000_000


def cell(mode, limits, prio, budget):
    ul_cap = CAP if limits in ('ul', 'both') else 0
    dl_cap = CAP if limits in ('dl', 'both') else 0
    b_ul = BUDGET if budget in ('ul', 'both') else 0
    b_dl = BUDGET if budget in ('dl', 'both') else 0
    # All-scope Normal is the omitted default; a Normal-only entry is invalid input
    # (validateConfig + controller rates()). The core cell therefore stores NO entry.
    entry = bool(ul_cap or dl_cap or prio != 'normal')
    # Direction relevance (controller has_class): cap_d, or non-Normal priority with budget_d.
    cls_ul = entry and bool(ul_cap or (prio != 'normal' and b_ul))
    cls_dl = entry and bool(dl_cap or (prio != 'normal' and b_dl))
    protected = mode in ('fast', 'protected')
    e = {
        'config': {
            'submitted_entry': ({'scope': 'all', 'bits_per_second': ul_cap, 'download_bits_per_second': dl_cap,
                                 'traffic_priority': None if prio == 'normal' else prio} if entry else None),
            'upload_budget_bits_per_second': b_ul, 'download_budget_bits_per_second': b_dl, 'schema': 3,
            'accepted': True,  # admission: 2M caps/16M budgets give floors >= 256k (checked below)
            'applied_version_reached': True,
        },
        'queues': {
            'app_ul_class': cls_ul, 'app_dl_class': cls_dl,
            # fffe always exists in tc; budget mode = status traffic_priority.default_class.<dir> non-null
            'default_ul_budget_class': bool(b_ul), 'default_dl_budget_class': bool(b_dl),
            'app_ul_tuple': ({'ceil_bps': min(ul_cap or b_ul, b_ul) if b_ul else ul_cap,
                              'htb_prio': {'high': 0, 'normal': 1, 'low': 2}[prio] if b_ul else 0} if cls_ul else None),
            'app_dl_tuple': ({'ceil_bps': min(dl_cap or b_dl, b_dl) if b_dl else dl_cap,
                              'htb_prio': {'high': 0, 'normal': 1, 'low': 2}[prio] if b_dl else 0} if cls_dl else None),
        },
        'bindings': {
            # Bind is issued for every socket of a CONFIGURED app; a verified class binding only
            # where a class exists. Cells without any class must NOT wait for bindings.
            'wait_for_upload_class_binding': cls_ul,
            'wait_for_download_class_binding': cls_dl,
            'binding_wait_allowed': cls_ul or cls_dl,
            'entry_without_class': entry and not (cls_ul or cls_dl),  # binding appears with no class (minor 0) and uses a slot
            'no_entry': not entry,
        },
        'traffic_placement': {
            'udp_ul_game_socket': 'app_class' if cls_ul else ('default_fffe' if b_ul else 'bypass_fff1_or_unshaped'),
            'tcp_ul_bulk_two_sockets': 'app_class' if cls_ul else ('default_fffe' if b_ul else 'bypass_fff1_or_unshaped'),
            'tcp_dl_established': 'app_class_ifb' if cls_dl else ('default_fffe_ifb' if b_dl else 'not_redirected'),
            'udp_dl': ('default_fffe_ifb' if b_dl else 'not_redirected') + ' (per-app UDP DL unsupported)',
        },
        'caps': {
            'ul_cap_bps': ul_cap or None, 'ul_cap_applies_to': 'A combined: 2 TCP UL + connected UDP UL' if ul_cap else None,
            'dl_cap_bps': dl_cap or None, 'dl_cap_applies_to': 'A TCP DL only (UDP DL never per-app)' if dl_cap else None,
            'ul_budget_bps': b_ul or None, 'dl_budget_bps': b_dl or None,
            'bound': 'SPEC.md §4 derived ceiling; no fixed multiplier',
        },
        'priority': {
            'ul': ('active' if (entry and prio != 'normal' and b_ul) else 'dormant'),
            'dl': ('active' if (entry and prio != 'normal' and b_dl) else 'dormant'),
            'effect_assessed_in_core': False,  # no contending app; floors clamp to 2M caps. See P1/P2.
        },
        'fast_path': {
            'expected': mode == 'fast',
            'requirement': ('A connected IPv4 UDP grant active; fast hits grow during the quiet window by ~datagrams sent; '
                            'no grant closed/refused by the shaping edit; same flow charged to its expected class (SPEC §3)'
                            if mode == 'fast' else 'no socket-authorization route gate; fast counters absent/zero'),
        },
        'firewall': {
            'flowgate_host_table': protected,
            'deny_sender_delivered': 0 if protected else 'all offered (no protection claim)',
            'allow_rule_required': protected,
        },
        'comparison_role': {
            'fast': 'fast-path + shaping combination',
            'protected': 'ordinary queue + shaping combination; vs off same cell = firewall increment',
            'off': 'protection-off + shaping combination (NOT a no-shaping baseline); vs reference R0 = shaping-only effect',
        }[mode],
        'capability_gaps': ['per-app UDP DL unsupported', 'Wine/Proton shaping unsupported',
                            'UDP UL GSO path unsupported (non-GSO sender only)'],
    }
    return {'id': f'{mode}-{limits}-{prio}-{budget}', 'mode': mode, 'limits': limits, 'priority': prio,
            'budget': budget, 'expected_v2': e}


def admitted(budget, caps):
    """Mirror allocationAdmitted / controller allocate() for the core population."""
    if not budget:
        return True
    pct = {'low': 10, 'normal': 15, 'high': 20}
    nominal = [budget * 15 // 100] + [min(budget * pct[p] // 100, c or budget) for p, c in caps]
    pool = budget * 3 // 5
    tot = sum(nominal)
    return all((n if tot <= pool else n * pool // tot) >= 256_000 for n in nominal)


def main():
    cells = [cell(*k) for k in itertools.product(MODES, LIMITS, PRIOS, BUDGETS)]
    for c in cells:
        e = c['expected_v2']
        for d, key in (('ul', 'upload_budget_bits_per_second'), ('dl', 'download_budget_bits_per_second')):
            caps = [(c['priority'], CAP if c['limits'] in (d, 'both') else 0)] if e['queues'][f'app_{d}_class'] else []
            assert admitted(e['config'][key], caps), c['id']
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if src and src.exists():
        old = {x['id']: x.get('expected', {}) for x in json.loads(src.read_text())['core']}
        diffs = []
        for c in cells:
            o, e = old.get(c['id'], {}), c['expected_v2']
            for k, v in (('ul_class', e['queues']['app_ul_class']), ('dl_class', e['queues']['app_dl_class']),
                         ('fast_ipv4_udp', e['fast_path']['expected'])):
                if k in o and o[k] != v:
                    diffs.append(f"{c['id']}: {k} v1={o[k]} v2={v}")
            if 'hard_cap_mbps' in o and c['limits'] == 'none':
                diffs.append(f"{c['id']}: hard_cap_mbps={o['hard_cap_mbps']} but no cap configured")
        print(f'{len(diffs)} v1/v2 differences', file=sys.stderr)
        for d in diffs[:60]:
            print('  ' + d, file=sys.stderr)
    json.dump({'schema': 2, 'source': '93eaa868ec2a1f98c0b66b27a682e2f332a23746',
               'spec': 'spec/SPEC.md', 'core': cells}, sys.stdout, indent=1)


if __name__ == '__main__':
    main()
