"""Assess retained raw cells by frozen loss rules; never alter receiver evidence."""
import copy
from measure import htb_leaf, klass, queue_drop

def queue_delta(before, after):
    """Counters are cumulative per session; an unpaired generation is unknown."""
    before = before or {}; after = after or {}
    old = {x['generation']: x for x in before.get('sessions', [])}
    total = {}
    for row in after.get('sessions', []):
        previous = old.get(row['generation'])
        if previous is None:
            return None
        for key, value in row.get('counters', {}).items():
            delta = int(value) - int(previous.get('counters', {}).get(key, 0))
            if delta < 0:
                return None
            total[key] = total.get(key, 0) + delta
    return total

def assess(raw):
    row = copy.deepcopy(raw)
    row['raw_status'] = raw['status']
    expected = row['expected']['expected_v2']
    ul_cap = expected['caps']['ul_cap_bps']
    observations = []
    failed = False
    for name, window in [('quiet', row.get('quiet', {}))] + [
        ('bulk-' + str(w['window']), w) for w in row.get('windows', [])
    ]:
        loss = window.get('loss', {})
        if not loss:
            continue
        before = window.get('before', {}).get('queue', loss.get('queue_before'))
        after = window.get('after', {}).get('queue', loss.get('queue_after'))
        counters = queue_delta(before, after)
        missing = loss.get('missing', 0)
        rejection_names = ('deadline_rejections', 'attribution_capacity_rejections',
                           'census_capacity_rejections', 'fairness_displacement_rejections')
        rejection_upper = sum(counters.get(k, 0) for k in rejection_names) if counters is not None else None
        item = {'window': name, 'missing': missing, 'queue_counter_delta': counters,
                'firewall_rejection_explanation_upper_bound': rejection_upper,
                'scope': 'host-wide guest session counters; correlation is not exact per-flow attribution'}
        shaping = expected['queues']['app_ul_class'] or expected['queues']['default_ul_budget_class']
        leafs0 = htb_leaf(window.get('before', {}).get('tc', []))
        leafs1 = htb_leaf(window.get('after', {}).get('tc', []))
        if expected['queues']['app_ul_class']:
            q0 = leafs0[0] if len(leafs0) == 1 else {}
            q1 = leafs1[0] if len(leafs1) == 1 else {}
        else:
            q0 = klass(window.get('before', {}).get('tc', []), 'fffe')
            q1 = klass(window.get('after', {}).get('tc', []), 'fffe')
        drops = None
        if shaping and q0.get('handle') == q1.get('handle') and q1:
            d0 = queue_drop(window.get('before', {}).get('qdisc', []), q0['handle'])
            d1 = queue_drop(window.get('after', {}).get('qdisc', []), q1['handle'])
            if d1 >= d0:
                drops = d1 - d0
        item['applicable_shaping_queue'] = q1.get('handle') if shaping else None
        item['leaf_qdisc_drop_delta'] = drops
        remainder = max(0, missing - (rejection_upper or 0) - (drops or 0))
        item['unclassified_after_explanation_upper_bounds'] = remainder
        threshold = 0 if name == 'quiet' else max(2, loss.get('sent_ok', 0) * .005)
        if not missing:
            item['result'] = 'Pass'
        elif shaping and drops is not None and drops + (rejection_upper or 0) >= missing:
            item['result'] = 'Inconclusive'
            item['reason'] = 'Mixed traffic shaping drops plus firewall rejections cover missing count only as an upper bound'
        elif remainder > threshold:
            failed = True
            item['result'] = 'Fail'
            item['reason'] = 'Unexplained loss exceeds frozen quiet/load threshold'
        elif rejection_upper and not shaping:
            failed = True
            item['result'] = 'Fail'
            item['reason'] = 'Firewall path dropped allowed traffic; deadline/admission rejection observed (stricter continuity check, separate from unexplained-loss threshold)'
        else:
            item['result'] = 'Inconclusive'
            item['reason'] = 'Missing packets remain below frozen load-failure threshold; cause not established'
        observations.append(item)
    row['loss_assessment'] = observations
    if failed:
        row['status'] = 'Fail'
    row['assessment_note'] = 'Raw evidence preserved; frozen loss requirements applied to per-session counter deltas. No threshold changes.'
    return row
