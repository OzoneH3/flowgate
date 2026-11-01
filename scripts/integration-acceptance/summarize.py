#!/usr/bin/env python3
"""Index exact evidence without treating missing/ambiguous assertions as passes."""
import argparse, collections, hashlib, json, pathlib
from priority_assess import assess_game
p = argparse.ArgumentParser()
p.add_argument('evidence', type=pathlib.Path)
a = p.parse_args()
r = a.evidence.resolve()
assert r.name == 'integration-acceptance' and '.workspace' in r.parts

def read(path):
    return json.loads(path.read_text())

def verdict(values):
    if any(v is False or v == 'Fail' for v in values):
        return 'Fail'
    if any(v == 'Not tested' for v in values):
        return 'Not tested'
    if any(v == 'Inconclusive' or v is None for v in values):
        return 'Inconclusive'
    return 'Pass' if all(v is True or v == 'Pass' for v in values) else 'Inconclusive'

stages = []
for path in sorted(list(r.glob('extensions-v2/*/evidence/results.json')) + list(r.glob('policy-v3/*/evidence/results.json')) + list(r.glob('P1-v3/*/evidence/results.json'))):
    values = read(path)
    superseded = {}
    if 'extensions-v2' in str(path):
        for key in ('P1-effect-upload','P1-effect-download'):
            if key in values:
                superseded[key] = values[key]
                values[key] = {'result':'Not tested'}
    records_path = path.with_name('records.json')
    p2 = [x for x in read(records_path) if x.get('kind') == 'P2-game'] if records_path.is_file() else []
    p2_assessment = None
    normal = [x for x in p2 if x['phase'] == 'normal']
    high = [x for x in p2 if x['phase'] == 'game-high']
    if len(normal) == len(high) == 3:
        n = [x['echo_rtt']['p95_ms'] for x in normal]
        h = [x['echo_rtt']['p95_ms'] for x in high]
        benefit = sum(n)/3-sum(h)/3
        spread = max(max(n)-min(n), max(h)-min(h))
        state = assess_game(normal, high)['result']
        p2_assessment = {'result': state, 'benefit_ms': benefit, 'within_phase_spread_ms': spread,
                         'raw': values.get('P2-benefit'),
                         'reason': 'Frozen within-phase variation; old evaluator incorrectly included the inter-phase effect in spread'}
        values['P2-benefit'] = {'result': state}
    rows = [{'assertion': key, 'status': verdict(item.values()), 'checks': item}
            for key, item in values.items()]
    stages.append({'kind': 'corrected priority P1' if 'P1-v3' in str(path) else 'policy/validation' if 'policy-v3' in str(path) else 'extensions', 'mode': path.parents[1].name,
                   'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                   'counts': dict(collections.Counter(x['status'] for x in rows)), 'rows': rows, 'p2_assessment': p2_assessment, 'superseded_priority_effects': superseded, 'superseded_reason': 'control phase rebinding was not awaited; see P1-v3' if superseded else None})
for path in r.glob('lifecycle-v2/evidence/lifecycle-results.json'):
    stages.append({'kind': 'kernel components', 'path': str(path), 'rows': read(path)})
for path in (list(r.glob('reference-v4/evidence/results.json')) or list(r.glob('reference-v2/evidence/results.json'))):
    stages.append({'kind': 'off + shaper disabled reference', 'path': str(path), 'checks': read(path)})
models = {}
for name in ['focused-go-3.jsonl', 'focused-race.jsonl', 'accounting-components-final.jsonl']:
    path = r / name
    if path.is_file():
        counts = collections.Counter()
        for line in path.read_text().splitlines():
            item = json.loads(line)
            if item.get('Test') and item.get('Action') in ('pass', 'fail', 'skip'):
                counts[item['Action']] += 1
        models[name] = dict(counts)
output = {'schema': 1, 'source': read(r/'complete-core-v4/core-report.json')['baseline_source'],
          'core_report': str(r/'complete-core-v4/core-report.json'),
          'stages': stages, 'component_tests': models,
          'known_omissions': ['Integrated fast-path application-usage accounting unfinished/not tested',
              'Physical Unraid confirmation plan only', 'Wine shaping unsupported',
              'Fresh Wine receiver load not run: retained source-equivalent evidence reused',
              'GUI uses exact bundle with synthetic API, not live daemon',
              'Echo windows in core lack bracketing queue snapshots; missing echoes remain Fail',
              'TCG CPU and RTT do not establish physical host overhead']}
(r/'evidence-index.json').write_text(json.dumps(output, indent=2)+'\n')
print(json.dumps({'stages': len(stages), 'component_tests': models}))
