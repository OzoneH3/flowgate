"""Validate receiver evidence from the isolated M1 native run, not API success."""
import json
import sys

rows = json.load(open(sys.argv[1]))
phases = {r['label']: r for r in rows if r['kind'] == 'phase'}
assert set(phases) == {'baseline', 'cap4m', 'cap8m', 'livechange', 'removed'}
for name, r in phases.items():
    for app, expected in [('A',1000),('A2',1000),('B',200)]:
        assert r['send'][app]['sent'] == r['receive'][app]['received'] == expected, (name,app)
        assert r['send'][app]['errors'] == 0, (name,app)
        assert r['receive'][app]['p95_ms'] < (50 if app == 'B' else 1000), (name,app,'latency')
    assert r['receive']['D']['received'] == 0
    assert all(int(v)==0 for s in r['queue_after']['sessions'] for v in s['counters'].values()), name
for name, cap in [('cap4m',4000000),('cap8m',8000000)]:
    r=phases[name]
    delivered=sum(r['receive'][n]['bytes'] for n in ('A','A2'))
    # Payload delivery cannot exceed the shared cap (allow a small token burst).
    assert delivered <= cap/8*r['wall_seconds']+12000, name
    assert delivered*8/r['wall_seconds'] > cap*0.45, (name,'underutilized')
needed={'foreign-refusal','live-cap','unconnected-multipeer','descriptor-transfer',
        'failure-restart','close-retirement','v6-multipeer-deny','foreign-mutation','cleanup'}
assert needed <= {r['kind'] for r in rows}
print('PASS: receiver delivery, shared cap bounds, sub-second p95, independent app, Deny and lifecycle evidence')
