#!/usr/bin/env python3
"""Read retained isolated results; no host operations or acceptance exemptions."""
import json,pathlib,statistics,sys
root=pathlib.Path(sys.argv[1])
def load(mode,name):return json.loads((root/mode/name).read_text())
def stats(values):
    v=sorted(values)
    return dict(count=len(v),median_ms=statistics.median(v) if v else None,
        p99_ms=v[min(len(v)-1,int(.99*len(v)))] if v else None,max_ms=max(v) if v else None)
results={mode:load(mode,'result.json') for mode in ('off','candidate')}
rows={mode:{(t,s,i):ms for t,s,i,ms in load(mode,'wine-latency.json') if t.startswith('SAT_')} for mode in results}
report={'scope':'Separate sequential identical workloads; observed per-sequence differences include scheduling noise. No unconditional latency guarantee.', 'flows':{}}
for token in results['candidate']['wine']:
    flow={}
    for mode in results:
        r=results[mode];n=r['datagrams_per_socket'];sockets=r['sockets_per_app']
        expected={(token,s,i) for s in range(sockets) for i in range(n)}
        present={k:v for k,v in rows[mode].items() if k in expected}
        flow[mode]=dict(offered=len(expected),received=len(present),missing_sequences=[list(k[1:]) for k in sorted(expected-present.keys())],
            observed_receiver_latency=stats(list(present.values())),first_datagram_ms={str(s):present.get((token,s,0)) for s in range(sockets)},
            observed_over_10ms=[list(k[1:])+[v] for k,v in sorted(present.items()) if v>10])
    common={k for k in rows['off'].keys() & rows['candidate'].keys() if k[0]==token}
    deltas={k:rows['candidate'][k]-rows['off'][k] for k in common}
    flow['paired_observed_difference']=stats(list(deltas.values()))
    flow['paired_over_10ms']=[list(k[1:])+[v] for k,v in sorted(deltas.items()) if v>10]
    # Deny/Ask losses are intentional. For the explicitly allowed stream,
    # every offered packet must be accounted for; absent rows never pass.
    if token=='SAT_ALPHA_A':
        flow['cold_inclusive_10ms_pass']=bool(common) and not flow['candidate']['missing_sequences'] and not flow['off']['missing_sequences'] and not flow['paired_over_10ms']
    report['flows'][token]=flow
report['acceptance_note']='User accepts one-time connection startup delay. Cold-inclusive pass is diagnostic, not the revised acceptance verdict; recurring spikes and loss still require separate assessment.'
report['native']={mode:results[mode]['native'] for mode in results}
report['cpu']={mode:{round_:load(mode,round_+'-cpu.json') for round_ in ('round1','round2')} for mode in results}
report['gate']={mode:load(mode,'gate-final.json') for mode in results}
report['stall']=load('candidate','verifier-stall.json')
(root/'comparison.json').write_text(json.dumps(report,indent=2)+'\n')
allowed=report['flows'].get('SAT_ALPHA_A',{})
print(f"Comparison: candidate_loss={len(allowed.get('candidate',{}).get('missing_sequences',[]))} paired_max_ms={allowed.get('paired_observed_difference',{}).get('max_ms')} after_expiry={report['stall'].get('receiver_deliveries_after_bound')}; full evidence={root/'comparison.json'}")
