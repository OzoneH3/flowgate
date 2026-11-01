#!/usr/bin/env python3
"""Emit the complete finite denominator, including missing/failed executions."""
import argparse,json,pathlib,hashlib,collections
from assess_results import assess
HERE=pathlib.Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('results',type=pathlib.Path);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
assert a.output.resolve().is_relative_to(a.results.resolve())
observed={};runs=[];sources=set()
for f in sorted(a.results.glob('*/evidence/core-results.json')):
 stage=f.parents[1];identity=stage/'release-identity.json'
 if identity.is_file():sources.add(json.loads(identity.read_text())['source'])
 else:
  provenance=stage/'provenance.json'
  if provenance.is_file():
   for name,digest in json.loads(provenance.read_text()).get('inputs',{}).items():
    m=pathlib.Path(name)
    if m.name=='manifest.json' and m.is_file() and hashlib.sha256(m.read_bytes()).hexdigest()==digest:sources.add(json.loads(m.read_text())['source'])
 rows=json.loads(f.read_text());runs.append({'path':str(f),'sha256':hashlib.sha256(f.read_bytes()).hexdigest()})
 for row in rows:
  if row['id'] in observed:raise SystemExit('duplicate cell (choose one immutable run series): '+row['id'])
  observed[row['id']]={**assess(row),'evidence':str(f)}
expected=json.loads((HERE/'spec/matrix-v2.json').read_text())['core']
rows=[]
for c in expected:
 row=observed.get(c['id'],dict(id=c['id'],status='Not tested',expected=c,reason='No completed receiver cell in selected series'))
 rows.append(row)
counts=dict(collections.Counter(x['status'] for x in rows))
assert len(sources)<=1,'do not combine different release revisions in one matched core series'
result={'schema':1,'baseline_source':next(iter(sources),'unknown'),'expected_contract_source':'93eaa868ec2a1f98c0b66b27a682e2f332a23746','core_total':len(rows),'counts':counts,'runs':runs,'core':rows,'limitations':['TCG internal-link measurements, not physical NIC or WAN latency','Priority ratio not guaranteed or tested by clamped-cap core','Core is native IPv4 outgoing: protocol/runtime/scope/lifecycle extensions reported separately','One-way guest timestamps are not RTT; quiet_rtt is sequence-matched echo RTT','Bulk UDP shares deliberately constrained cap: drops are not counted as unconstrained overhead']}
a.output.write_text(json.dumps(result,indent=2)+'\n')
text=['FlowGate receiver core expected versus observed','Baseline: '+result['baseline_source'],f"Finite core: {len(rows)} cells; "+', '.join(f'{k}={v}' for k,v in counts.items()),'', '| Cell | Result | Quiet loss | Echo RTT p99/max ms | TCP UL+UDP / TCP DL Mbit/s | Evidence |','|---|---|---|---|---|---|']
for r in rows:
 q=r.get('quiet',{});rt=r.get('quiet_rtt',{});ws=r.get('windows',[]);rates='; '.join(f"{w.get('combined_ul_payload_mbps',0):.3f} / {w.get('tcp_dl_payload_mbps',0):.3f}" for w in ws) or '—'
 text.append(f"| {r['id']} | {r['status']} | {q.get('loss',{}).get('missing','—')} | {rt.get('p99_ms','—')} / {rt.get('max_ms','—')} | {rates} | {r.get('evidence','—')} |")
a.output.with_suffix('.md').write_text('\n'.join(text)+'\n')
print(json.dumps(counts))

# Compare only the matched composite workload cells, retaining uncertainty/status.
comparisons=[]
for c in expected:
 if c['mode']!='fast':continue
 suffix=c['id'].split('-',1)[1];rr={m:observed.get(m+'-'+suffix) for m in ['fast','protected','off']}
 def rt(row,k):return (row or {}).get('quiet_rtt',{}).get(k)
 out={'cell_suffix':suffix,'comparison':'same shaping state; off is NOT shaping-disabled reference','statuses':{m:(r or {}).get('status','Not tested') for m,r in rr.items()},'quiet_rtt':{m:(r or {}).get('quiet_rtt') for m,r in rr.items()},'cpu':{m:{'daemon_cpu_seconds':(r or {}).get('daemon_cpu_seconds'),'driver_cpu_seconds':(r or {}).get('driver_cpu_seconds'),'elapsed_seconds':(r or {}).get('elapsed_seconds')} for m,r in rr.items()}}
 for mode in ['fast','protected']:
  out[mode+'_minus_off_ms']={k:rt(rr[mode],k)-rt(rr['off'],k) if rt(rr[mode],k) is not None and rt(rr['off'],k) is not None else None for k in ['p50_ms','p95_ms','p99_ms','max_ms']}
 comparisons.append(out)
a.output.with_name('matched-comparisons.json').write_text(json.dumps({'comparisons':comparisons,'limitations':['30 echoes per cell: p99 approximates max; no tail confidence claim','difference of independently sampled percentiles, not per-packet paired RTT','CPU includes setup/API verification, not isolated steady traffic or a physical host-core estimate']},indent=2)+'\n')
