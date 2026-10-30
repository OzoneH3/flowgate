#!/usr/bin/env python3
"""Report all offered packets, plus fixed elapsed-sequence windows chosen before testing."""
import json,pathlib,statistics,sys
root=pathlib.Path(sys.argv[1])
candidate=sys.argv[2] if len(sys.argv)>2 else 'candidate'
def load(mode,name):return json.loads((root/(candidate if mode=='candidate' else mode)/name).read_text())
def stats(v):
    v=sorted(v)
    return dict(count=len(v),median_ms=statistics.median(v) if v else None,p99_ms=v[min(len(v)-1,int(.99*len(v)))] if v else None,max_ms=max(v) if v else None)
results={m:load(m,'result.json') for m in ('off','candidate')}
rows={m:{(s,i):v for t,s,i,v in load(m,'wine-latency.json') if t=='SAT_ALPHA_A'} for m in results}
n=results['candidate']['datagrams_per_socket'];sockets=results['candidate']['sockets_per_app'];interval=results['candidate']['interval_ms']
report={'scope':'Sequential matched isolated workloads; sequence-paired differences include scheduling noise. Fixed 0-1s,1-5s,5s-end windows do not waive any losses or redefine connection startup. Prior failed endurance remains evidence.','flows':{}}
for sock in range(sockets):
    out={}
    for name,lo,hi in [('all',0,n),('first_second',0,min(n,1000//interval)),('seconds_1_to_5',1000//interval,min(n,5000//interval)),('after_5_seconds',5000//interval,n)]:
        expected={(sock,i) for i in range(lo,hi)};window={}
        for m in results:
            window[m]={'offered':len(expected),'missing':[i for s,i in sorted(expected-rows[m].keys())],'latency':stats([v for k,v in rows[m].items() if k in expected])}
        common=expected & rows['off'].keys() & rows['candidate'].keys()
        deltas={i:rows['candidate'][(s,i)]-rows['off'][(s,i)] for s,i in common}
        window['paired_difference']=stats(list(deltas.values()));window['paired_over_10ms']=[[i,v] for i,v in sorted(deltas.items()) if v>10]
        out[name]=window
    out['first_datagram_ms']={m:rows[m].get((sock,0)) for m in results};report['flows'][sock]=out
report['native']={m:results[m]['native'] for m in results}
report['cpu']={m:{r:load(m,r+'-cpu.json') for r in ('round1',)} for m in results}
(root/(candidate+'-paired-analysis.json')).write_text(json.dumps(report,indent=2)+'\n')
print('Paired comparison saved:',root/(candidate+'-paired-analysis.json'),'; all startup/steady losses and excursions retained')
