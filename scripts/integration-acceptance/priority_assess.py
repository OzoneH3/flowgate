"""Frozen SPEC v2.1 noise-referenced priority effect assessment."""
def assess(shares,direction):
 key='ul_payload_mbps' if direction=='upload' else 'dl_payload_mbps'
 phases=('A-low','A-high','normal-control','A-low-repeat')
 mean={p:{a:sum(x[key][a] for x in shares[p])/len(shares[p]) for a in ('A','B')} for p in phases}
 noise=max(abs(shares[p][0][key][a]-shares[p][1][key][a]) for p in phases for a in ('A','B'))
 control=abs(mean['normal-control']['A']-mean['normal-control']['B'])
 drift=abs(mean['A-low']['A']-mean['A-low-repeat']['A'])
 aggregate=sum(sum(v.values()) for v in mean.values())/len(phases)
 dlow=mean['A-low']['B']-mean['A-low']['A'];dhigh=mean['A-high']['A']-mean['A-high']['B']
 sa=mean['A-high']['A']-mean['A-low']['A'];sb=mean['A-low']['B']-mean['A-high']['B']
 saturated=all(x['saturation'][direction] for p in phases for x in shares[p])
 if not saturated:state,reason='Inconclusive','budget not saturated'
 elif 2*noise>=.25*aggregate:state,reason='Inconclusive','within-phase noise too large'
 elif drift>2*noise+.05*aggregate:state,reason='Inconclusive','drift'
 elif dlow>control+2*noise and dhigh>control+2*noise and sa>2*noise and sb>2*noise:state,reason='Pass','swap effect above control asymmetry and noise'
 else:state,reason='Fail','ineffective or reversed priority effect in saturated stable windows'
 return dict(result=state,reason=reason,means=mean,N=noise,C=control,D=drift,aggregate=aggregate,delta_A_low=dlow,delta_A_high=dhigh,S_A=sa,S_B=sb,saturated=saturated)

def assess_game(normal, high):
 """E3: phase repeatability excludes the between-phase effect itself."""
 if len(normal)!=3 or len(high)!=3:
  return {'result':'Not tested','reason':'three repeats per phase required'}
 n=[x['echo_rtt']['p95_ms'] for x in normal];h=[x['echo_rtt']['p95_ms'] for x in high]
 benefit=sum(n)/3-sum(h)/3;spread=max(max(n)-min(n),max(h)-min(h))
 if any(x['loss']['unclassified']>0 for x in high):state='Fail'
 elif not all(x['saturated'] for x in normal+high) or spread>abs(benefit):state='Inconclusive'
 else:state='Pass' if benefit>=0 else 'Fail'
 return {'result':state,'benefit_ms':benefit,'within_phase_spread_ms':spread}
