#!/usr/bin/env python3
"""Pre-registered causal rule; incomplete trace is never ordering evidence."""
import argparse,json,pathlib
p=argparse.ArgumentParser();p.add_argument('run',type=pathlib.Path);a=p.parse_args();e=a.run/'evidence';t=json.loads((e/'handoff-trace.json').read_text());records=json.loads((e/'records.json').read_text());clock=next(x for x in records if x['kind']=='clock-pair');offset=clock['boottime_ns']-clock['monotonic_ns'];rows=[]
for r in records:
 if r['kind']!='startup-order':continue
 sock=r['socket']['sockets'][0];port=sock['port'];cookie=int.from_bytes(bytes.fromhex(sock['cookie']),'little')
 packets=[x for x in t['Events'] if x['Kind']=='packet' and f':{port}|' in x['Flow']];byseq={x['Seq']:x for x in packets};ends={x['ID']:x for x in t['Events'] if x['Kind']=='verdict-end' and f':{port}|' in x['Flow']};overtakes=[]
 for m,rm,_ in r['arrivals']:
  if m in byseq:continue
  for k,rk,_ in r['arrivals']:
   if k>=m or rm>=rk or k not in byseq:continue
   v=ends.get(byseq[k]['ID'])
   if v and v['Allowed'] and v['OK'] and v['BootNS']>rm+offset:overtakes.append({'fast_seq':m,'queued_seq':k,'fast_arrival_boot_ns':rm+offset,'queued_verdict_end_ns':v['BootNS']})
 grants=[x['BootNS'] for x in t['Events'] if x['Kind']=='grant-published' and x['ID']==cookie]
 rows.append({'tag':r['tag'],'port':port,'sent':r['sender']['sent'],'received':r['receiver']['received'],'reordered':r['receiver']['reordered'],'confirmed_overtakes':overtakes,'grant_after_start_ms':(min(grants)-r['start_ns']-offset)/1e6 if grants else None,'max_startup_delay_ms':r['receiver']['max_ms'],'gate':r.get('gate')})
control=next(x for x in records if x['kind']=='established-order-control');rx=control['receiver'];rx=list(rx.values()) if 'received' not in rx else [rx]
checks={'trace_complete':not t['Truncated'],'all_delivered':all(x['received']==x['sent']==125 for x in rows),'zero_reorder':all(x['reordered']==0 for x in rows),'zero_confirmed_overtakes':all(not x['confirmed_overtakes'] for x in rows),'established_all_delivered':sum(x['received'] for x in rx)==sum(x['sent'] for x in control['sender']),'established_zero_reorder':all(x['reordered']==0 for x in rx)}
result={'result':'Inconclusive' if t['Truncated'] else ('Pass' if all(checks.values()) else 'Fail'),'checks':checks,'clock_offset_ns':offset,'events':len(t['Events']),'cases':rows,'established':control};(a.run/'causal-assessment.json').write_text(json.dumps(result,indent=2));print(json.dumps({'result':result['result'],'checks':checks,'cases':len(rows),'overtakes':sum(len(x['confirmed_overtakes']) for x in rows),'grant_ms':[x['grant_after_start_ms'] for x in rows]},indent=2))
