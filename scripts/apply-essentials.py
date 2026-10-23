#!/usr/bin/env python3
"""Apply the reviewed essentials-only preset through the authenticated primary API.

Runs as the administrator UID (no sudo). Excludes the work VPN interface, never
selects Tailscale transport/discovery, refuses anything outside the reviewed
proposal, applies exactly once and reconciles a lost reply by receipt (no replay).
Never starts protection. Usage: scripts/apply-essentials.py [--dry-run] [--services]
"""
import argparse,json,pathlib,socket,sys,time

SOCK='/run/flowgate-api/daemon.sock'
OPTIONS={'service_assistance':False,'tailscale':False,'tailscale_incoming':False,'tailscale_http':False,'discovery':False,'excluded_interfaces':['ppp0']}
RESOLVED,TIMESYNCD='/usr/lib/systemd/systemd-resolved','/usr/lib/systemd/systemd-timesyncd'
# Reviewed semantic proposal (docs/ESSENTIAL-NETWORKING.md), work VPN ppp0 excluded.
UPSTREAM={('172.30.42.128','enp7s0'),('172.30.42.250','enp7s0'),('100.100.100.100','tailscale0'),('fd7a:115c:a1e0::53','tailscale0')}
NTP={'162.159.200.123'}
DHCP={('enp7s0',68,67),('enp7s0',546,547)}

def api(op,timeout=25,**q):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(timeout);s.connect(SOCK)
  s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode())
  line=s.makefile('rb').readline()
  if not line:raise ConnectionError('no response')
  return json.loads(line)

def key(r):
 """Reviewed semantic identity of one proposed/stored preset rule."""
 f=r['filter'];comp=(r.get('preset')or{}).get('component')or r.get('component')
 return (comp,r.get('executable')or'ALL',f.get('direction'),f.get('protocol'),f.get('remote_address'),f.get('remote_port')or 0,f.get('local_address')or'',f.get('local_port')or 0,f.get('interface_name')or'',f.get('uid')or 0,bool(f.get('all_programs')),(f.get('peer_service')or{}).get('uid'))

def reviewed():
 out=set()
 if OPTIONS['service_assistance']:
  for addr,ifn in UPSTREAM:
   for proto in ('udp','tcp'):out.add(('dns',RESOLVED,'outgoing',proto,addr,53,'',0,ifn,974,False,None))
  for addr in NTP:out.add(('time',TIMESYNCD,'outgoing','udp',addr,123,'',0,'',973,False,None))
 for ifn,lp,rp in DHCP:out.add(('dhcp','ALL','outgoing','udp','*',rp,'',lp,ifn,0,True,None))
 return out

def check_preview(v,identity=None):
 """Return problems; empty means the preview is exactly within the reviewed proposal."""
 problems=[];allowed=reviewed();seen=set()
 for r in v.get('rules',[]):
  k=key(r)
  if k not in allowed:problems.append(('outside reviewed proposal',k))
  if k in seen:problems.append(('duplicate',k))
  seen.add(k)
  if (r.get('filter')or{}).get('interface_name')=='ppp0' or 'tailscaled'in(r.get('executable')or''):problems.append(('excluded scope proposed',k))
  if identity and r.get('executable')in identity:
   want=identity[r['executable']];f=r['filter']
   if (f.get('application'),f.get('revision'))!=want:problems.append(('service identity changed since review',r['executable']))
 if v.get('preserved_rule_ids'):problems.append(('existing rules overlap; review',v['preserved_rule_ids']))
 other=[i for i in v.get('issues',[])if not i.startswith('Excluded by review, not proposed: ppp0')]
 if other:problems.append(('preview issues',other))
 if not any(i.startswith('Excluded by review, not proposed: ppp0')for i in v.get('issues',[])):problems.append(('ppp0 exclusion not confirmed by daemon',None))
 missing=allowed-seen
 return problems,sorted(missing,key=str)

def verify_applied(before_rules, after_rules, proposed):
 """Apply is additive: old unreviewed records must survive byte-for-byte."""
 before={r['id']:r for r in before_rules};after={r['id']:r for r in after_rules};plan={r['id']:r for r in proposed}
 if set(after)!=set(before)|set(plan):raise RuntimeError('stored inventory differs from additive reviewed apply')
 for rid,r in before.items():
  if rid not in plan and after[rid]!=r:raise RuntimeError('unreviewed rule changed: '+rid)
 for rid,r in plan.items():
  if any(after[rid].get(k)!=r.get(k) for k in ('filter','executable','action','schema')):raise RuntimeError('stored scope/action differs: '+rid)
  if any((after[rid].get('preset')or{}).get(k)!=(r.get('preset')or{}).get(k) for k in ('name','component')):raise RuntimeError('stored preset differs: '+rid)

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--dry-run',action='store_true');ap.add_argument('--services',action='store_true',help='also review upstream DNS/time assistance; localhost omitted');ap.add_argument('--evidence',default=str(pathlib.Path(__file__).resolve().parents[1]/'.workspace/essential-apply'))
 a=ap.parse_args();OPTIONS['service_assistance']=a.services;ev=pathlib.Path(a.evidence);ev.mkdir(parents=True,exist_ok=True)
 before=api('list')
 if 'essential-optional-services-v1' not in before.get('capabilities',[]):raise SystemExit('Matching backend required for DHCP-only defaults. Nothing applied.')
 if 'essential-interface-exclusion-v1'not in before.get('capabilities',[]):raise SystemExit('Installed daemon does not support reviewed interface exclusion; install the matching monitoring update first. Nothing applied.')
 if before['protection']['state']!='stopped'or before['enforcement']['state']!='stopped':raise SystemExit('Protection is not stopped; refusing.')
 if before['permissions'].get('role')!='administrator'or not before['permissions'].get('can_manage_rules'):raise SystemExit('Not the authorized administrator endpoint.')
 user_before=[r for r in before.get('rules')or[]if not r.get('preset')]
 (ev/'list-before.json').write_text(json.dumps(before,indent=1))
 # Service identities seen in the reviewed host preview (application key, revision).
 identity=None
 ref=pathlib.Path(__file__).resolve().parents[1]/'.workspace/essential-host/result-ui-preview.json'
 if ref.exists():
  identity={}
  for r in json.loads(ref.read_text())['direct']['rules']:
   if r.get('executable'):identity[r['executable']]=(r['filter'].get('application'),r['filter'].get('revision'))
 v=api('essential-preview',generation=before['generation'],essential_options=OPTIONS)
 if v.get('error'):raise SystemExit('Preview failed, nothing saved: '+json.dumps(v.get('error_code')or v['error']))
 v=v['essential_preview'];(ev/'preview.json').write_text(json.dumps(v,indent=1))
 problems,missing=check_preview(v,identity)
 print('PREVIEW',len(v['rules']),'rules; options',json.dumps(v['options']))
 for i in v['issues']:print('  issue:',i)
 if missing:print('  reviewed entries not currently proposed (narrower, not added):',missing)
 if problems:raise SystemExit('Preview differs from the reviewed proposal; renewed review required, nothing applied: '+json.dumps(problems,default=str))
 if a.dry_run:print('DRY RUN: preview matches the reviewed proposal; nothing applied');return
 token=v['token']
 try:
  r=api('essential-apply',generation=before['generation'],preview_token=token,essential_options=OPTIONS)
 except (OSError,ValueError,ConnectionError) as e:
  print('Apply response lost (%s); reconciling by receipt, not replaying'%e)
  r=api('essential-status',generation=before['generation'],preview_token=token)
  if r.get('error'):raise SystemExit('Outcome unknown; inspect rules/status before any retry: '+json.dumps(r))
 if r.get('error'):raise SystemExit('Apply refused, nothing saved: '+json.dumps(r.get('error_code')or r['error']))
 receipt=r.get('essential_receipt')or(r.get('essential_status')or{}).get('receipt')
 (ev/'receipt.json').write_text(json.dumps(r,indent=1))
 after=api('list');(ev/'list-after.json').write_text(json.dumps(after,indent=1))
 preset=[x for x in after.get('rules')or[]if x.get('preset')];user_after=[x for x in after.get('rules')or[]if not x.get('preset')]
 assert user_after==user_before,'existing user rules changed'
 verify_applied(before.get('rules')or[],after.get('rules')or[],v['rules'])
 states=after.get('rule_states')or{}
 inactive=[x['id']for x in preset if(states.get(x['id'])or{}).get('state','active')!='active']
 assert after['protection']['state']=='stopped'and after['enforcement']['state']=='stopped'
 assert after['generation']==before['generation']
 print('APPLIED',len(preset),'essential rules; user rules unchanged',[x['id']for x in user_after],'; protection stopped')
 if inactive:print('WARNING inactive after apply:',inactive)
 if receipt:print('receipt options',json.dumps(receipt.get('options')))

if __name__=='__main__':main()
