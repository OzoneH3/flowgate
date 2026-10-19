#!/usr/bin/env python3
"""Build a visible review-only preset from incident evidence. Never saves rules."""
import argparse,datetime,hashlib,ipaddress,json,pathlib
ZERO='0001-01-01T00:00:00Z'
def dns_servers(text):
 result=set()
 for line in text.splitlines():
  line=line.strip()
  if line.startswith('DNS Servers:'):
   for token in line.split(':',1)[1].split():
    try:
     if '%'in token:raise ValueError('Scoped DNS interface requires separate supported review')
     address=ipaddress.ip_address(token)
     if address.is_unspecified or address.is_multicast:raise ValueError('DNS address is not a unicast endpoint')
     result.add(str(address))
    except ValueError:raise ValueError('Unrecognized configured DNS address '+token)
 return sorted(result)
def proposal(process,servers,existing):
 a=process.get('application',{})
 if type(process.get('pid'))is not int or process['pid']<=0 or type(process.get('uid'))is not int or process['uid']<0 or process.get('executable')!=a.get('executable'):
  raise ValueError('Missing live process/principal/executable binding')
 if a.get('kind')!='native'or not all(a.get(k)for k in ['key','revision','executable'])or process.get('executable_revision')!=a['revision']or not all(process.get(k)for k in ['start_ticks','netns','mountns','boot_id']):
  raise ValueError('No complete authoritative live native executable binding; no preset target guessed')
 if not any(line.rsplit(':',1)[-1].rstrip('/').endswith('/systemd-resolved.service')for line in process.get('cgroup','').splitlines()):
  raise ValueError('Evidence is not the observed resolved service; no service-name authorization')
 items=[]
 for address in sorted(set(str(ipaddress.ip_address(s))for s in servers)):
  ip=ipaddress.ip_address(address)
  if '%'in address or ip.is_unspecified or ip.is_multicast:raise ValueError('Unsupported DNS peer')
  for protocol in ['udp','tcp']:
   f={'application':a['key'],'revision':a['revision'],'uid':process['uid'],'direction':'outgoing','protocol':protocol,'remote_address':address,'remote_port':53,'local_port':0}
   key=hashlib.sha256(json.dumps(f,sort_keys=True).encode()).hexdigest()[:32]
   matches=[r for r in existing if all(r.get('filter',{}).get(k,0 if k.endswith('_port')else None)==v for k,v in f.items())and not r.get('filter',{}).get('network_zone')and not r.get('filter',{}).get('process')]
   items.append({'reason':'Configured DNS upstream; TCP fallback and UDP queries. Not incoming permission and not a VPN/systemd exemption.','disposition':'preserve_existing_review_only'if matches else 'proposed_not_saved','existing_rule_ids':[r['id']for r in matches],
    'candidate_rule':{'schema':2,'id':'essential-dns-'+key,'version':1,'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'disabled':False,'action':'allow','priority':100,'executable':a['executable'],'expires':ZERO,'filter':f}})
 return {'preset':'Essential system networking — observed host DNS','version':1,'review_only':True,'rules_saved':0,'target_scope':'application','network_scope':'Any network, constrained to each exact configured DNS IP and port53','identity':process,
  'items':items,'activation':'Keep monitoring. Review each candidate, revalidate live identity and apply through identity-bound preview/save with existing administrator authority; never import this file as authority.',
  'updates':'Executable revision or DNS-server changes require fresh review. Existing rules, including disabled/user-edited rules, are never overwritten or enabled. No automatic startup/update application.',
  'not_included':['UID0 wildcard','systemd or NetworkManager wildcard','unsolicited incoming traffic','Tailscale blanket exemption','public fallback DNS not currently configured','application outbound Internet access']}
def main():
 p=argparse.ArgumentParser();p.add_argument('evidence',type=pathlib.Path);a=p.parse_args()
 services=json.loads((a.evidence/'services.json').read_text());entry=services['systemd-resolved.service']['process']
 if not entry or entry.get('returncode')!=0:raise SystemExit('Resolved identity evidence unavailable; no rules proposed')
 process=json.loads(entry['stdout']);dns=json.loads((a.evidence/'dns.json').read_text())
 if dns.get('returncode')!=0:raise SystemExit('Configured DNS unavailable; no rules proposed')
 existing=json.loads((a.evidence/'rules.db.json').read_text())
 if not isinstance(existing,list):raise SystemExit('Stored inventory unavailable; inspect before proposing rules')
 print(json.dumps(proposal(process,dns_servers(dns['stdout']),existing),indent=2))
if __name__=='__main__':main()
