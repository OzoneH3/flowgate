#!/usr/bin/env python3
"""Refresh the reviewed IANA special-purpose snapshot; no runtime HTTP/geo dependency.
Run from repository root, review the generated diff, then run identity/zone tests.
All downloads are kept under .workspace/address-registry/.
"""
import argparse, csv, datetime, hashlib, io, ipaddress, json, pathlib, urllib.request, xml.etree.ElementTree as ET
p=argparse.ArgumentParser();p.add_argument('--output',default='internal/identity/data/iana-special.json');a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1];cache=root/'.workspace/address-registry';cache.mkdir(parents=True,exist_ok=True)
local={'10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','::1/128','fc00::/7','fe80::/10'}
records=[];sources=[];combined=hashlib.sha256()
for family in ('ipv4','ipv6'):
 name=f'iana-{family}-special-registry';base=f'https://www.iana.org/assignments/{name}/'
 url=base+name+'-1.csv'
 def get(url):
  with urllib.request.urlopen(url,timeout=25) as r:
   b=r.read(1024*1024+1)
  if len(b)>1024*1024:raise ValueError('registry exceeds 1 MiB')
  return b
 raw=get(url);(cache/(name+'.csv')).write_bytes(raw);combined.update(raw)
 xml=get(base+name+'.xml');(cache/(name+'.xml')).write_bytes(xml)
 updated=ET.fromstring(xml).find('{http://www.iana.org/assignments}updated').text
 sources.append(dict(url=url,sha256=hashlib.sha256(raw).hexdigest(),updated=updated))
 for row in csv.DictReader(io.StringIO(raw.decode('utf-8-sig'))):
  for part in row['Address Block'].split(','):
   prefix=str(ipaddress.ip_network(part.split('[')[0].strip()))
   records.append(dict(prefix=prefix,name=row['Name'],global_reachable=row['Globally Reachable'].strip().startswith('True'),local=prefix in local))
if not local.issubset({x['prefix']for x in records}):raise ValueError('review local-scope registry changes')
records.sort(key=lambda x:(ipaddress.ip_network(x['prefix']).version,int(ipaddress.ip_network(x['prefix']).network_address),ipaddress.ip_network(x['prefix']).prefixlen))
out=dict(schema=1,version='iana-special-'+combined.hexdigest()[:16],retrieved=str(datetime.date.today()),sources=sources,records=records)
output=(root/a.output).resolve()
if not output.is_relative_to(root):raise ValueError('output must stay in workspace')
output.write_text(json.dumps(out,indent=2)+'\n');print(out['version'],len(records),'records')
