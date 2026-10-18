#!/usr/bin/python3
"""Unprivileged typed client. No nft/sudo/subprocess or renderer command bridge."""
import json,socket,sys,uuid

def call(op='list',**q):
 with socket.socket(socket.AF_UNIX)as s:
  s.settimeout(5);s.connect('/run/flowgate-api/daemon.sock');s.sendall((json.dumps(dict(version=1,operation=op,**q))+'\n').encode());f=s.makefile('rb');r=json.loads(f.readline())
  if r.get('error'):raise SystemExit(f"{r.get('error_code')}: {r['error']}; refresh status, no automatic replay")
  return r
op=sys.argv[1]if len(sys.argv)==2 else 'status'
if len(sys.argv)>2 or op not in ['status','stop','incoming','both']:raise SystemExit('usage: flowgate-control [status|stop|incoming|both]')
r=call()
if op!='status':
 fields=dict(generation=r['generation'],protection_id=r['protection']['id'])
 if op=='stop':r=call('protection-stop',**fields)
 else:r=call('protection-start',profile=op,request_id=uuid.uuid4().hex,**fields)
print(json.dumps({k:r.get(k)for k in ['generation','protection','enforcement','traffic_monitor','permissions']},indent=2))
