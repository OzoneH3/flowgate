#!/usr/bin/env python3
"""Enumerate the extended capability grid without inventing execution coverage.
Core is a COMPOSITE UDP+TCP workload. It does not pass every protocol-specific
row below. Grid rows remain Not tested until independently matched evidence exists.
"""
import itertools,json,argparse,pathlib

def rows():
 for mode,limits,priority,budget,scope,runtime,protocol,family,direction in itertools.product(
  ['fast','protected','off'],['none','ul','dl','both'],['low','normal','high'],['none','ul','dl','both'],['all','local','internet'],['native','wine'],['tcp','udp'],[4,6],['outgoing','incoming']):
  fast=mode=='fast' and protocol=='udp' and family==4 and direction=='outgoing'
  native=runtime=='native';ul=limits in ('ul','both');dl=limits in ('dl','both')
  yield {'id':'-'.join(map(str,[mode,limits,priority,budget,scope,runtime,protocol,family,direction])),
   'axes':dict(mode=mode,limits=limits,priority=priority,budget=budget,scope=scope,runtime=runtime,protocol=protocol,family=family,direction=direction),
   'expected':{'authorization':'protection off' if mode=='off' else 'socket-destination lifetime grant if fresh proof + explicit Allow' if fast else 'ordinary protected path',
    'fast':'eligible conditional on full proof/outdev' if fast else 'Unsupported (ordinary protection remains)',
    'ul':'not configured' if not ul else 'Unsupported per Wine application' if not native else 'conditional: verified connected native socket, non-GSO UDP only; shared app cap',
    'dl':'not configured' if not dl else 'Unsupported per Wine application' if not native else 'Unsupported per-app UDP DL (connected aggregate default only under budget)' if protocol=='udp' else 'conditional: established native TCP + verified binding',
    'priority':'dormant without that direction budget; no packet-verdict authority' if budget=='none' else 'Unsupported per Wine application' if not native else 'experimental best effort in supported shaping scope; no minimum/fairness promise',
    'scope':'All combined ceiling; specific leaf is conjunctive; Unknown runtime classification uses All only; explicit zone Normal overrides inheritance'},
   'observed_status':'Not tested','core_link':'-'.join([mode,limits,priority,budget]) if scope=='all' else None,
   'core_link_warning':'composite workload evidence only; not protocol-specific proof',
   'socket_shape_omissions':['wildcard/unconnected budget match','fragments/extensions/VLAN','NAT/tproxy/forwarded/multicast','physical interface coverage']}

if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 assert a.output.resolve().is_relative_to(pathlib.Path(__file__).resolve().parents[3]),'output must remain in checkout/workspace'
 with a.output.open('w') as f:
  n=0
  for r in rows():f.write(json.dumps(r)+'\n');n+=1
 print(n)
