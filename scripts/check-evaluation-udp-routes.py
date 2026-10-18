#!/usr/bin/env python3
"""Focused setup regression; run with scripts/lab.sh, never in the host netns."""
import os,subprocess,time
from evaluation_udp_continuity import route_snapshot,settle_ipv6
assert os.environ['FLOWGATE_PARENT_NETNS']!=os.readlink('/proc/self/ns/net')
def wait(fn):
 end=time.monotonic()+8
 while time.monotonic()<end:
  if fn():return
  time.sleep(.05)
 raise AssertionError('IPv6 DAD did not complete')
def cmd(*args):subprocess.run(args,check=True)
try:
 cmd('ip','link','add','fghost','type','veth','peer','name','fgpeer')
 for dev in ['fghost','fgpeer']:cmd('ip','link','set',dev,'up')
 cmd('ip','addr','add','10.79.0.1/24','dev','fghost')
 cmd('ip','-6','addr','add','fd79::1/64','dev','fghost','nodad')
 settle_ipv6(wait);before=route_snapshot();time.sleep(2)
 assert before==route_snapshot(),'route baseline changed after setup settled'
 # A genuine route change must still fail comparison: no route fields ignored.
 cmd('ip','route','add','198.51.100.0/24','dev','fghost')
 assert before!=route_snapshot(),'route comparison hid an actual route addition'
 print('PASS IPv6 setup/DAD settles before baseline; stable route snapshot; real route change detected')
finally:cmd('ip','link','delete','fghost')
