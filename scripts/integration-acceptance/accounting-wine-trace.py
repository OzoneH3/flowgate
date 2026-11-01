"""Parse bounded fixture syscall traces; fixed 256B single-message sends only.
Unsupported or incomplete trace forms remain explicit, never counted as success.
"""
import re,collections

def parse(paths):
 pending={};events=[];unsupported=[]
 pattern=re.compile(r'(aAlpha|aBeta|bAlpha|bBeta)\|(\d+)\|(\d+)\|')
 for path in paths:
  for line in path.read_text(errors='replace').splitlines():
   parts=line.split(None,2)
   if len(parts)<3:continue
   tid=parts[0];body=parts[2]
   if '<... ' in body and ' resumed>' in body:
    saved=pending.pop((str(path),tid),None)
    if saved is None:continue
    event=saved
   else:
    m=pattern.search(body)
    if not m or '<UDP' not in body:continue
    event={'app':m[1],'socket':int(m[2]),'seq':int(m[3]),'call':body.split('(',1)[0],'tid':tid}
    if 'sendmmsg' in event['call']:unsupported.append({'reason':'multi-message syscall requires explicit msg_len parsing','line':line});continue
    if '<unfinished ...>' in body:pending[(str(path),tid)]=event;continue
   ret=re.search(r'\)\s*=\s*(-?\d+)(?:\s+([A-Z][A-Z0-9_]+))?',body)
   if ret is None:unsupported.append({'reason':'return unavailable','line':line});continue
   event.update(return_bytes=int(ret[1]),errno=ret[2],trace=path.name);events.append(event)
 unsupported.extend({'reason':'unfinished syscall at trace end','event':v} for v in pending.values())
 out={}
 for name in ['aAlpha','aBeta','bAlpha','bBeta']:
  rows=[e for e in events if e['app']==name and 125<=e['seq']<375]
  out[name]={'successful_return_bytes':sum(e['return_bytes'] for e in rows if e['return_bytes']>0),'successful_calls':sum(e['return_bytes']>0 for e in rows),'failed_calls':sum(e['return_bytes']<0 for e in rows),'errno_counts':dict(collections.Counter(e['errno'] for e in rows if e['return_bytes']<0)),'events':rows}
 return {'apps':out,'unsupported':unsupported}
