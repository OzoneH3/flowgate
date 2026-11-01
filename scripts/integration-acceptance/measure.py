"""Guest-side measurements. No policy or product implementation changes."""
class MeasurementInconclusive(Exception):pass

def htb_leaf(rows):
 return [r for r in rows if r.get('class')=='htb' and r.get('handle','').split(':')[-1] not in ('fff0','fff1','fffe') and r.get('leaf')]
def klass(rows,minor):
 return next((r for r in rows if r.get('class')=='htb' and r.get('handle','').split(':')[-1]==minor),{})
def stat(r,k):return r.get('stats',{}).get(k,0)
def delta(before,after,k):
 if (before.get('handle')!=after.get('handle') or k!='backlog' and stat(after,k)<stat(before,k)):
  raise MeasurementInconclusive('counter reset or changed class handle: '+str((before.get('handle'),after.get('handle'),k,stat(before,k),stat(after,k))))
 return stat(after,k)-stat(before,k)
def snapshot_delta(before,after):
 return {k:delta(before,after,k) for k in ['bytes','packets','drops','overlimits','backlog']}
def queue_drop(qdiscs,handle):
 # Count only the leaf fq_codel. HTB and child counters may describe the same drop.
 return sum(q.get('drops',q.get('stats',{}).get('drops',0)) for q in qdiscs if q.get('parent')==handle)
def payload_bound(rate,seconds,burst,backlog,skb,recvq=0):
 return rate*max(0,seconds)/8+burst+backlog+skb+recvq
def charged_bound(rate,seconds,burst,cburst):return rate*max(0,seconds)/8+burst+cburst+65536
