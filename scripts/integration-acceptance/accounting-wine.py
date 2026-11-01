# Successful syscall-return payload accounting, not shaping or delivery claims.
configure([],enabled=False)
def until(fn,seconds=45):
 end=time.monotonic()+seconds
 while time.monotonic()<end:
  v=fn()
  if v:return v
  time.sleep(.2)
 raise AssertionError('Wine accounting timeout')
pathlib.Path('/proc/sys/kernel/bpf_stats_enabled').write_text('0')
s=api();api('traffic-start',generation=GEN,collector_generation=s['traffic_monitor'].get('generation',''));until(lambda:api()['traffic_monitor']['state']=='active')
record('wine-fixture',cases={n:{'pid':c['pid'],'application':c['application']} for n,c in wine_cases.items()})
for c in wine_cases.values():c['go'].touch()
for c in wine_cases.values():until(lambda c=c:'PROGRESS 1 125' in c['trace'].read_text())
time.sleep(3)
def kernel_counts():
 tool=str(P/'bpftool')
 maps=json.loads(subprocess.check_output([tool,'-j','map','show'],text=True));out=[]
 for m in maps:
  if m.get('name')=='counters' and m.get('bytes_key')==8 and m.get('bytes_value')==16:
   out.append(dict(map=m,rows=json.loads(subprocess.check_output([tool,'-j','map','dump','id',str(m['id'])],text=True))))
 return dict(captured_wall_ns=time.time_ns(),bpf_stats_enabled=pathlib.Path('/proc/sys/kernel/bpf_stats_enabled').read_text().strip(),maps=out,programs=json.loads(subprocess.check_output([tool,'-j','prog','show'],text=True)))
def snap():
 s=api();return {'activity':s['activity'],'usage':api('observed-usage')['observed_usage'],'gate':s.get('socket_authorization'),'monitor':s['traffic_monitor'],'events':s.get('events'), 'runtime_checks':s.get('runtime_checks'),'kernel_counts':kernel_counts()}
def value(s,n):return sum(int(e['uploaded']) for e in s['usage']['entries'] if e['source']=='udp-api-reported' and e['uid']==0 and e['application']['key']==wine_cases[n]['application']['key'])
phases={}
for n,c in wine_cases.items():
 before=snap();c['measure'].touch();until(lambda c=c:'SATURATION_SENT' in c['trace'].read_text());time.sleep(3);after=snap()
 # Require two distinct collector observations with stable conserved totals.
 previous=after
 for _ in range(40):
  time.sleep(.2);after=snap()
  oldns=(previous['activity'].get('udp') or {}).get('sample_ns',0);newns=(after['activity'].get('udp') or {}).get('sample_ns',0)
  total=lambda x:sum(int(e['uploaded']) for e in x['usage']['entries']+x['usage'].get('unattributed',[]) if e['source']=='udp-api-reported')
  if newns>oldns and total(after)==total(previous):break
  if newns>oldns:previous=after
 else:raise AssertionError('no stable post-send collector window')
 phases[n]=(before,after)
 record('wine-measured-window',name=n,before=before,after=after,fast_delta=(after['gate'] or {}).get('fast_packets',0)-(before['gate'] or {}).get('fast_packets',0),misses_delta=after['monitor']['missed_operations']-before['monitor']['missed_operations'],gaps_before=before['usage']['gaps'],gaps_after=after['usage']['gaps'])
for c in wine_cases.values():until(lambda c=c:'SATURATION_DONE' in c['trace'].read_text())
import wine_trace
linux=wine_trace.parse(list(R.glob('*-linux.txt')));record('wine-linux-returns',**linux)
for n,c in wine_cases.items():
 until(lambda c=c:'SATURATION_DONE' in c['trace'].read_text());lines=c['trace'].read_text().splitlines();stats=[list(map(int,l.split()[1:])) for l in lines if l.startswith('STATS ')];warm=[list(map(int,l.split()[1:])) for l in lines if l.startswith('WARMSTATS ')];errors=[list(map(int,l.split()[1:])) for l in lines if l.startswith('WSAERROR ')]
 before,after=phases[n];winsock_expected=(sum(x[2] for x in stats)-sum(x[1] for x in warm))*256;expected_window=linux['apps'][n]['successful_return_bytes'];actual=value(after,n)-value(before,n)
 unattributed=lambda s:sum(int(e['uploaded']) for e in s['usage'].get('unattributed',[]) if e['source']=='udp-api-reported')
 other_delta=sum(value(after,other)-value(before,other) for other in wine_cases if other!=n)
 results['wine-'+n]={'two_socket_stats_present':len(stats)==len(warm)==2,'linux_trace_complete':not linux['unsupported'] and linux['apps'][n]['successful_calls']+linux['apps'][n]['failed_calls']>=500,'successful_calls':all(x[2]==375 for x in stats) if n!='bBeta' else sum(x[2]+x[3] for x in stats)==750,'exact_verified_app_usage':actual==expected_window,'no_cross_application_credit':other_delta==0,'conservation':actual+unattributed(after)-unattributed(before)==expected_window}
 record('wine-accounting-result',name=n,application=c['application'],send_stats=stats,warm_stats=warm,wsa_errors=errors,successful_return_bytes_total=sum(x[2] for x in stats)*256,winsock_reported_window_bytes=winsock_expected,linux_syscalls=linux['apps'][n],measured_expected=expected_window,measured_app_bytes=actual,unattributed_delta=unattributed(after)-unattributed(before),other_app_delta=other_delta,checks=results['wine-'+n])
# Prefix/app identities must stay disjoint; separate Deny is never inferred from
# a peer app's Allow. Receiver output is retained independently of API bytes.
results['wine-separation']={'four_distinct_verified_keys':len({c['application']['key'] for c in wine_cases.values()})==4}
rx=peerop('stats');results['wine-separation']['denied_prefix_app_no_delivery']=sum(rx.get('bBeta-'+str(i),{}).get('received',0) for i in (0,1))==0
record('wine-receiver',receiver=rx)
record('wine-coverage',scope='real Win64 game-like two-socket streams; UID0 guest; receiver and successful-call counts separate; no Wine shaping')
s=api();api('traffic-stop',generation=GEN,collector_generation=s['traffic_monitor']['generation'])
