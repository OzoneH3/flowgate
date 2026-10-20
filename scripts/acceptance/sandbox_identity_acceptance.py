"""Sandbox (mount-namespace) executable identity for rules saved from ENDED
requests, imported only by the private lab (scripts/lab.sh, user+net ns).
Real disposable launches inside private mount namespaces (unshare -m) whose
/proc/PID/exe path is not valid in the daemon's namespace, real kernel
interception, API and receiver. Never the host daemon.
"""
import json,os,shutil,subprocess,time

def check(g):
 api,ask,wait,RUN,log,NATIVE=[g[k] for k in ('api','ask','wait','RUN','log','NATIVE')]
 generation=g['generation'];assert not api().get('rules')
 caps=api()['capabilities'];assert 'request-application-rule-v1' in caps and 'request-sandbox-identity-v1' in caps,caps
 BACK=RUN/'back';BACK.mkdir();APP=str(BACK/'app');shutil.copy2(NATIVE,APP)  # host-visible backing file
 SIB=RUN/'sib';SIB.mkdir();shutil.copy2(NATIVE,SIB/'app')
 with open(SIB/'app','ab') as fh:fh.write(b'\0sibling')                    # a different executable, same name
 M=RUN/'m';M.mkdir()   # empty in the daemon's namespace; a tmpfs only inside each sandbox
 launched=[];ports=iter(range(45500,45900,10));n=iter(range(1,100))
 def save_json(name,v):(RUN/name).write_text(json.dumps(v,indent=2)+'\n')
 def sandbox(backing=None,only=None):
  """New process in a NEW private mount namespace. backing: bind the host
  directory at a per-instance path visible only inside; only: copy the
  executable into the sandbox tmpfs (no host-visible backing file)."""
  tag='i%d'%next(n);inner='%s/%s'%(M,tag)
  if backing:setup='mkdir %s && mount --bind %s %s'%(inner,backing,inner)
  else:setup='mkdir %s && cp %s %s/app'%(inner,only,inner)
  script='mount -t tmpfs fgsb %s && %s && exec %s/app %d'%(M,setup,inner,next(ports))
  c=subprocess.Popen(['unshare','-m','--propagation','private','sh','-c',script],env=dict(os.environ,FLOWGATE_FIXTURE_TIMEOUT_SECONDS='10'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(RUN/'sandbox.log').open('a'),text=True)
  info=json.loads(c.stdout.readline());launched.append(c)
  assert os.readlink('/proc/%d/ns/mnt'%info['pid'])!=os.readlink('/proc/self/ns/mnt')
  exe=os.readlink('/proc/%d/exe'%info['pid']);assert exe==inner+'/app' and not os.path.exists(exe),exe  # invalid on the daemon side
  return c,info,exe
 def quit(c):
  if c.poll() is None:c.terminate();c.wait(5)
 def peer_count():
  p=RUN/'peer-received.log';return len(p.read_text().splitlines())if p.exists()else 0
 def events_for(pid):return [e for e in api().get('events',[]) if any(o['pid']==pid for o in e['attribution'].get('owners',[]))]
 def pending(pid):return next((e for e in events_for(pid) if e['state']=='awaiting-decision'),None)
 def event(id):return next((e for e in api().get('events',[]) if e['id']==id),None)
 fields=dict(address=False,port=False,protocol=False,process=False)
 rev=lambda:api()['network_zones']['revision']
 def rr(op,e,action,**kw):
  q=dict(generation=generation,id=e['id'],action=action,scope='persistent',network_zone='any',zone_revision=rev(),remember=kw.pop('remember',fields));q.update(kw)
  return api(op,**q)
 def daemon_refs():
  # Open references any FlowGate process holds to sandbox executables.
  out=[];BIN=g['BIN']
  for p in os.listdir('/proc'):
   if not p.isdigit():continue
   try:
    if os.readlink('/proc/%s/exe'%p)!=BIN:continue
    for fd in os.listdir('/proc/%s/fd'%p):
     t=os.readlink('/proc/%s/fd/%s'%(p,fd))
     if t.startswith(str(M)) or t.startswith(str(BACK)) or t.startswith(str(SIB)) or t.endswith('/app') or t.endswith('/app (deleted)'):out.append((p,fd,t))
   except OSError:pass
  return out
 def prompt_then_exit(c,info,tag):
  ask(c,'send',protocol='tcp',timeout_ms=8000)
  e=wait(lambda:pending(info['pid']));save_json(tag+'-pending.json',e)
  src=wait(lambda:(lambda x:x and x.get('request_rule',{}).get('executable_identity') not in (None,'pending') and x)(event(e['id'])))['request_rule']
  quit(c)  # the requester exits before any review
  wait(lambda:not os.path.exists('/proc/%d'%info['pid']))
  return e,src
 before=peer_count()
 # 1. Prompt from a sandboxed instance, exit before review.
 c,info,exe=sandbox(backing=BACK)
 old,src=prompt_then_exit(c,info,'sandbox')
 app=old['attribution']['application']
 assert app['executable']==exe and app.get('host_executable')==APP,app
 assert src['executable_identity']=='verified',src
 owner=old['attribution']['owners'][0];assert owner['mountns']!=os.readlink('/proc/self/ns/mnt')
 refs=daemon_refs();assert not refs,('retained executable reference after digest',refs)
 log('PASS sandboxed instance PID %d (mount ns %s, ns-local %s) prompted; evidence verified via host backing %s; no open executable reference after digest'%(info['pid'],owner['mountns'],exe,APP))
 # 2. Remember -> Allow from the ENDED request (was: "process ran in another mount namespace").
 refused=rr('request-rule-preview',old,'allow',remember=dict(fields,process=True));assert refused.get('error_code')=='process_scope_unavailable',refused
 p=rr('request-rule-preview',old,'allow');save_json('sandbox-preview.json',p);assert not p.get('error'),p
 s=rr('request-rule-save',old,'allow',preview_token=p['request_rule_preview']['token']);save_json('sandbox-save.json',s);assert not s.get('error'),s
 rule=s['saved_rule'];f=rule['filter']
 assert f['application']==app['key'] and f['revision']==app['revision'] and not f.get('process') and f['protocol']=='*',rule
 ended=event(old['id']);assert ended is None or ended['state']!='allowed',ended
 assert api('decide',generation=generation,id=old['id'],action='allow',scope='once').get('error'),'ended request approved'
 assert peer_count()==before,'ended request delivered'
 assert not daemon_refs(),daemon_refs()
 log('PASS Remember -> Allow saved from the ended sandbox request: rule %s bound to key %s… revision %s; ended request undeliverable; references closed'%(rule['id'],app['key'][:12],app['revision']))
 # 3. Relaunch: NEW process, NEW mount namespace, other per-instance path, same backing file.
 c,info2,exe2=sandbox(backing=BACK);assert exe2!=exe and info2['pid']!=info['pid']
 ask(c,'send',protocol='tcp',timeout_ms=8000);wait(lambda:peer_count()==before+1)
 rows=events_for(info2['pid']);save_json('relaunch-events.json',rows)
 assert all(e['state']!='awaiting-decision' for e in rows) and any(e['state']=='allowed' and e['rule']==rule['id'] for e in rows),rows
 new=next(e for e in rows if e['rule']==rule['id']);no=new['attribution']['owners'][0]
 # Namespace inode numbers can be reused after the first sandbox died; the
 # instance is new by PID/start and its namespace-local path.
 assert no['executable']==exe2 and no['pid']==info2['pid'] and no['mountns']!=os.readlink('/proc/self/ns/mnt'),no
 quit(c)
 log('PASS relaunch in new mount ns %s at %s (PID %d) delivered by rule %s without prompt'%(no['mountns'],exe2,info2['pid'],rule['id']))
 # 4. Sibling sandbox running a different executable (same name) prompts.
 c,info3,_=sandbox(backing=SIB);ask(c,'send',protocol='tcp',timeout_ms=8000);o=wait(lambda:pending(info3['pid']));save_json('sibling-pending.json',o)
 assert o['attribution']['application']['key']!=app['key']
 assert not api('decide',generation=generation,id=o['id'],action='block',scope='once').get('error')
 time.sleep(.3);assert peer_count()==before+1;quit(c)
 log('PASS sibling sandbox with a different executable prompted (not covered) and was denied once')
 # 5. Modified/replaced backing file at the same path prompts again.
 tmp=APP+'.new';shutil.copy2(NATIVE,tmp)
 with open(tmp,'ab') as fh:fh.write(b'\0modified')
 os.replace(tmp,APP)
 c,info4,_=sandbox(backing=BACK);ask(c,'send',protocol='tcp',timeout_ms=8000);m=wait(lambda:pending(info4['pid']));save_json('replaced-pending.json',m)
 ma=m['attribution']['application'];assert ma['key']==app['key'] and ma['revision']!=app['revision'],ma
 assert any(r['id']==rule['id'] for r in m.get('previous_revision_rules') or []),m.get('previous_revision_rules')
 assert not api('decide',generation=generation,id=m['id'],action='block',scope='once').get('error')
 time.sleep(.3);assert peer_count()==before+1;quit(c)
 log('PASS replaced executable at the reused host path prompted (revision %s -> %s); old rule listed as previous revision only'%(app['revision'],ma['revision']))
 # 6. Sandbox-only executable (lives only in the sandbox tmpfs): precise refusal.
 c,info5,exe5=sandbox(only=NATIVE)
 so,src5=prompt_then_exit(c,info5,'sandbox-only')
 assert src5['executable_identity']=='sandbox-only',src5
 r=rr('request-rule-preview',so,'allow');save_json('sandbox-only-refusal.json',r)
 assert r.get('error_code')=='identity_unverifiable' and 'Start the app again and choose Remember while its request is open.' in r['error'] and exe5 in r['error'] and 'mountns' in r['error'],r
 again=rr('request-rule-preview',so,'allow');assert again.get('error_code')=='identity_unverifiable',again
 assert len(api()['rules'])==1 and peer_count()==before+1
 assert not daemon_refs(),daemon_refs()
 log('PASS sandbox-only executable (%s on sandbox tmpfs): identity_unverifiable refusal, no rule: %s'%(exe5,r['error']))
 g['delete'](rule);assert not api().get('rules')
 for c in launched:quit(c)
 log('PASS different UID: unit-only (lab maps a single UID); see TestSandboxRequestRuleAfterExitBindsVerifiedIdentity / TestRetainedEvidenceRefusesModifiedReplacedAndOtherUser')
 (RUN/'result.json').write_text(json.dumps({'passed':True,'generation':generation,'native':NATIVE,'deliveries':peer_count()-before,'rules':0,'host_actions':False},indent=2)+'\n')
