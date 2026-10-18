"""Focused real receiver checks; called only inside process-rules-isolated lab."""
import json

def check(g):
 api,run,log,create,edit,delete,incoming,outgoing,wait=[g[k]for k in ['api','RUN','log','create','edit','delete','incoming','outgoing','wait']]
 gen=api()['generation'];config=api()['network_zones'];revision=config['revision']
 def zone(zone,action,direction):
  d=dict(direction=direction,protocol='*',action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
  target=dict(zone=zone,scope='machine');p=api('zone-rule-preview',generation=gen,zone_revision=revision,zone_target=target,observed_draft=d);assert not p.get('error'),p
  v=p['zone_preview'];assert not v['rule']['filter'].get('application') and v['rule']['filter']['all_programs'] and v['rule']['filter']['all_uids']
  s=api('zone-rule-save',generation=gen,zone_revision=revision,zone_target=target,observed_draft=d,preview_token=v['token']);assert not s.get('error'),s
  # Explicit receipt check models ambiguous ACK, no new ID/write.
  r=api('zone-rule-save',generation=gen,zone_revision=revision,zone_target=target,observed_draft=d,preview_token=v['token']);assert r['replayed']and r['saved_rule']==s['saved_rule']
  (run/('zone-'+zone+'-'+direction+'-preview.json')).write_text(json.dumps(p,indent=2))
  return s['saved_rule']
 def scoped(name,target,zone,action,direction):
  d=dict(target_scope=target,network_zone=zone,zone_revision=revision,direction=direction,protocol='*',action=action,remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
  p=api('observed-rule-preview',generation=gen,observed_target=g['target'](name),observed_draft=d);assert not p.get('error'),p
  s=api('observed-rule-save',generation=gen,observed_draft=d,preview_token=p['observed_preview']['token']);assert not s.get('error'),s;return s['saved_rule']
 for direction,send in [('incoming',incoming),('outgoing',outgoing)]:
  local=zone('local','allow',direction);internet=zone('internet','block',direction)
  for proto in ['udp','tcp']:send('alpha',proto,False,True);send('alpha',proto,True,False)
  log('PASS '+direction+' all-program Local IPv4 Allow/Internet IPv6 Block, TCP+UDP actual receiver counts; explicit configured routed peers')
  app=scoped('alpha','application','internet','allow',direction)
  send('alpha','udp',True,True);send('beta','udp',True,True)
  process=scoped('alpha','process','internet','block',direction)
  send('alpha','udp',True,False);send('beta','udp',True,True)
  view=api('policy-view',generation=gen)['policy_view'];assert len(view['zones'])==2 and view['network_zones']['revision']==revision
  assert any(internet['id']in p['zone_fallback_rule_ids'] for p in view['processes'])
  ev=next(x for x in api()['events'] if x['rule']==process['id'])
  explanation=api('policy-explain',generation=gen,event_ids=[ev['id']])['policy_explanations']['contexts'][0]
  assert explanation['selected_rule']==process['id'];assert [x['id']for x in explanation['matching_rules']]==[process['id'],app['id'],internet['id']]
  q=dict(process,disabled=True)
  edited=api('rule-save',generation=gen,zone_revision=revision,id=process['id'],expected_version=process['version'],rule=q);assert not edited.get('error'),edited
  process=edited['saved_rule'];send('alpha','udp',True,True)
  stale=api('rule-delete',generation=gen,id=process['id'],expected_version=process['version']-1);assert stale.get('error_code')=='version_conflict'
  delete(process);delete(app);send('alpha','udp',True,False)
  log('PASS '+direction+' application override + exact process override, sibling fallback, disable/staleDelete/delete + authoritative ordered explanation')
  delete(local);delete(internet)
 assert api().get('rules',[])==[]
 logs=api('decision-log',decision_query={'limit':100});assert not logs.get('error');(run/'zone-decision-log.json').write_text(json.dumps(logs,indent=2));assert any(r.get('flow',{}).get('network_scope',{}).get('zone')=='internet' for r in logs['decision_log']['records'])
 (run/'zone-decision-log.json').write_text(json.dumps(logs,indent=2))
 log('PASS Decision Log zone scope/target snapshots; no Activity byte-total claim; final rules0')

def check_unknown(g):
 import time
 api,run,log,cmd,wait=[g[k]for k in ['api','RUN','log','cmd','wait']]
 cmd('nsenter','--net=/proc/'+str(g['peer'].pid)+'/ns/net','ip','addr','add','10.80.0.2/32','dev','fgpeer')
 cmd('ip','route','add','10.80.0.2/32','dev','fghost')
 gen=api()['generation'];revision=api()['network_zones']['revision'];d=dict(direction='incoming',protocol='*',action='allow',remote_address='*',local_port=0,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z');target=dict(zone='local',scope='machine')
 p=api('zone-rule-preview',generation=gen,zone_revision=revision,zone_target=target,observed_draft=d);assert not p.get('error'),p
 v=p['zone_preview'];s=api('zone-rule-save',generation=gen,zone_revision=revision,zone_target=target,observed_draft=d,preview_token=v['token']);assert not s.get('error'),s
 before=g['received']('alpha','udp4');g['remote']('udp',port=g['infos']['alpha']['ports']['udp4'],source_address='10.80.0.2')
 def pending():
  return next((x for x in api().get('events',[])if x['flow']['remote'].startswith('10.80.0.2:')and x['state']=='awaiting-decision'),None)
 event=wait(pending);assert event['flow']['network_scope']['state']=='unavailable';assert not event['flow']['network_scope'].get('zone');assert event['rule']=='default-ask';assert g['received']('alpha','udp4')==before
 r=api('decide',generation=gen,id=event['id'],action='block',scope='once');assert not r.get('error'),r;time.sleep(.5);assert g['received']('alpha','udp4')==before
 (run/'unknown-peer.json').write_text(json.dumps(event,indent=2));g['delete'](s['saved_rule']);assert api().get('rules',[])==[]
 log('PASS routed private peer outside configured Local does not inherit LocalAllow; explicit unknown/Ask then Deny, receiver count unchanged; rules0')
