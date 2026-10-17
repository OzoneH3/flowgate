"""One actual controller/NFQUEUE receiver check; only imported in private host-lab."""
def exercise(g):
    import json,time
    from pathlib import Path
    api,remote,wait,counts=g['api'],g['remote'],g['wait'],g['counts']
    port=44001
    def target():
        snapshot=api().get('activity',{})
        for row in snapshot.get('rows',[]):
            if row['socket']['protocol']=='udp' and row['socket']['local'].endswith(':'+str(port)) and row['ownership_category']=='visible-holder' and len(row['owners'])==1:
                return dict(row_id=row['id'],process_id=row['owners'][0])
    chosen=wait(target)
    assert not api().get('events'), 'rule must be created before any pending attempt'
    generation=api()['generation']
    draft=dict(direction='incoming',protocol='udp',action='allow',remote_address='10.79.0.2',local_port=port,remote_port=0,disabled=False,expires='0001-01-01T00:00:00Z')
    preview_request=dict(generation=generation,observed_target=chosen,observed_draft=draft)
    preview=api('observed-rule-preview',**preview_request)
    assert 'error' not in preview,preview
    p=preview['observed_preview'];assert p['enforcement']['covered']
    saved=api('observed-rule-save',generation=generation,preview_token=p['token'],observed_draft=draft)
    assert saved.get('saved_rule',{}).get('id')==p['rule']['id'],saved
    (g['RUN']/'observed-rule-receiver-api.json').write_text(json.dumps(dict(preview_request=preview_request,preview=preview,saved=saved),indent=2))
    assert not api().get('events'), 'creation must not fabricate or approve a flow'
    remote('udp',port=port,source_port=45301);wait(lambda:counts[port]==1)
    assert not g['pending'](port)
    remote('udp',port=port,source_port=45302);wait(lambda:counts[port]==2)
    # Existing editor, unchanged semantics: edit the created Allow to Block.
    rule=saved['saved_rule'];rule['action']='block'
    edited=api('rule-save',generation=generation,id=rule['id'],expected_version=rule['version'],rule=rule)
    assert 'error' not in edited,edited
    remote('udp',port=port,source_port=45303)
    wait(lambda:any(e['state']=='blocked' and e['rule']==rule['id'] for e in api().get('events',[])))
    time.sleep(.2);assert counts[port]==2
    # Service scope does not grant a different listening service permission.
    remote('udp',port=44003,source_port=45304)
    e=wait(lambda:g['pending'](44003));assert counts[44003]==0
    assert 'error' not in api('decide',id=e['id'],action='block',scope='once')
    print('PASS receiver: Activity-created incoming Allow before any pending event delivers two one-shot UDP attempts/new source ports; edit Block prevents delivery; different service remains Ask. Actual isolated host-mode controller, IPv4, root namespace peer.',flush=True)
