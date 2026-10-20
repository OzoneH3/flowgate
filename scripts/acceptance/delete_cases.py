"""One receiver check for atomic rule deletion; invoked only by host-lab."""
def exercise(g):
    api,remote,wait,pending,counts=g['api'],g['remote'],g['wait'],g['pending'],g['counts']
    port=44001
    remote('udp',port=port,source_port=45101)
    event=wait(lambda:pending(port))
    assert counts[port]==0
    r=api('decide',id=event['id'],action='allow',scope='persistent');assert 'error' not in r,r
    wait(lambda:counts[port]==1)
    snapshot=api();rule=next(r for r in snapshot['rules'] if r['filter'].get('local_port')==port)
    assert 'conditional-rule-delete-v1' in snapshot['capabilities']
    remote('udp',port=port,source_port=45102);wait(lambda:counts[port]==2)
    r=api('rule-delete',generation=snapshot['generation'],id=rule['id'],expected_version=rule.get('version',0))
    assert r.get('deleted_rule')==dict(id=rule['id'],version=rule.get('version',0)),r
    assert not api().get('rules')
    remote('udp',port=port,source_port=45103)
    event=wait(lambda:pending(port));assert counts[port]==2
    r=api('decide',id=event['id'],action='block',scope='once');assert 'error' not in r,r
    import time
    time.sleep(.3);assert counts[port]==2
    print('PASS receiver: persistent UDP Allow delivers and matches new source port; conditional delete restores Ask; subsequent held one-shot Block delivers nothing',flush=True)
