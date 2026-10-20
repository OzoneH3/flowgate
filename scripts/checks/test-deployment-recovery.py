#!/usr/bin/env python3
"""Unprivileged trace of the fixed local recovery command. No host paths/actions."""
import json,os,pathlib,subprocess,sys,tempfile,types
root=pathlib.Path(__file__).resolve().parents[2];run=pathlib.Path(tempfile.mkdtemp(prefix='recovery-trace-',dir=root/'.workspace'))
release=run/'release';release.mkdir();state=run/'state';state.mkdir();(state/'protection.json').write_text('{"schema":1,"mode":"both"}');(state/'rules.db').write_bytes(b'policy-sentinel')
commands=[]
def path(value):
 value=str(value)
 if value=='/usr/local/lib/flowgate/current':return release
 if value=='/var/lib/flowgate/protection.json':return state/'protection.json'
 raise AssertionError('Unexpected recovery path '+value)
def execute(argv,**kw):
 commands.append(argv);assert kw.get('check')is True
 return types.SimpleNamespace(returncode=0)
mods={'pathlib':types.SimpleNamespace(Path=path),'subprocess':types.SimpleNamespace(run=execute),'os':types.SimpleNamespace(**{k:getattr(os,k)for k in dir(os)if not k.startswith('__')})}
mods['os'].geteuid=lambda:0
original={k:sys.modules[k]for k in mods}
try:
 sys.modules.update(mods)
 exec(compile((root/'deployment/recover.py').read_text(),'recovery-under-test','exec'),{})
finally:sys.modules.update(original)
assert json.loads((state/'protection.json').read_text())=={'schema':1,'mode':'monitoring'}
assert(state/'rules.db').read_bytes()==b'policy-sentinel'
assert commands==[['systemctl','stop','flowgate.service'],[str(release/'flowgate'),'protection-recover','--state','/run/flowgate-enforcement'],['systemctl','reset-failed','flowgate.service','flowgate-guard.service'],['systemctl','start','flowgate-guard.service','flowgate.service']],commands
(run/'result.json').write_text(json.dumps({'passed':True,'commands':commands,'label':'mocked subprocess trace only, not installed recovery/systemd acceptance'},indent=2));print('PASS recovery command trace persists monitoring, preserves policy, scopes cleanup/reset/start; no host action')
