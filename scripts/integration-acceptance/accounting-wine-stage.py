#!/usr/bin/env python3
"""Stage supported Proton + two synthetic PEs/two private prefixes in a VM.
No Wine, collector or firewall is executed on the host.
"""
import argparse,pathlib,subprocess,shutil,json,hashlib,os,re
p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--backend',type=pathlib.Path,required=True);p.add_argument('--collector',type=pathlib.Path,required=True);p.add_argument('--wine-runtime',type=pathlib.Path);p.add_argument('--wine-prefix-template',type=pathlib.Path);p.add_argument('--wine-helper',type=pathlib.Path);a,rest=p.parse_known_args();H=pathlib.Path(__file__).resolve().parent;root=H.parents[3];out=a.output.resolve();assert '.workspace' in out.parts
subprocess.run(['python3',str(H/'accounting-stage.py'),'--output',str(out),'--case-file',str(H/'accounting-wine.py'),'--backend',str(a.backend),'--collector',str(a.collector),*rest],check=True)
host_tmp=out/'host-tmp';host_tmp.mkdir();os.environ['TMPDIR']=str(host_tmp)
o=out/'overlay';w=o/'work/m1';guest=pathlib.Path('/work/m1');runtime=a.wine_runtime or root/'.workspace/udp-capacity/proton';prefix=a.wine_prefix_template or root/'.workspace/proton-launcher-fixture/run11/prefix-a/pfx';fixture=H/'wine-fixture'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for sub in ['files/bin','files/lib/wine/x86_64-unix','files/lib/wine/x86_64-windows','files/lib/x86_64-linux-gnu','files/share/wine']:
 shutil.copytree(runtime/sub,w/'proton'/sub,symlinks=True,ignore=shutil.ignore_patterns('mono','gecko'),dirs_exist_ok=True)
# Dynamic Linux libraries are copied, never executed, along with the guest.
libs=set()
for f in [runtime/'files/bin/wine',runtime/'files/bin/wineserver',*(runtime/'files/lib/wine/x86_64-unix').glob('*.so')]:
 r=subprocess.run(['ldd',str(f)],capture_output=True,text=True)
 for tok in r.stdout.split():
  if tok.startswith('/') and pathlib.Path(tok).is_file():libs.add(pathlib.Path(tok))
for src in libs:
 dst=o/str(src).lstrip('/');dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
for label in ['a','b']:
 dst=w/('prefix-'+label);shutil.copytree(prefix,dst,symlinks=True,ignore=shutil.ignore_patterns('syswow64','Program Files (x86)','vrclient','gstreamer-1.0','shadercache','*.old','*.new','pfx.lock','creation_sync_guard','pfx'))
 for f in dst.rglob('*'):
  if not f.is_symlink():continue
  target=os.readlink(f)
  if '/files/lib/wine/' in target:
   tail=target.split('/files/lib/wine/',1)[1];f.unlink();f.symlink_to(guest/'proton/files/lib/wine'/tail)
shutil.copy2(a.wine_helper or root/'.workspace/windows/table-probe.exe',w/'table-probe.exe')
build=out/'pe-build';build.mkdir();shutil.copy2(fixture/'win64_fixture.h',build/'win64_fixture.h')
with (build/'win64_fixture.h').open('a') as f:f.write('\nAPI int WSAGetLastError(void);\n')
s=(fixture/'stable-udp.c').read_text().replace('Sleep(2000); closesocket(s);','Sleep(20000); closesocket(s);')
s=s.replace('static unsigned attempted[MAX_SOCKETS], ok[MAX_SOCKETS], failed[MAX_SOCKETS];','static unsigned attempted[MAX_SOCKETS], ok[MAX_SOCKETS], failed[MAX_SOCKETS], errors[MAX_SOCKETS][128], other_errors[MAX_SOCKETS];')
s=s.replace('else failed[index]++;','else {failed[index]++;int error=WSAGetLastError()-10000;if(error>=0 && error<128)errors[index][error]++;else other_errors[index]++;}')
s=s.replace('Sleep(20000); closesocket(s);', '''for(unsigned e=0;e<128;e++){if(!errors[index][e])continue;char line[96];unsigned at=0;const char *t="WSAERROR ";while(*t)line[at++]=*t++;at=append(line,at,index);line[at++]=' ';at=append(line,at,e+10000);line[at++]=' ';at=append(line,at,errors[index][e]);line[at++]=10;line[at]=0;say(line);}Sleep(20000); closesocket(s);''')
s=s.replace('attempted[index]++;','''if(seq==125){char line[96];unsigned at=0;const char *t="WARMSTATS ";while(*t)line[at++]=*t++;at=append(line,at,index);line[at++]=' ';at=append(line,at,ok[index]);line[at++]=' ';at=append(line,at,failed[index]);line[at++]=10;line[at]=0;say(line);char gate[1024];if(GetEnvironmentVariableA("FLOWGATE_MEASURE_GO",gate,sizeof(gate)))while(GetFileAttributesA(gate)==INVALID_FILE_ATTRIBUTES)Sleep(20);}
        attempted[index]++;''')
(build/'fixture.c').write_text(s)
h=(build/'win64_fixture.h').read_text();names=re.findall(r'^API .*?\b(\w+)\(',h,re.M);ws={'WSAStartup','socket','sendto','closesocket','bind','getsockname','htons','ntohs','htonl','inet_addr','WSAGetLastError'}
for dll,ns in [('KERNEL32',[n for n in names if n not in ws]),('WS2_32',sorted(ws))]:
 d=build/(dll+'.def');d.write_text('LIBRARY '+dll+'.dll\nEXPORTS\n'+'\n'.join(ns)+'\n');subprocess.run(['llvm-dlltool','-m','i386:x86-64','-d',str(d),'-l',str(build/(dll+'.lib'))],check=True)
subprocess.run(['clang','--target=x86_64-pc-windows-msvc','-ffreestanding','-fno-stack-protector','-O2','-c',str(build/'fixture.c'),'-o',str(build/'fixture.obj')],check=True)
for app in ['Alpha','Beta']:
 subprocess.run(['lld-link','/entry:mainCRTStartup','/subsystem:console','/nodefaultlib','/out:'+str(w/(app+'.exe')),str(build/'fixture.obj'),str(build/'KERNEL32.lib'),str(build/'WS2_32.lib')],check=True)
 # Distinct PE revisions in addition to distinct verified paths.
 with (w/(app+'.exe')).open('ab') as f:f.write(('synthetic-'+app).encode())
shutil.copy2(H/'accounting-wine-setup.py',w/'wine_setup.py')
f=w/'peer.py';s=f.read_text();old=next(l for l in s.splitlines() if "tag,seq,ts=struct.unpack" in l)
s=s.replace(old," now=time.monotonic_ns()\n if b.startswith((b'aAlpha|',b'aBeta|',b'bAlpha|',b'bBeta|')):\n  fields=b.split(b'|',4);tag=fields[0].decode()+'-'+fields[1].decode();seq=int(fields[2]);ts=now\n else:\n "+old);f.write_text(s)
f=w/'common.py';s=f.read_text().replace(" args += ['--udp-helper'", " args += ['--wine-runtime-bin',str(P/'proton/files/bin'),'--wine-prefix',str(P/'prefix-a'),'--wine-prefix',str(P/'prefix-b'),'--wine-helper',str(P/'table-probe.exe')]\n args += ['--udp-helper'")
s=s.replace("  db=sqlite3.connect(R/'rules.db')", "  import wine_setup\n  wine_cases=wine_setup.setup(P,R,children)\n  globals()['wine_cases']=wine_cases\n  db=sqlite3.connect(R/'rules.db')")
s=s.replace('  db.commit();db.close();', '''  for name,c in wine_cases.items():
   a=c['application'];rule={'schema':2,'id':'wine-'+name,'version':1,'created':'2026-01-01T00:00:00Z','action':'block' if name=='bBeta' else 'allow','executable':a['executable'],'filter':{'application':a['key'],'revision':a['revision'],'uid':0,'direction':'outgoing','protocol':'udp','remote_address':'*'}};db.execute('insert into rules values(?,?)',(rule['id'],json.dumps(rule)))
  db.commit();db.close();''')
f.write_text(s)
(out/'wine-provenance.json').write_text(json.dumps({'scope':'real headless supported Win64 Proton; UID0 guest fixture; two applications x two prefixes; no Wine shaping','runtime':str(runtime),'helper_sha256':sha(w/'table-probe.exe'),'pe':{x:sha(w/(x+'.exe')) for x in ['Alpha','Beta']},'source_sha256':sha(build/'fixture.c'),'library_count':len(libs)},indent=2))
base=pathlib.Path(rest[rest.index('--base-initrd')+1])
with (out/'wine-overlay.gz').open('wb') as dst:
 find=subprocess.Popen(['find','.','-print0'],cwd=o,stdout=subprocess.PIPE);cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=o,stdin=find.stdout,stdout=subprocess.PIPE,stderr=subprocess.PIPE);find.stdout.close();subprocess.run(['gzip','-1'],stdin=cpio.stdout,stdout=dst,check=True);cpio.stdout.close();assert cpio.wait()==find.wait()==0
with (out/'initramfs.gz').open('wb') as dst:
 for src in (base,out/'wine-overlay.gz'):
  with src.open('rb') as f:shutil.copyfileobj(f,dst)
(out/'image-hashes.json').write_text(json.dumps({n:sha(out/n) for n in ('vmlinuz','initramfs.gz')},indent=2))
