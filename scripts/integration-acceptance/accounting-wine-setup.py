import pathlib,os,subprocess,time,json

def setup(P,R,children):
 cases={}
 initialized=[]
 for prefix in ('a','b'):
  env=dict(os.environ,WINEPREFIX=str(P/('prefix-'+prefix)),WINEDEBUG='-all',WINEESYNC='0',WINEFSYNC='0',WINE_NTSYNC='0',WINE_DISABLE_FAST_SYNC='1',WINEDLLOVERRIDES='mscoree,mshtml=',HOME=str(R),TMPDIR=str(R),DISPLAY='',WAYLAND_DISPLAY='',LD_LIBRARY_PATH=str(P/'proton/files/lib/x86_64-linux-gnu'))
  begin=time.monotonic()
  with (R/('wineboot-'+prefix+'.txt')).open('w') as output:
   proc=subprocess.Popen([str(P/'proton/files/bin/wine'),r'C:\windows\system32\wineboot.exe','-u'],env=env,stdout=output,stderr=subprocess.STDOUT)
   try:code=proc.wait(90)
   except subprocess.TimeoutExpired:proc.kill();proc.wait();raise RuntimeError('Wine prefix initialization timeout '+prefix)
  initialized.append(dict(prefix=prefix,seconds=time.monotonic()-begin,returncode=code))
  assert code==0,initialized
 time.sleep(3)
 visible=[]
 for f in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
  try:
   args=f.read_bytes().replace(b'\0',b' ').decode(errors='replace')
   if any(n in args for n in ('services.exe','winedevice.exe','wineserver')):visible.append(dict(pid=f.parent.name,argv=args[:1024]))
  except OSError:pass
 (R/'wine-services.json').write_text(json.dumps(dict(initialized=initialized,processes=visible),indent=2))
 for prefix in ['a','b']:
  for app in ['Alpha','Beta']:
   name=prefix+app;trace=R/(name+'.txt');go=R/(name+'-go');measure=R/(name+'-measure');exe=P/(app+'.exe')
   win=lambda p:'Z:'+str(p).replace('/','\\')
   env=dict(os.environ,WINEPREFIX=str(P/('prefix-'+prefix)),WINEDEBUG='-all',WINEESYNC='0',WINEFSYNC='0',WINE_NTSYNC='0',WINE_DISABLE_FAST_SYNC='1',WINEDLLOVERRIDES='mscoree,mshtml=',HOME=str(R),TMPDIR=str(R),LD_LIBRARY_PATH=str(P/'proton/files/lib/x86_64-linux-gnu'),FLOWGATE_TEST_SOCKETS='2',FLOWGATE_TEST_DATAGRAMS='375',FLOWGATE_TEST_INTERVAL_MS='8',FLOWGATE_TEST_PORT='43001',FLOWGATE_TEST_HOST='10.79.0.2',FLOWGATE_TEST_TOKEN=name,FLOWGATE_TEST_GO=win(go),FLOWGATE_TEST_TRACE=win(trace),FLOWGATE_MEASURE_GO=win(measure))
   args=[str(P/'proton/files/bin/wine'),str(exe)]
   if (P/'strace').exists():args=[str(P/'strace'),'-f','-ttt','-T','-yy','-s','96','-e','trace=sendto,sendmsg,sendmmsg,write,writev','-o',str(R/(name+'-linux.txt')),*args]
   p=subprocess.Popen(args,env=env,stdout=(R/(name+'.out.txt')).open('w'),stderr=(R/(name+'.err')).open('w'));children.append(p)
   deadline=time.monotonic()+60
   while time.monotonic()<deadline:
    if p.poll() is not None:raise RuntimeError('Wine fixture exited '+name+' '+str(p.returncode))
    if trace.exists() and 'SATURATION_READY' in trace.read_text():break
    time.sleep(.1)
   else:raise RuntimeError('Wine READY timeout '+name)
   pid=p.pid
   if (P/'strace').exists():
    ids=pathlib.Path('/proc/'+str(p.pid)+'/task/'+str(p.pid)+'/children').read_text().split();assert ids,('traced Wine child missing',name);pid=int(ids[0])
   info=json.loads(subprocess.check_output([str(P/'inspect'),'inspect',str(pid)],text=True))
   assert info['application']['kind']=='wine',info
   cases[name]={'process':p,'pid':pid,'application':info['application'],'trace':trace,'go':go,'measure':measure}
 # Initialize services with foreground applications ALREADY holding the broker.
 # A standalone wineboot can exit its last foreground client and stop the broker.
 service_runs=[]
 for prefix in ('a','b'):
  env=dict(os.environ,WINEPREFIX=str(P/('prefix-'+prefix)),WINEDEBUG='+service,+ntoskrnl',WINEESYNC='0',WINEFSYNC='0',WINE_NTSYNC='0',WINE_DISABLE_FAST_SYNC='1',WINEDLLOVERRIDES='mscoree,mshtml=',HOME=str(R),TMPDIR=str(R),DISPLAY='',WAYLAND_DISPLAY='',LD_LIBRARY_PATH=str(P/'proton/files/lib/x86_64-linux-gnu'))
  begin=time.monotonic()
  with (R/('wineboot-live-'+prefix+'.txt')).open('w') as output:
   proc=subprocess.Popen([str(P/'proton/files/bin/wine'),r'C:\windows\system32\wineboot.exe','-u'],env=env,stdout=output,stderr=subprocess.STDOUT)
   try:code=proc.wait(45)
   except subprocess.TimeoutExpired:proc.kill();proc.wait();code=-1
  service_runs.append(dict(prefix=prefix,seconds=time.monotonic()-begin,returncode=code))
 processes=[]
 for f in pathlib.Path('/proc').glob('[0-9]*/cmdline'):
  try:
   args=f.read_bytes().replace(b'\0',b' ').decode(errors='replace')
   if any(n in args for n in ('services.exe','winedevice.exe','wineserver')):processes.append(dict(pid=f.parent.name,argv=args[:1024]))
  except OSError:pass
 (R/'wine-services-live.json').write_text(json.dumps(dict(initialized=service_runs,processes=processes),indent=2))
 # Diagnostic-only helper round trips in the same broker, before protection.
 import select
 probes=[]
 for prefix in ('a','b'):
  env=dict(PATH='/usr/bin:/bin',WINEPREFIX=str(P/('prefix-'+prefix)),WINESERVER='/usr/bin/false',WINEDEBUG='-all',WINELOADERNOEXEC='1',WINEDLLOVERRIDES='mscoree,mshtml=',DISPLAY='',WAYLAND_DISPLAY='',TMPDIR=str(R),HOME=str(R),XDG_CACHE_HOME=str(R),XDG_CONFIG_HOME=str(R),XDG_DATA_HOME=str(R),WINEESYNC='0',WINEFSYNC='0',WINE_NTSYNC='0',WINE_DISABLE_FAST_SYNC='1')
  proc=subprocess.Popen([str(P/'proton/files/lib/wine/x86_64-unix/wine'),str(P/'table-probe.exe')],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(R/('helper-'+prefix+'.err')).open('w'),text=True)
  try:
   for request in ('t4','u4','p4','u4'):
    begin=time.monotonic();proc.stdin.write(request+'\n');proc.stdin.flush();ready=select.select([proc.stdout],[],[],30)[0];reply=proc.stdout.readline() if ready else ''
    probes.append(dict(prefix=prefix,request=request,seconds=time.monotonic()-begin,reply=reply,timeout=not ready))
    if not ready:break
  finally:
   proc.terminate()
   try:proc.wait(5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
 (R/'helper-latency.json').write_text(json.dumps(probes,indent=2))
 return cases
