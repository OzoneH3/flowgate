#!/usr/bin/env python3
"""TEST-ONLY Go overlay: bounded memory trace; zero verdict-path file writes."""
import pathlib,json,subprocess,hashlib,os,argparse
root=pathlib.Path('/home/flowgate-user/Apps/flowgate')
p=argparse.ArgumentParser();p.add_argument('--source',type=pathlib.Path,default=root/'.workspace/integration-acceptance-source');p.add_argument('--output',type=pathlib.Path,required=True);args=p.parse_args();frozen=args.source.resolve();out=args.output.resolve();assert '.workspace' in frozen.parts and '.workspace' in out.parts
assert not out.exists();out.mkdir();replace={}
def overlay(name,fn):
 p=frozen/name;target=out/p.name;target.write_text(fn(p.read_text()));replace[str(p)]=str(target)
trace=out/'handoff_trace.go';trace.write_text('''package serveprofile
import("encoding/json";"os";"sync";"time";"golang.org/x/sys/unix")
type handoffEvent struct{ Kind string; ID,Seq,BootNS uint64; Flow string; Allowed,OK bool }
var handoff struct {sync.Mutex; Events [8192]handoffEvent; Used int; Truncated bool}
func HandoffRecord(kind string,id,seq uint64,flow string,allowed,ok bool){
 handoff.Lock();defer handoff.Unlock()
 if handoff.Used==len(handoff.Events){handoff.Truncated=true;return}
 var ts unix.Timespec;unix.ClockGettime(unix.CLOCK_BOOTTIME,&ts)
 handoff.Events[handoff.Used]=handoffEvent{kind,id,seq,uint64(ts.Nano()),flow,allowed,ok};handoff.Used++
}
func DumpHandoff(){
 handoff.Lock();defer handoff.Unlock()
 f,err:=os.OpenFile("/work/.workspace/m1/handoff-trace.json",os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return};defer f.Close()
 json.NewEncoder(f).Encode(struct{Events []handoffEvent;Truncated bool;DumpedAt time.Time}{handoff.Events[:handoff.Used],handoff.Truncated,time.Now()})
}
''');replace[str(frozen/'internal/serveprofile/handoff_trace.go')]=str(trace)
overlay('internal/queue/processor.go',lambda s:s.replace('"flowgate/internal/queuehealth"','"flowgate/internal/queuehealth"\ndiagnostics "flowgate/internal/serveprofile"').replace('\tallowed, err := p.verdict(j.id, live && v.State == "allowed", valid)',''' diagnostics.HandoffRecord("verdict-begin",uint64(j.id),0,j.flow.Key(),live && v.State=="allowed",true)
 allowed, err := p.verdict(j.id, live && v.State == "allowed", valid)
 diagnostics.HandoffRecord("verdict-end",uint64(j.id),0,j.flow.Key(),allowed,err==nil)'''))
overlay('internal/queue/queue.go',lambda s:s.replace('\t\t\tif err == nil {\n\t\t\t\tdiagnostics.Count', '''            if err==nil && f.Protocol=="udp" && f.Direction=="outgoing" && len(*a.Payload)>=52 && (*a.Payload)[0]>>4==4 && (*a.Payload)[9]==17 {
                off:=int((*a.Payload)[0]&15)*4+8+16
                if len(*a.Payload)>=off+8 {diagnostics.HandoffRecord("packet",uint64(*a.PacketID),binary.LittleEndian.Uint64((*a.Payload)[off:off+8]),f.Key(),false,true)}
            }
\t\t\tif err == nil {\n\t\t\t\tdiagnostics.Count''',1))
overlay('internal/socketgrant/grant.go',lambda s:s.replace('"flowgate/internal/identity"','"flowgate/internal/identity"\ndiagnostics "flowgate/internal/serveprofile"\n"fmt"').replace('\ts.entries[k] = Value{deadline, s.generation}', '\tdiagnostics.HandoffRecord("grant-published",k.Cookie,0,fmt.Sprintf("%v",k),true,true)\n\ts.entries[k] = Value{deadline, s.generation}',1))
overlay('cmd/flowgate/serve.go',lambda s:s.replace('func serveCommand(args []string) error {','func serveCommand(args []string) error {\n defer diagnostics.DumpHandoff()'))
(out/'overlay.json').write_text(json.dumps({'Replace':replace},indent=2))
env=dict(os.environ,GOMAXPROCS='2',TMPDIR=str(root/'.workspace/t'),GOTMPDIR=str(root/'.workspace/t'),GOCACHE=str(root/'.workspace/socket-enforcement-release/source/.workspace/go-cache'))
subprocess.run(['go','build','-overlay',str(out/'overlay.json'),'-tags','socketprototype','-o',str(out/'flowgate-order-trace'),'./cmd/flowgate'],cwd=frozen,env=env,check=True)
(out/'provenance.json').write_text(json.dumps({'source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=frozen,text=True).strip(),'test_only':True,'maximum_events':8192,'file_io':'shutdown dump only','sha256':{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.is_file()}},indent=2))
