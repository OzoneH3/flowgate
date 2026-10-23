const {test}=require('node:test');const assert=require('node:assert/strict');
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const {wrapperTarget}=require('../dist/test/flatpak-names.cjs');
const {ApplicationIcons,iconKey}=require('../dist/test/icons.cjs');
test('wrapper metadata parses bounded literal variables without executing commands',()=>{
 const script='#!/bin/sh\nDIR="$XDG_DATA_HOME/Product"\nBIN="$DIR/client"\nmkdir -p "$DIR"\nexec "$BIN" "$@"\n';
 assert.equal(wrapperTarget(script,'/test/data'),'/test/data/Product/client');
 for(const bad of [script.replace('$DIR/client','$(touch /bad)'),script.replace('mkdir -p "$DIR"','BIN="/other"'),script.replace('mkdir -p "$DIR"','eval "$SCRIPT"'),script.replace('$DIR/client','$UNKNOWN/client'),script+'exec "/other"\n'])assert.equal(wrapperTarget(bad,'/test/data'),undefined);
});
test('inactive Flatpak names match exact native UID/key/revision and wrapper target',async(t)=>{
 const home=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/flatpak-inactive-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const root=path.join(home,'installation/app'),uid=1234,id='org.example.Launcher',deploy=path.join(root,id,'x86_64/stable','a'.repeat(64));
 const bin=path.join(deploy,'files/bin'),desktops=path.join(deploy,'files/share/applications');fs.mkdirSync(bin,{recursive:true});fs.mkdirSync(desktops,{recursive:true});
 fs.mkdirSync(path.join(root,id,'current'));fs.symlinkSync(deploy,path.join(root,id,'current/active'));
 fs.writeFileSync(path.join(deploy,'metadata'),`[Application]\nname=${id}\n`);
 fs.writeFileSync(path.join(desktops,id+'.desktop'),'[Desktop Entry]\nType=Application\nName=Friendly Launcher\nExec=wrapper\n');
 const data=path.join(home,'.var/app',id,'data/Product');fs.mkdirSync(data,{recursive:true});const exe=path.join(data,'client');fs.writeFileSync(exe,'updated binary');
 fs.writeFileSync(path.join(bin,'wrapper'),'#!/bin/sh\nDIR="$XDG_DATA_HOME/Product"\nBIN="$DIR/client"\nexec "$BIN" "$@"\n');
 const native=path.join(bin,'runner');fs.writeFileSync(native,'native executable');
 function rule(file,shown=file,user=uid){const st=fs.statSync(file,{bigint:true});return {executable:shown,filter:{uid:user,application:crypto.createHash('sha256').update(`${user}|native||${file}`).digest('hex'),revision:`${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}`}};}
 async function name(r){const icons=new ApplicationIcons(home,[home],[],[root]);icons.observe({observation:{activity:{rows:[],processes:{}}},control:{events:[],rules:[r]}});return (await icons.metadata([iconKey({key:r.filter.application,revision:r.filter.revision,executable:r.executable})]))[iconKey({key:r.filter.application,revision:r.filter.revision,executable:r.executable})].name;}
 assert.equal(await name(rule(native,'/app/bin/runner')),'Friendly Launcher');assert.equal(await name(rule(exe)),'Friendly Launcher');
 const other=path.join(data,'other');fs.writeFileSync(other,'other executable');assert.equal(await name(rule(other)),undefined);
 const wrongUID=rule(exe);wrongUID.filter.uid++;assert.equal(await name(wrongUID),undefined);
 const old=rule(native,'/app/bin/runner');fs.writeFileSync(native,'different revision');assert.equal(await name(old),undefined);
 fs.writeFileSync(path.join(bin,'wrapper'),'#!/bin/sh\nexec "$(command)"\n');assert.equal(await name(rule(exe)),undefined);
});
test('native literal wrappers and Flatpak deployments provide bounded icon assets',async(t)=>{
 const home=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/linux-icon-test-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const svg='<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><path d="M0 0h16v16H0z"/></svg>';
 const exe=path.join(home,'real-client'),wrapper=path.join(home,'wrapper');fs.writeFileSync(exe,'native');fs.chmodSync(exe,0o755);fs.writeFileSync(wrapper,`#!/bin/sh\nexec ${exe} "$@"\n`);fs.chmodSync(wrapper,0o755);
 fs.mkdirSync(path.join(home,'applications'));fs.writeFileSync(path.join(home,'native.svg'),svg);fs.writeFileSync(path.join(home,'applications/native.desktop'),`[Desktop Entry]\nType=Application\nName=Native Client\nExec=${wrapper}\nIcon=${home}/native.svg\n`);
 const id='org.example.Client',deploy=path.join(home,'app',id,'x86_64/stable','c'.repeat(64)),flatExe=path.join(deploy,'files/bin/client');fs.mkdirSync(path.dirname(flatExe),{recursive:true});fs.writeFileSync(flatExe,'flatpak');fs.writeFileSync(path.join(deploy,'metadata'),`[Application]\nname=${id}\n`);
 const share=path.join(deploy,'files/share');fs.mkdirSync(path.join(share,'applications'),{recursive:true});fs.writeFileSync(path.join(share,'applications',id+'.desktop'),`[Desktop Entry]\nType=Application\nName=Flatpak Client\nIcon=${id}\n`);
 fs.mkdirSync(path.join(share,'icons/hicolor/scalable/apps'),{recursive:true});fs.writeFileSync(path.join(share,'icons/hicolor/scalable/apps',id+'.svg'),svg);
 const native={key:'native',revision:'1',name:'client',executable:exe,kind:'native'},flat={key:'flat',revision:'2',name:'client',executable:'/app/bin/client',host_executable:flatExe,kind:'native'};
 const icons=new ApplicationIcons(home,[home],[]);icons.observe({observation:{activity:{rows:[],processes:{n:{application:native},f:{application:flat}}}},control:{events:[],rules:[]}});
 const results=await icons.metadata([iconKey(native),iconKey(flat),'unknown']);
 for(const app of [native,flat]){const result=results[iconKey(app)];assert.ok(result.icon);assert.equal(icons.asset(result.icon.split('/').pop()).data.toString(),svg);}
 assert.equal(results[iconKey(native)].name,'Native Client');assert.equal(results[iconKey(flat)].name,'Flatpak Client');assert.equal(results.unknown.icon,null);
});

test('saved host deployment paths retain Flatpak metadata; richer backing evidence invalidates a miss',async(t)=>{
 const home=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/flatpak-host-icons-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 const id='org.example.Launcher',deploy=path.join(home,'app',id,'x86_64/stable','d'.repeat(64));
 const executable=path.join(deploy,'files/bin/runner'),share=path.join(deploy,'files/share');
 fs.mkdirSync(path.dirname(executable),{recursive:true});fs.writeFileSync(executable,'native');
 fs.writeFileSync(path.join(deploy,'metadata'),`[Application]\nname=${id}\n`);
 fs.mkdirSync(path.join(share,'applications'),{recursive:true});
 fs.mkdirSync(path.join(share,'icons/hicolor/scalable/apps'),{recursive:true});
 fs.writeFileSync(path.join(share,'applications',id+'.desktop'),`[Desktop Entry]\nType=Application\nName=Example Launcher\nIcon=${id}\n`);
 fs.writeFileSync(path.join(share,'icons/hicolor/scalable/apps',id+'.svg'),'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16"><path d="M0 0h16v16H0z"/></svg>');
 const saved={key:'saved',revision:'r',executable};
 const icons=new ApplicationIcons(home,[home],[],[],[]);
 const state={observation:{activity:{rows:[],processes:{}}},control:{events:[],rules:[{executable,filter:{application:saved.key,revision:saved.revision,uid:1000}}]}};
 icons.observe(state);
 const result=(await icons.metadata([iconKey(saved)]))[iconKey(saved)];assert.equal(result.name,'Example Launcher');assert.ok(result.icon);
 const live={key:'live',revision:'r',executable:'/app/bin/runner',kind:'native'};
 state.observation.activity.processes.p={application:live,uid:1000};icons.observe(state);
 assert.equal((await icons.metadata([iconKey(live)]))[iconKey(live)].icon,null);
 live.host_executable=executable;icons.observe(state);
 const found=(await icons.metadata([iconKey(live)]))[iconKey(live)];assert.equal(found.name,'Example Launcher');assert.ok(found.icon);
});
