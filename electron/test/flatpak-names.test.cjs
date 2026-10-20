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
