const {test}=require('node:test');
const assert=require('node:assert/strict');
const {desktopGameExecutable}=require('../dist/test/desktop-game.cjs');
const {icoToPng}=require('../dist/test/icon-ico.cjs');
test('literal launcher shortcut resolves spaced executable without executing shell text',()=>{
 assert.equal(desktopGameExecutable(`bash -c '~/user_config/scripts/lwp /games/My\\ Game/Game.exe'`),'/games/My Game/Game.exe');
 for(const value of ['bash -c "$(bad) /games/A.exe"','lwp /games/A.exe; bad','lwp /games/A.exe /games/B.exe','lwp /games/../A.exe']) assert.equal(desktopGameExecutable(value),undefined);
});
test('bounded ICO DIB converts to PNG and invalid frame offsets are rejected',()=>{
 const ico=Buffer.alloc(22+48);ico.writeUInt16LE(1,2);ico.writeUInt16LE(1,4);
 ico[6]=1;ico[7]=1;ico.writeUInt32LE(48,14);ico.writeUInt32LE(22,18);
 ico.writeUInt32LE(40,22);ico.writeInt32LE(1,26);ico.writeInt32LE(2,30);ico.writeUInt16LE(1,34);ico.writeUInt16LE(32,36);
 ico[64]=255;ico[65]=255;
 const png=icoToPng(ico);assert.ok(png);assert.equal(png.toString('hex',0,8),'89504e470d0a1a0a');assert.equal(png.readUInt32BE(16),1);
 ico.writeUInt32LE(0xfffffff0,18);assert.equal(icoToPng(ico),undefined);
 assert.equal(icoToPng(Buffer.alloc(1024*1024+1)),undefined);
});

const {peIconToPng}=require('../dist/test/icon-pe.cjs');
function peFixture(wide=false){
 const d=Buffer.alloc(2048);d.write('MZ');d.writeUInt32LE(128,60);d.writeUInt32LE(0x4550,128);d.writeUInt16LE(1,134);
 const size=wide?240:224,opt=152,dirs=wide?112:96;d.writeUInt16LE(size,148);d.writeUInt16LE(wide?0x20b:0x10b,opt);d.writeUInt32LE(16,opt+dirs-4);d.writeUInt32LE(4096,opt+dirs+16);d.writeUInt32LE(512,opt+dirs+20);
 const sec=opt+size;d.writeUInt32LE(4096,sec+12);d.writeUInt32LE(512,sec+16);d.writeUInt32LE(512,sec+20);
 const b=512;function dir(at,es){d.writeUInt16LE(es.length,b+at+14);es.forEach(([id,target],i)=>{d.writeUInt32LE(id,b+at+16+i*8);d.writeUInt32LE(target>>>0,b+at+20+i*8)});}
 dir(0,[[3,0x80000020],[14,0x80000038]]);dir(32,[[1,0x80000050]]);dir(56,[[1,0x80000068]]);dir(80,[[1033,128]]);dir(104,[[1033,144]]);
 d.writeUInt32LE(4096+160,b+128);d.writeUInt32LE(48,b+132);d.writeUInt32LE(4096+208,b+144);d.writeUInt32LE(20,b+148);
 const dib=b+160;d.writeUInt32LE(40,dib);d.writeUInt32LE(1,dib+4);d.writeUInt32LE(2,dib+8);d.writeUInt16LE(1,dib+12);d.writeUInt16LE(32,dib+14);d[dib+42]=255;d[dib+43]=255;
 const g=b+208;d.writeUInt16LE(1,g+2);d.writeUInt16LE(1,g+4);d[g+6]=1;d[g+7]=1;d.writeUInt16LE(1,g+10);d.writeUInt16LE(32,g+12);d.writeUInt32LE(48,g+14);d.writeUInt16LE(1,g+18);return d;
}
test('PE32 and PE32+ exact icon resources decode without loading executable code',()=>{
 for(const wide of [false,true]){const p=peIconToPng(peFixture(wide));assert.ok(p);assert.equal(p.readUInt32BE(16),1);}
});
test('truncated, cyclic, oversized and unmapped PE resource offsets fail closed',()=>{
 const valid=peFixture();for(const n of [0,64,128,256,512,700])assert.equal(peIconToPng(valid.subarray(0,n)),undefined);
 const bad=peFixture();bad.writeUInt32LE(0x80000000,532);assert.equal(peIconToPng(bad),undefined);
 const outside=peFixture();outside.writeUInt32LE(0xffffffff,640);assert.equal(peIconToPng(outside),undefined);
});

const {versionName,peDisplayName,readPEResources}=require('../dist/test/icon-pe.cjs');
function versionNode(key,value='',children=[],binary=false){
 const k=Buffer.from(key+'\0','utf16le'),v=binary?Buffer.from(value):Buffer.from(value?value+'\0':'','utf16le');
 const align=n=>(n+3)&~3,at=align(6+k.length),first=align(at+v.length);
 let len=first;for(const c of children)len=align(len+c.length);
 const b=Buffer.alloc(len);b.writeUInt16LE(len);b.writeUInt16LE(binary?v.length:v.length/2,2);b.writeUInt16LE(binary?0:1,4);k.copy(b,6);v.copy(b,at);let off=first;for(const c of children){c.copy(b,off);off=align(off+c.length);}return b;
}
function versionResource(desc,product='Example Product'){
 return versionNode('VS_VERSION_INFO',Buffer.alloc(52),[versionNode('StringFileInfo','',[versionNode('040904B0','',[
 versionNode('FileDescription',desc),versionNode('ProductName',product)])])],true);
}
function versionPE(desc){
 const b=peFixture(),v=versionResource(desc);b.writeUInt16LE(1,512+14);b.writeUInt32LE(16,512+16);b.writeUInt32LE(0x80000038,512+20);
 b.writeUInt32LE(v.length,512+148);v.copy(b,512+208);b.writeUInt32LE(1024,152+96+20);b.writeUInt32LE(1024,152+224+16);return b;
}
test('version names prefer FileDescription, fall back to ProductName and preserve Unicode',()=>{
 assert.equal(versionName(versionResource('Friendly application')), 'Friendly application');
 assert.equal(versionName(versionResource('')), 'Example Product');
 assert.equal(versionName(versionResource('Éditeur 日本語')), 'Éditeur 日本語');
 assert.equal(versionName(versionResource('Bad\u202ename')), 'Example Product');
 assert.equal(peDisplayName(versionPE('Synthetic Beta')), 'Synthetic Beta');
});
test('version parser refuses truncated or oversized values and invalid tree lengths',()=>{
 const good=versionResource('Friendly');for(const n of [0,6,16,good.length-8])assert.equal(versionName(good.subarray(0,n)),undefined);
 const bad=Buffer.from(good);bad.writeUInt16LE(0);assert.equal(versionName(bad),undefined);
 assert.equal(versionName(versionResource('x'.repeat(300),'Fallback')), 'Fallback');
});
test('bounded resource reader handles large EXEs and metadata is revision-keyed',async(t)=>{
 const fs=require('fs'),path=require('path');const {ApplicationIcons,iconKey}=require('../dist/test/icons.cjs');
 const dir=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/pe-name-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const exe=path.join(dir,'test.exe');fs.writeFileSync(exe,versionPE('First name'));fs.chmodSync(exe,0o755);fs.truncateSync(exe,100*1024*1024);
 const resources=await readPEResources(exe);assert.ok(resources.length<100000);assert.equal(peDisplayName(resources),'First name');
 const icons=new ApplicationIcons(dir,[dir],[]);let app={key:'app',revision:'one',executable:exe,name:'test.exe'};
 const observe=()=>icons.observe({observation:{activity:{rows:[],processes:{p:{application:app}}}},control:{events:[],rules:[]}});observe();
 assert.equal((await icons.metadata([iconKey(app)]))[iconKey(app)].name,'First name');
 fs.writeFileSync(exe,versionPE('Second name'));app={...app,revision:'two'};observe();
 assert.equal((await icons.metadata([iconKey(app)]))[iconKey(app)].name,'Second name');
 assert.equal((await icons.metadata(['not-authorized']))['not-authorized'].name,undefined);
});

test('Flatpak names require exact deployment metadata and remain display-only',async(t)=>{
 const fs=require('fs'),path=require('path');const {ApplicationIcons,iconKey,flatpakDisplayName}=require('../dist/test/icons.cjs');
 const root=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/flatpak-names-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 function fixture(id,name,commit='a'.repeat(64)){
  const deployment=path.join(root,'app',id,'x86_64','stable',commit),exe=path.join(deployment,'files/bin/runner');
  fs.mkdirSync(path.dirname(exe),{recursive:true});fs.writeFileSync(exe,'synthetic');
  fs.writeFileSync(path.join(deployment,'metadata'),`[Application]\nname=${id}\nruntime=example\n\n[Context]\nshared=network;\n`);
  const desktop=path.join(deployment,'files/share/applications',id+'.desktop');fs.mkdirSync(path.dirname(desktop),{recursive:true});
  fs.writeFileSync(desktop,`[Desktop Entry]\nType=Application\nName=${name}\nExec=runner\n`);return {exe,deployment,desktop};
 }
 const a=fixture('org.example.First','Friendly First'),b=fixture('org.example.Second','Friendly Second');
 assert.equal(await flatpakDisplayName(a.exe),'Friendly First');assert.equal(await flatpakDisplayName(b.exe),'Friendly Second');
 const icons=new ApplicationIcons(root,[root],[]),app={key:'exact-first',revision:'revision',kind:'native',name:'runner',executable:'/app/bin/runner',host_executable:a.exe};
 icons.observe({observation:{activity:{rows:[],processes:{p:{application:app}}}},control:{events:[],rules:[]}});
 assert.equal((await icons.metadata([iconKey(app)]))[iconKey(app)].name,'Friendly First');assert.equal(app.name,'runner');assert.equal(app.key,'exact-first');
 const rule={executable:app.executable,filter:{application:app.key,revision:app.revision}};
 const withRule=new ApplicationIcons(root,[root],[]);
 withRule.observe({observation:{activity:{rows:[],processes:{p:{application:app}}}},control:{events:[],rules:[rule]}});
 assert.equal((await withRule.metadata([iconKey(app)]))[iconKey(app)].name,'Friendly First','stored rule must not erase live backing-file metadata');
 assert.equal((await icons.metadata(['unauthorized']))['unauthorized'].name,undefined);
 const plain={...app,key:'no-backing',host_executable:undefined};icons.observe({observation:{activity:{rows:[],processes:{p:{application:plain}}}},control:{events:[],rules:[]}});
 assert.equal((await icons.metadata([iconKey(plain)]))[iconKey(plain)].name,undefined);
 fs.writeFileSync(path.join(a.deployment,'metadata'),'[Application]\nname=org.example.Second\n');assert.equal(await flatpakDisplayName(a.exe),undefined);
 fs.unlinkSync(b.desktop);fs.symlinkSync(a.desktop,b.desktop);assert.equal(await flatpakDisplayName(b.exe),undefined);
 const revised=fixture('org.example.First','New deployment','b'.repeat(64));assert.equal(await flatpakDisplayName(revised.exe),'New deployment');
 fs.writeFileSync(revised.desktop,'[Desktop Entry]\nType=Application\nName=Bad\u202ename\n');assert.equal(await flatpakDisplayName(revised.exe),undefined);
});
