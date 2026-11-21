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


test('fallback artwork distinguishes installed services, CLI tools and desktop apps without changing identity',async(t)=>{
 const fs=require('fs'),path=require('path');const {ApplicationIcons,iconKey}=require('../dist/test/icons.cjs');
 const root=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/fallback-icons-'));t.after(()=>fs.rmSync(root,{recursive:true,force:true}));
 const bin=path.join(root,'bin'),desktop=path.join(root,'applications'),units=path.join(root,'units');
 for(const dir of [bin,desktop,units])fs.mkdirSync(dir);
 const make=(name)=>{const executable=path.join(bin,name);fs.writeFileSync(executable,'#!/bin/sh\nexit 0\n');fs.chmodSync(executable,0o755);return {key:name,revision:'r',name,kind:'native',executable};};
 const service=make('worker'),cli=make('command'),gui=make('desktop'),terminal=make('console'),windows=make('unknown.exe');
 fs.writeFileSync(path.join(units,'worker.service'),`[Unit]\nDescription=Synthetic\n[Service]\nExecStart=${service.executable} --listen\n`);
 fs.writeFileSync(path.join(desktop,'desktop.desktop'),`[Desktop Entry]\nType=Application\nName=Desktop\nExec=${gui.executable}\nTerminal=false\n`);
 fs.writeFileSync(path.join(desktop,'console.desktop'),`[Desktop Entry]\nType=Application\nName=Console\nExec=${terminal.executable}\nTerminal=true\n`);
 const icons=new ApplicationIcons(root,[root],[bin],[],[units]);
 const apps=[service,cli,gui,terminal,windows];
 icons.observe({observation:{activity:{rows:[],processes:Object.fromEntries(apps.map(a=>[a.key,{application:a}]))}},control:{events:[],rules:[]}});
 const before=JSON.stringify(apps),metadata=await icons.metadata(apps.map(iconKey));
 assert.equal(metadata[iconKey(service)].fallback,'service');
 assert.equal(metadata[iconKey(cli)].fallback,'terminal');
 assert.equal(metadata[iconKey(terminal)].fallback,'terminal');
 assert.equal(metadata[iconKey(gui)].fallback,undefined,'desktop app lacking artwork is not labelled CLI');
 assert.equal(metadata[iconKey(windows)].fallback,undefined,'unknown Windows executable is not classified from a native path');
 assert.equal((await icons.metadata(['unauthorized']))['unauthorized'].fallback,undefined);
 assert.equal(JSON.stringify(apps),before,'artwork metadata cannot alter permission identities');
});

test('24-bit icon rows use DWORD padding and the transparency mask',()=>{
 const {inflateSync}=require('node:zlib');
 const width=3,height=2,stride=12,maskStride=4;
 const ico=Buffer.alloc(22+40+(stride+maskStride)*height);
 ico.writeUInt16LE(1,2);ico.writeUInt16LE(1,4);ico[6]=width;ico[7]=height;
 ico.writeUInt32LE(ico.length-22,14);ico.writeUInt32LE(22,18);
 ico.writeUInt32LE(40,22);ico.writeInt32LE(width,26);ico.writeInt32LE(height*2,30);ico.writeUInt16LE(1,34);ico.writeUInt16LE(24,36);
 // Bottom row blue; top row red. Padding is not pixel data or alpha.
 for(let x=0;x<3;x++){ico[62+x*3]=255;ico[62+stride+x*3+2]=255;}
 ico.fill(123,71,74);ico[62+stride*height+maskStride]=0x40;
 const png=icoToPng(ico);assert.ok(png);
 let pos=8,data;
 while(pos<png.length){const size=png.readUInt32BE(pos);if(png.toString('ascii',pos+4,pos+8)==='IDAT')data=inflateSync(png.subarray(pos+8,pos+8+size));pos+=size+12;}
 assert.deepEqual([...data.subarray(1,13)],[255,0,0,255,255,0,0,0,255,0,0,255]);
 assert.deepEqual([...data.subarray(14,18)],[0,0,255,255]);
 assert.equal(icoToPng(ico.subarray(0,ico.length-1)),undefined);
 ico.writeUInt16LE(16,36);assert.equal(icoToPng(ico),undefined);
});

test('read-only Windows images need no Unix execute bit; missing files retry',async(t)=>{
 const fs=require('node:fs'),path=require('node:path');const {ApplicationIcons,iconKey}=require('../dist/test/icons.cjs');
 const home=fs.mkdtempSync(path.resolve(__dirname,'../../.workspace/readonly-pe-'));t.after(()=>fs.rmSync(home,{recursive:true,force:true}));
 let now=1000;const icons=new ApplicationIcons(home,[home],[],[],[],()=>now);
 const apps=['Alpha','Beta'].map((name,i)=>({key:name,revision:'r'+i,name,executable:path.join(home,name+'.exe')}));
 icons.observe({observation:{activity:{processes:{},rows:[]}},control:{events:[],rules:apps.map(a=>({executable:a.executable,filter:{application:a.key,revision:a.revision,uid:1000}}))}});
 assert.equal((await icons.metadata(apps.map(iconKey)))[iconKey(apps[0])].icon,null);
 for(const a of apps)fs.writeFileSync(a.executable,peFixture(),{mode:0o644});
 now+=30001;
 for(const a of apps)assert.ok((await icons.metadata([iconKey(a)]))[iconKey(a)].icon);
 assert.equal((await icons.request(['not-allowed']))['not-allowed'],null);
});

test('paletted ICO frames decode packed pixels, row padding and AND transparency', () => {
  const { inflateSync } = require('node:zlib');
  for (const bits of [1, 4, 8]) {
    const paletteSize = 2;
    const ico = Buffer.alloc(22 + 40 + paletteSize * 4 + 16);
    ico.writeUInt16LE(1, 2);
    ico.writeUInt16LE(1, 4);
    ico[6] = 3;
    ico[7] = 2;
    ico.writeUInt32LE(ico.length - 22, 14);
    ico.writeUInt32LE(22, 18);
    const dib = ico.subarray(22);
    dib.writeUInt32LE(40, 0);
    dib.writeInt32LE(3, 4);
    dib.writeInt32LE(4, 8);
    dib.writeUInt16LE(1, 12);
    dib.writeUInt16LE(bits, 14);
    // A zero colors-used field selects the format's full palette.
    if (bits !== 1) dib.writeUInt32LE(paletteSize, 32);
    dib[40] = 255;
    dib[46] = 255;
    const setRow = (offset, indices) => indices.forEach((index, x) => {
      dib[offset + ((x * bits) >> 3)] |= index << (8 - bits - ((x * bits) & 7));
    });
    setRow(48, [0, 1, 0]);
    setRow(52, [1, 0, 1]);
    dib[60] = 0x40;
    const png = icoToPng(ico);
    assert.ok(png, `${bits}-bit icon`);
    const length = png.readUInt32BE(33);
    assert.equal(png.toString('ascii', 37, 41), 'IDAT');
    const pixels = inflateSync(png.subarray(41, 41 + length));
    assert.deepEqual([...pixels], [
      0, 255, 0, 0, 255, 0, 0, 255, 0, 255, 0, 0, 255,
      0, 0, 0, 255, 255, 255, 0, 0, 255, 0, 0, 255, 255,
    ]);
    assert.equal(icoToPng(ico.subarray(0, -1)), undefined);
    if (bits !== 1) {
      dib[48] = 2 << (8 - bits);
      assert.equal(icoToPng(ico), undefined);
    }
  }
});
