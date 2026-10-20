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
