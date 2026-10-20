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
