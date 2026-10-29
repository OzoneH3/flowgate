const {test}=require('node:test');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const {accountName}=require('../dist/test/account-lookup.cjs');
const {accountLabel,accountRowLabel}=require('../dist/test/accounts.cjs');
test('system NSS resolution is display only, validates UIDs and preserves unknown fallback',async()=>{
 const root=execFileSync('getent',['passwd','0'],{encoding:'utf8'}).split(':')[0];
 assert.equal(await accountName(0),root);
 assert.equal(await accountName(4294967294),null);
 for(const value of [-1,4294967296,'0',1.2,NaN,null])await assert.rejects(accountName(value),/Invalid UID/);
 assert.equal(accountLabel(4294967294),'UID 4294967294');
 assert.equal(accountRowLabel(4294967294),'User UID 4294967294');
 assert.equal(accountRowLabel(undefined),'Unknown account');
 assert.equal(accountRowLabel(0),'User UID 0');
});
test('resolved names include the numeric UID and trigger one display refresh',async()=>{
 let calls=0,events=0;
 global.window={flowgate:{accountName:async uid=>{calls++;return uid===12345?'test-account':null}},dispatchEvent:()=>events++};
 assert.equal(accountRowLabel(12345),'User UID 12345');
 await new Promise(resolve=>setImmediate(resolve));
 assert.equal(accountRowLabel(12345),'test-account (UID 12345)');
 assert.equal(accountLabel(12345),'test-account (UID 12345)');
 assert.equal(calls,1);assert.equal(events,1);
 delete global.window;
});
test('saved rules remain separate by UID when account names are displayed',async()=>{
 const {activityTree}=require('../dist/test/model.cjs');
 global.window={flowgate:{accountName:async uid=>({7001:'alice',7002:'service'}[uid]||null)},dispatchEvent:()=>{}};
 const rules=[7001,7002].map(uid=>({id:`rule-${uid}`,version:1,schema:2,action:'allow',priority:100,disabled:false,created:'',expires:'0001-01-01T00:00:00Z',executable:'/synthetic/tool',filter:{application:`app-${uid}`,revision:'r1',uid,direction:'outgoing',protocol:'*'}}));
 const first=activityTree({processes:{},rows:[]},rules)[0].children[0];
 assert.deepEqual(first.children.map(r=>r.presentationLabel),['User UID 7001','User UID 7002']);
 await new Promise(resolve=>setImmediate(resolve));
 const group=activityTree({processes:{},rows:[]},rules)[0].children[0];
 assert.deepEqual(group.children.map(r=>r.presentationLabel),['alice (UID 7001)','service (UID 7002)']);
 assert.deepEqual(group.children.map(r=>r.inactive.uid),[7001,7002]);
 assert.deepEqual(group.children.map(r=>r.inactive.key),['app-7001','app-7002']);
 delete global.window;
});
