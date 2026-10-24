const {test}=require('node:test'),assert=require('node:assert/strict');
const {parseQueueHealth,queueHealthWarning}=require('../dist/test/queue-health.cjs');
const now=new Date().toISOString();
const admin={state:'pressure',sampled_at:now,counter_units:{deadline_rejections:'packets',netlink_overflow_notifications:'notifications'},sessions:[{generation:'a'.repeat(32),queue:101,direction:'both',started_at:now,counters:{deadline_rejections:'18446744073709551615',netlink_overflow_notifications:'2'},saturated:true,gauges:{active_workers:2,retained_packets:1}}]};
test('queue warning is connected-only and clears independently of cumulative totals',()=>{
 const h=parseQueueHealth(admin);assert.equal(h.sessions[0].counters.deadline_rejections,'18446744073709551615');
 const w=queueHealthWarning(true,h);assert.match(w.title,/2 notifications/);assert.match(w.title,/not confirmed kernel drops/);assert.match(w.title,/Accounting coverage gaps are separate/);
 assert.equal(queueHealthWarning(false,h),undefined);assert.equal(queueHealthWarning(true,{...h,state:'ready'}),undefined);assert.equal(queueHealthWarning(true,{...h,state:'inactive'}),undefined);assert.equal(parseQueueHealth(undefined),undefined);
});
test('ordinary queue health has no invented machine detail',()=>{
 const h=parseQueueHealth({state:'pressure',sampled_at:now});assert.equal(h.sessions,undefined);assert.match(queueHealthWarning(true,h).text,/Queue pressure/);
});
test('bad diagnostics never reject connection or imply readiness',()=>{
 for(const bad of [null,{}, {state:'future',sampled_at:now},{...admin,sessions:Array(9).fill(admin.sessions[0])},{...admin,sessions:[{...admin.sessions[0],counters:{deadline_rejections:3}}]},{...admin,sessions:[{...admin.sessions[0],counters:{deadline_rejections:'18446744073709551616'}}]},{...admin,sessions:[{...admin.sessions[0],gauges:{active_workers:-1}}]}]) assert.equal(parseQueueHealth(bad).state,'unavailable');
});

test('malformed JSON objects cannot invoke string coercion or inherit counter units',()=>{
 for (const raw of [{...admin,state:{toString:1}},{...admin,counter_units:{deadline_rejections:{toString:1}}},{...admin,sessions:[{...admin.sessions[0],direction:{toString:1}}]},{...admin,sessions:[{...admin.sessions[0],counters:{toString:'1'}}]}]) assert.equal(parseQueueHealth(raw).state,'unavailable');
});
