const {test}=require('node:test'),assert=require('node:assert/strict');
const {parseQueueHealth,queueHealthNow,queueHealthWarning}=require('../dist/test/queue-health.cjs');
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
test('queue diagnostics distinguish recent causes, session totals and live recovery', () => {
 const key = 'attribution_capacity_rejections';
 const raw = {...admin, counter_units: {...admin.counter_units, [key]: 'packets'}, sessions: [{
   ...admin.sessions[0], counters: {[key]: '2332'}, recent_counters: {[key]: '4'}, last_admission_mask: 1,
   gauges: {attribution_packets: 0, retained_packets: 0, active_workers: 0},
 }]};
 const snapshot = parseQueueHealth(raw);
 const warning = queueHealthWarning(true, snapshot);
 assert.match(warning.title, /At sample: No packets in owner lookup or held for a decision/);
 assert.match(warning.title, /About the last 30 seconds\nOwner lookup capacity reached before a rule decision: 4 packets\nLatest owner lookup rejection: per-endpoint limit/);
 assert.match(warning.title, /Recorded totals since this queue started/);
 assert.match(warning.title, new RegExp(BigInt(2332).toLocaleString()));
 assert.match(queueHealthNow(true, {...snapshot, state: 'ready'}), /No queue rejections or I\/O issues in the last 30 seconds/);
 assert.match(queueHealthNow(false, snapshot), /disconnected/);
 assert.match(queueHealthWarning(true, parseQueueHealth(admin)).title, /recent count by cause is unavailable/);
 raw.sessions[0].recent_counters[key] = '2333';
 assert.equal(parseQueueHealth(raw).state, 'unavailable');
});
test('daemon first-proof totals coexist with numeric queue gauges', () => {
 const raw = {...admin, state: 'ready', sessions: [{...admin.sessions[0], gauges: {
   active_workers: 0, first_proof_history_rows: 9, first_proof_admissions: '18446744073709551615',
   first_proof_denied_tails_reclaimed: '0', first_proof_history_evictions: '0',
   first_proof_history_full_observations: '0',
 }}]};
 const ready = parseQueueHealth(raw);
 assert.equal(ready.state, 'ready');
 assert.equal(ready.sessions[0].gauges.first_proof_admissions, '18446744073709551615');
 assert.equal(queueHealthWarning(true, ready), undefined);
 raw.sessions[0].gauges.first_proof_admissions = '18446744073709551616';
 assert.match(queueHealthWarning(true, parseQueueHealth(raw)).title, /GUI could not read/);
 assert.match(queueHealthWarning(true, parseQueueHealth({state:'unavailable',sampled_at:now})).title, /daemon reports/);
});
test('bad diagnostics never reject connection or imply readiness',()=>{
 for(const bad of [null,{}, {state:'future',sampled_at:now},{...admin,sessions:Array(9).fill(admin.sessions[0])},{...admin,sessions:[{...admin.sessions[0],counters:{deadline_rejections:3}}]},{...admin,sessions:[{...admin.sessions[0],counters:{deadline_rejections:'18446744073709551616'}}]},{...admin,sessions:[{...admin.sessions[0],gauges:{active_workers:-1}}]}]) assert.equal(parseQueueHealth(bad).state,'unavailable');
});

test('malformed JSON objects cannot invoke string coercion or inherit counter units',()=>{
 for (const raw of [{...admin,state:{toString:1}},{...admin,counter_units:{deadline_rejections:{toString:1}}},{...admin,sessions:[{...admin.sessions[0],direction:{toString:1}}]},{...admin,sessions:[{...admin.sessions[0],counters:{toString:'1'}}]}]) assert.equal(parseQueueHealth(raw).state,'unavailable');
});
