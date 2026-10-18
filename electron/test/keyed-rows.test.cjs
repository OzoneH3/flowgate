const {test}=require('node:test'),assert=require('node:assert/strict');
const {replaceKeyedRow}=require('../dist/test/keyed-rows.cjs');
test('one invalidated row does not move every following sibling (controlled negative case)',()=>{
 function reconcile(inPlace){
  const nodes=Array.from({length:1000},(_,id)=>({id})),body=[...nodes];let moves=0;
  const previous=nodes[1], next={id:1};previous.replaceWith=n=>body.splice(body.indexOf(previous),1,n);
  if(inPlace)replaceKeyedRow(previous,next);
  const ordered=[nodes[0],next,...nodes.slice(2)];
  for(let i=0;i<ordered.length;i++)if(body[i]!==ordered[i]){
   const index=body.indexOf(ordered[i]);if(index>=0)body.splice(index,1);body.splice(i,0,ordered[i]);moves++;
  }
  while(body.length>ordered.length)body.pop();assert.deepEqual(body,ordered);return moves;
 }
 assert(reconcile(false)>900,'negative control reproduces the displaced-sibling race');
 assert.equal(reconcile(true),0);
});
