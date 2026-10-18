const {test}=require('node:test'), assert=require('node:assert/strict');
const {TrafficGraph}=require('../dist/test/graph.cjs');
const {chartDefaults}=require('../dist/test/pane-model.cjs');
test('unchanged presentation never repaints; same-frame changes coalesce without changing history',()=>{
 const prior={document:global.document,raf:global.requestAnimationFrame};const scheduled=[];
 global.document={hidden:false};global.requestAnimationFrame=fn=>(scheduled.push(fn),scheduled.length);
 try {
  const g=Object.create(TrafficGraph.prototype);Object.assign(g,{settings:chartDefaults(),host:{hidden:false},unit:'autoByte',source:'tcp',selector:{},sync(){},view:{points:[{at:1}]}});
  let paints=0;g.paintNow=()=>paints++;
  g.setPresentation(chartDefaults());assert.equal(scheduled.length,0);
  g.setUnit('autoBit');g.setSource('udp');g.setPresentation({...chartDefaults(),download:false});assert.equal(scheduled.length,1);
  scheduled.shift()();assert.equal(paints,1);assert.equal(g.view.points[0].at,1);
  g.setPresentation({...chartDefaults(),download:false});assert.equal(scheduled.length,0);
  global.document.hidden=true;g.setUnit('autoByte');assert.equal(scheduled.length,0);
 }finally{global.document=prior.document;global.requestAnimationFrame=prior.raf;}
});
