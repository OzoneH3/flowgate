const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const { placementScript, PROMPT_TITLE, promptTitle } = require('../dist/test/prompt-placement.cjs');
test('KDE placement only touches own PID and fixed permission caption', () => {
  const desired = { x: 2040, y: 980, width: 520, height: 460 };
  const windows = [
    { pid: 42, caption: promptTitle(7) },
    { pid: 43, caption: promptTitle(7) },
    { pid: 42, caption: promptTitle(8) },
    { pid: 42, caption: 'FlowGate' },
    { pid: 42, caption: 'Firefox' },
  ];
  const workspace = { windowList: () => windows };
  vm.runInNewContext(placementScript(42, 7, desired), {
    workspace,
    print: () => {},
  });
  assert.deepEqual({ ...windows[0].frameGeometry }, desired);
  assert.equal(workspace.activeWindow, undefined);
  for (const w of windows.slice(1)) assert.equal(w.frameGeometry, undefined);
  assert.throws(() => placementScript(-1, 7, desired));
  assert.throws(() => placementScript(42, 7, { ...desired, x: NaN }));
});
test('KDE configured priority overrides Electron output order and uses that output workarea', () => {
  const { primaryOutputName } = require('../dist/test/prompt-placement.cjs');
  assert.equal(
    primaryOutputName({
      outputs: [
        { name: 'DP-3', priority: 2, connected: true },
        { name: 'DP-2', priority: 1, connected: true },
      ],
    }),
    'DP-2',
  );
  assert.equal(
    primaryOutputName({
      outputs: [
        { name: 'disabled', priority: 0, connected: true },
        { name: 'missing', priority: 1, connected: false },
      ],
    }),
    undefined,
  );
  const w = { pid: 42, caption: promptTitle(7) },
    output = { name: 'DP-2' };
  const workspace = {
    windowList: () => [w],
    screens: [{ name: 'DP-3' }, output],
    sendClientToScreen: (window, o) => assert.equal(o, output),
    currentDesktopForScreen: () => 1,
    clientArea: () => ({ x: 2560, y: 0, width: 2560, height: 1392 }),
  };
  vm.runInNewContext(placementScript(42, 7, { x: 2040, y: 980, width: 520, height: 460 }, 'DP-2'), {
    workspace,
    KWin: { PlacementArea: 0 },
    print: () => {},
  });
  assert.deepEqual({ ...w.frameGeometry }, { x: 4600, y: 932, width: 520, height: 460 });
});

test('startup handshake on KWin 6.6 waits for native configure and reveals without activation', () => {
  const { placementQML } = require('../dist/test/prompt-placement.cjs');
  const qml = placementQML(42, 7, { x: 0, y: 0, width: 520, height: 460 }, 'primary');
  const body = qml.slice(
    qml.indexOf('  function tick() {') + '  function tick() {'.length,
    qml.lastIndexOf('\n  }'),
  );
  const output = { name: 'primary' },
    other = { name: 'secondary' };
  let requested,
    focused = 0,
    stopped = 0;
  const w = {
    pid: 42,
    caption: promptTitle(7),
    internalId: 'native-A',
    output: other,
    opacity: 0,
    setMaximize() {},
    get frameGeometry() {
      return this.actual;
    },
    set frameGeometry(v) {
      requested = v;
    },
    actual: { x: 0, y: 0, width: 1280, height: 848 },
  };
  const state = {
    ticks: 0,
    nativeID: null,
    previous: '',
    stable: 0,
    applied: 0,
    waited: 0,
    confirmed: 0,
  };
  const workspace = {
    stackingOrder: [w, { ...w, pid: 43 }],
    screens: [other, output],
    sendClientToScreen(win, o) {
      win.output = o;
    },
    currentDesktop: { id: 'desktop-1' },
    clientArea(_kind, _output, desktop) {
      assert.equal(desktop, workspace.currentDesktop);
      return { x: 2000, y: 30, width: 900, height: 570 };
    },
    set activeWindow(v) {
      assert.equal(v, w);
      focused++;
    },
  };
  const context = vm.createContext({
    state,
    target: w,
    workspace,
    clock: {
      stop() {
        stopped++;
      },
    },
    KWin: { PlacementArea: 0 },
    console: { log() {} },
  });
  const tick = () => vm.runInContext(`(function(){${body}})()`, context);
  for (let i = 0; i < 5; i++) tick();
  assert.equal(w.opacity, 0);
  assert.equal(focused, 0);
  assert(requested);
  // Requested setBounds is NOT proof; native actual frame remains the restored main size.
  assert.equal(state.confirmed, 0);
  w.actual = { ...requested };
  for (let i = 0; i < 3; i++) tick();
  assert.equal(w.opacity, 1);
  assert.equal(w.keepAbove, true);
  assert.equal(focused, 0);
  assert.equal(stopped, 1);
  assert.deepEqual({ ...w.actual }, { x: 2380, y: 140, width: 520, height: 460 });
  assert.match(qml, /windowAdded.connect/);
  assert.match(qml, /windowAdded.disconnect/);
});
test('handshake rejects native-window replacement', () => {
  const { placementQML } = require('../dist/test/prompt-placement.cjs');
  const qml = placementQML(42, 7, { x: 0, y: 0, width: 520, height: 460 }, 'primary');
  const body = qml.slice(
    qml.indexOf('  function tick() {') + '  function tick() {'.length,
    qml.lastIndexOf('\n  }'),
  );
  const output = { name: 'primary' },
    w = { pid: 42, caption: promptTitle(7), internalId: 'new-native', output };
  let stopped = false;
  const context = vm.createContext({
    state: { ticks: 0, nativeID: 'old-native' },
    workspace: { stackingOrder: [w] },
    clock: {
      stop() {
        stopped = true;
      },
    },
  });
  vm.runInContext(`(function(){${body}})()`, context);
  assert.equal(stopped, true);
  assert.equal(w.opacity, undefined);
});

test('fullscreen primary redirects only the permission window to a free secondary output', () => {
  const primary={name:'DP-1'},secondary={name:'DP-2'};
  const desktop={id:1},otherDesktop={id:2};
  const run=(over={},screens=[primary,secondary],extra=[],perOutput=true)=>{
    const permission={pid:42,caption:promptTitle(7)};
    const game={pid:99,caption:'Synthetic fullscreen',fullScreen:true,minimized:false,output:primary,desktops:[desktop],...over};
    let target;
    const workspace={screens,windowList:()=>[permission,game,...extra],currentDesktop:desktop,
      ...(perOutput ? {currentDesktopForScreen:()=>desktop} : {}),
      sendClientToScreen:(w,output)=>{assert.equal(w,permission);target=output;},
      clientArea:(_kind,output,currentDesktop)=>{
        assert.equal(currentDesktop,desktop);
        return output===primary?{x:0,y:0,width:1920,height:1080}:{x:1920,y:0,width:1600,height:900};
      }};
    vm.runInNewContext(placementScript(42,7,{x:1400,y:620,width:520,height:460},'DP-1'),{workspace,KWin:{PlacementArea:0},print:()=>{}});
    assert.equal(game.frameGeometry,undefined,'fullscreen application is never moved');
    assert.equal(workspace.activeWindow,undefined,'placement does not request activation');
    return {permission,target};
  };
  const redirected=run();
  assert.equal(redirected.target,secondary);
  assert.deepEqual({...redirected.permission.frameGeometry},{x:3000,y:440,width:520,height:460});
  assert.equal(run({},[primary,secondary],[],false).target,secondary,'KWin 6.6 uses its shared desktop for fullscreen routing');
  assert.equal(run({desktops:[otherDesktop]},[primary,secondary],[],false).target,primary);
  assert.equal(run({fullScreen:false}).target,primary);
  assert.equal(run({minimized:true}).target,primary);
  assert.equal(run({desktops:[otherDesktop]}).target,primary);
  assert.equal(run({output:secondary}).target,primary);
  assert.equal(run({},[primary]).target,primary);
  assert.equal(run({},[primary,secondary],[{pid:100,fullScreen:true,output:secondary}]).target,primary,'no free secondary preserves primary fallback');
});

test('startup handshake uses fullscreen routing while awaiting native geometry confirmation', () => {
  const {placementQML}=require('../dist/test/prompt-placement.cjs');
  const qml=placementQML(42,7,{x:0,y:0,width:520,height:460},'DP-1');
  const body=qml.slice(qml.indexOf('  function tick() {')+'  function tick() {'.length,qml.lastIndexOf('\n  }'));
  const primary={name:'DP-1'},secondary={name:'DP-2'};
  const permission={pid:42,caption:promptTitle(7),internalId:'one',output:primary,opacity:0,setMaximize(){},frameGeometry:{x:0,y:0,width:1280,height:800}};
  const game={pid:99,fullScreen:true,output:primary};
  const state={ticks:0,nativeID:null,previous:'',stable:0,applied:0,waited:0,confirmed:0};
  const workspace={screens:[primary,secondary],stackingOrder:[permission,game],currentDesktopForScreen:()=>1,
    sendClientToScreen:(w,output)=>{w.output=output;},clientArea:()=>({x:1920,y:0,width:1600,height:900})};
  const context=vm.createContext({state,target:permission,workspace,clock:{stop(){}},KWin:{PlacementArea:0},console:{log(){}}});
  vm.runInContext(`(function(){${body}})()`,context);
  game.fullScreen=false; // Alt-tab during the asynchronous startup handshake.
  for(let i=0;i<12;i++)vm.runInContext(`(function(){${body}})()`,context);
  assert.equal(permission.output,secondary);
  assert.equal(permission.opacity,1);
  assert.equal(workspace.activeWindow,undefined);
});

test('borderless output-covering windows redirect without treating normal maximized windows as fullscreen', () => {
  const primary={name:'DP-1',geometry:{x:0,y:0,width:1920,height:1080}},secondary={name:'DP-2',geometry:{x:1920,y:0,width:1920,height:1080}};
  const run=(frame,over={},primaryName='DP-1')=>{
    const permission={pid:42,caption:promptTitle(7)};
    const game={pid:100,output:primary,fullScreen:false,normalWindow:true,noBorder:true,frameGeometry:frame,...over};
    let selected;
    const workspace={screens:[primary,secondary],windowList:()=>[permission,game],currentDesktopForScreen:()=>1,
      sendClientToScreen:(w,o)=>{assert.equal(w,permission);selected=o;},clientArea:(_k,o)=>o.geometry};
    vm.runInNewContext(placementScript(42,7,{x:0,y:0,width:520,height:460},primaryName),{workspace,KWin:{PlacementArea:0},print(){}});
    return selected;
  };
  assert.equal(run({...primary.geometry}),secondary);
  assert.equal(run({...primary.geometry},{},''),secondary,'discovery failure still uses fullscreen-aware routing');
  assert.equal(run({...primary.geometry},{},'missing-output'),secondary,'removed configured output has a usable fallback');
  assert.equal(run({x:0,y:30,width:1920,height:1050}),primary,'maximized workarea leaves panel space');
  assert.equal(run({...primary.geometry},{noBorder:false}),primary);
  assert.equal(run({...primary.geometry},{normalWindow:false}),primary,'panel/desktop surfaces are excluded');
  assert.equal(run({...primary.geometry},{minimized:true}),primary);
});


test('reused popup stays on secondary after alt-tab, but recovers when output disconnects', () => {
  const primary={name:'DP-1',geometry:{x:0,y:0,width:1920,height:1080}};
  const secondary={name:'DP-2',geometry:{x:1920,y:0,width:1600,height:900}};
  const permission={pid:42,caption:promptTitle(7),output:primary};
  const game={pid:99,fullScreen:true,output:primary};
  const workspace={screens:[primary,secondary],windowList:()=>[permission,game],
    currentDesktopForScreen:()=>1, clientArea:(_k,o)=>o.geometry,
    sendClientToScreen:(w,o)=>{w.output=o;}};
  const resize=(height=460)=>vm.runInNewContext(
    placementScript(42,7,{x:0,y:0,width:520,height},'DP-1',true),
    {workspace,KWin:{PlacementArea:0},print(){}});
  resize();
  assert.equal(permission.output,secondary,'warm popup moves away from fullscreen primary');
  game.fullScreen=false;
  game.minimized=true;
  resize(650);
  assert.equal(permission.output,secondary,'expanding Details after alt-tab retains output');
  assert.deepEqual({...permission.frameGeometry},{x:3000,y:250,width:520,height:650});
  resize();
  assert.equal(permission.output,secondary,'next compact request retains output');
  workspace.screens=[primary];
  resize();
  assert.equal(permission.output,primary,'disconnected output falls back to available primary');
});
