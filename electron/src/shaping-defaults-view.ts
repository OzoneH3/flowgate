import { DEFAULT_SHAPING, TRAFFIC_PRIORITIES, UPLOAD_RATE_UNITS, uploadRateBits, uploadRateValue, type ShapingDefaults, type UploadRateUnit, type TrafficPriority } from './upload-shaping';
import type { Preferences } from './protocol';

export function setupShapingDefaults(panel: Element, prefs: Preferences) {
  const defaults=prefs.shapingDefaults || DEFAULT_SHAPING;
  const box=document.createElement('fieldset');box.id='shapingDefaults';box.className='shaping-defaults';
  const legend=document.createElement('legend');legend.textContent='New rule defaults';box.append(legend);
  const priorityLabel=document.createElement('label');priorityLabel.textContent='Priority';
  const priority=document.createElement('select');priority.id='defaultPriority';priority.setAttribute('aria-label','Default priority');
  for(const p of TRAFFIC_PRIORITIES)priority.add(new Option(p[0].toUpperCase()+p.slice(1),p));
  priority.value=defaults.priority;priorityLabel.append(priority);box.append(priorityLabel);
  function rate(direction:'upload'|'download',label:string) {
    const row=document.createElement('label');row.textContent=label;
    const input=document.createElement('input');input.id=direction==='upload'?'defaultUploadLimit':'defaultDownloadLimit';input.type='text';input.inputMode='decimal';input.setAttribute('aria-label',`Default ${label}`);
    const units=document.createElement('select');units.setAttribute('aria-label',`Default ${label} units`);
    for(const unit of UPLOAD_RATE_UNITS)units.add(new Option(unit,unit));
    let unit=defaults[direction==='upload'?'uploadUnit':'downloadUnit'];units.value=unit;
    input.value=uploadRateValue(defaults[direction==='upload'?'uploadBits':'downloadBits'],unit);
    units.onchange=()=>{try{const bits=uploadRateBits(input.value,unit);unit=units.value as UploadRateUnit;input.value=uploadRateValue(bits,unit);message.textContent='';}catch(e){units.value=unit;message.textContent=String(e instanceof Error?e.message:e);}};
    row.append(input,units);box.append(row);
    return ()=>({bits:uploadRateBits(input.value,unit),unit});
  }
  const upload=rate('upload','UL limit'),download=rate('download','DL limit');
  const help=document.createElement('p');help.textContent='Starting values for new settings in any zone. Save each rule separately to apply it.';
  const save=document.createElement('button');save.id='saveShapingDefaults';save.textContent='Save defaults';
  const message=document.createElement('span');message.id='shapingDefaultsStatus';message.setAttribute('role','status');
  save.onclick=async()=>{
    try {
      const u=upload(),d=download();
      const shapingDefaults:ShapingDefaults={priority:priority.value as TrafficPriority,uploadBits:u.bits,uploadUnit:u.unit,downloadBits:d.bits,downloadUnit:d.unit};
      save.disabled=true;
      await window.flowgate.preferences({shapingDefaults});
      message.textContent='Defaults saved.';
    } catch(e) {message.textContent=String(e instanceof Error?e.message:e);}
    finally {save.disabled=false;}
  };
  box.append(help,save,message);panel.append(box);
}
