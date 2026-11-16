import type {CheckSettings} from './connection-checks';
export function setupConnectionChecks(parent:HTMLElement){
 const section=document.createElement('section');section.className='backgroundbar';
 section.innerHTML='<h3>Connection ownership checks</h3><label><input type="checkbox" disabled> Periodically reverify established accelerated connections</label><p>Enabled by default. Turning this off reduces background work but later owner or executable changes may go undetected. Initial authorization, rule revocation, permission expiry, socket cleanup and Activity collection stay enabled. Applies to accelerated IPv4 UDP output connections; it does not change existing TCP admission policy. Checks already running may finish. Saved for this machine across daemon restarts.</p><button type="button">Refresh</button><button type="button" disabled>Save</button><p role="status"></p>';
 parent.append(section);const input=section.querySelector('input')!,[refresh,save]=section.querySelectorAll('button'),message=section.querySelector('[role=status]')!;
 let settings:CheckSettings|undefined,busy=false;
 const run=async(write=false)=>{if(busy)return;busy=true;input.disabled=save.disabled=refresh.disabled=true;
  try {const v=await window.flowgate.connectionChecks(write?{enabled:input.checked,expected_revision:settings?.revision}:undefined);settings=v.settings;if(settings)input.checked=settings.enabled;input.disabled=save.disabled=!v.writable||!settings;message.textContent=v.message;}
  catch(e){message.textContent=String(e)+' Refresh before editing.';settings=undefined;}
  finally{busy=false;refresh.disabled=false;}
 };
 refresh.onclick=()=>void run();save.onclick=()=>void run(true);void run();
}
