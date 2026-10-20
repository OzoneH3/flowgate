import { icoToPng } from './icon-ico';
// Read-only PE resources, never LoadLibrary/execute. Format reference:
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
export function peIconToPng(data: Buffer): Buffer | undefined {
  try {
    if (data.length > 64 * 1024 * 1024 || data.toString('ascii',0,2)!=='MZ') return;
    const pe=data.readUInt32LE(60);
    if(data.readUInt32LE(pe)!==0x4550) return;
    const count=data.readUInt16LE(pe+6), size=data.readUInt16LE(pe+20), opt=pe+24;
    if(!count || count>96) return;
    const magic=data.readUInt16LE(opt), dirs=magic===0x10b?96:magic===0x20b?112:0;
    if(!dirs || size<dirs+24 || data.readUInt32LE(opt+dirs-4)<3) return;
    const rva=data.readUInt32LE(opt+dirs+16), resourceSize=data.readUInt32LE(opt+dirs+20);
    if(!rva || resourceSize>16*1024*1024) return;
    function map(address:number,length:number):number {
      for(let i=0;i<count;i++){
        const s=opt+size+i*40, va=data.readUInt32LE(s+12), bytes=data.readUInt32LE(s+16), raw=data.readUInt32LE(s+20);
        const delta=address-va;
        if(delta>=0 && delta+length<=bytes && raw+delta+length<=data.length) return raw+delta;
      }
      throw Error('Unmapped PE resource');
    }
    const base=map(rva,resourceSize);
    function within(at:number,n:number){if(at<0 || at+n>resourceSize)throw Error('Resource bounds');return base+at;}
    function entries(at:number){
      const p=within(at,16), n=data.readUInt16LE(p+12)+data.readUInt16LE(p+14);
      if(n>512)throw Error('Resource entry limit');within(at+16,n*8);
      return Array.from({length:n},(_,i)=>({id:data.readUInt32LE(p+16+i*8),target:data.readUInt32LE(p+20+i*8)}));
    }
    function dir(target:number){if(!(target&0x80000000))throw Error('Expected resource directory');return entries(target&0x7fffffff);}
    function blob(target:number){
      if(target&0x80000000)throw Error('Expected resource data');const p=within(target,16);
      const addr=data.readUInt32LE(p),len=data.readUInt32LE(p+4);
      if(!len||len>1024*1024)throw Error('Icon size limit');return data.subarray(map(addr,len),map(addr,len)+len);
    }
    const roots=entries(0),groups=roots.find(x=>x.id===14),icons=roots.find(x=>x.id===3);
    if(!groups||!icons)return;
    const images=dir(icons.target);
    for(const group of dir(groups.target).slice(0,16)) for(const lang of dir(group.target).slice(0,16)){
      const g=blob(lang.target);if(g.length<6||g.readUInt16LE(0)!==0||g.readUInt16LE(2)!==1)continue;
      const n=g.readUInt16LE(4);if(!n||n>256||6+n*14>g.length)continue;
      const frames=[];
      for(let i=0;i<n;i++){
        const at=6+i*14,id=g.readUInt16LE(at+12),image=images.find(x=>x.id===id);if(!image)continue;
        const langs=dir(image.target),chosen=langs.find(x=>x.id===lang.id)||langs[0];if(!chosen)continue;
        const bytes=blob(chosen.target);if(bytes.length!==g.readUInt32LE(at+8))continue;
        const ico=Buffer.alloc(22+bytes.length);ico.writeUInt16LE(1,2);ico.writeUInt16LE(1,4);
        g.copy(ico,6,at,at+12);ico.writeUInt32LE(22,18);bytes.copy(ico,22);
        frames.push({width:g[at]||256,ico});
      }
      frames.sort((a,b)=>Math.abs(a.width-32)-Math.abs(b.width-32));
      for(const frame of frames){const png=icoToPng(frame.ico);if(png)return png;}
    }
  } catch { /* Invalid/unsupported resources use the neutral icon. */ }
}
