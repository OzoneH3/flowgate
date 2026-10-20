import fs from 'node:fs/promises';
import { icoToPng } from './icon-ico';
// Read-only PE resources. https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
function peResources(data: Buffer) {
    if (data.length > 64 * 1024 * 1024 || data.toString('ascii',0,2)!=='MZ') throw Error('Invalid PE');
    const pe=data.readUInt32LE(60);
    if(data.readUInt32LE(pe)!==0x4550) throw Error('Invalid PE');
    const count=data.readUInt16LE(pe+6), size=data.readUInt16LE(pe+20), opt=pe+24;
    if(!count || count>96) throw Error('Invalid PE');
    const magic=data.readUInt16LE(opt), dirs=magic===0x10b?96:magic===0x20b?112:0;
    if(!dirs || size<dirs+24 || data.readUInt32LE(opt+dirs-4)<3) throw Error('Invalid PE');
    const rva=data.readUInt32LE(opt+dirs+16), resourceSize=data.readUInt32LE(opt+dirs+20);
    if(!rva || resourceSize>16*1024*1024) throw Error('Invalid PE');
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
    return {roots:entries(0),dir,blob};
}
export function peIconToPng(data: Buffer): Buffer | undefined {
  try {
    const {roots,dir,blob}=peResources(data),groups=roots.find(x=>x.id===14),icons=roots.find(x=>x.id===3);
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

// VERSIONINFO strings are display metadata only, never permission authority.
// https://learn.microsoft.com/en-us/windows/win32/menurc/versioninfo-resource
export function versionName(data: Buffer): string | undefined {
  try {
    let budget=128;
    const fields=new Map<string,string>();
    const align=(n:number)=>(n+3)&~3;
    function node(at:number,limit:number,keys:string[]):number {
      if(--budget<0||keys.length>4||at+6>limit)throw Error('Version bounds');
      const len=data.readUInt16LE(at),n=data.readUInt16LE(at+2),type=data.readUInt16LE(at+4),end=at+len;
      if(len<8||end>limit||type>1)throw Error('Version node');
      let stop=at+6;while(stop+2<=end&&data.readUInt16LE(stop)!==0){stop+=2;if(stop-at>512)throw Error('Version key');}
      if(stop+2>end)throw Error('Unterminated key');
      const key=data.toString('utf16le',at+6,stop),value=align(stop+2),bytes=n*(type===1?2:1);
      if(bytes>8192||value+bytes>end)throw Error('Version value');
      if(keys.length===0&&key!=='VS_VERSION_INFO')throw Error('Version root');
      if(keys.length===3&&keys[1]==='StringFileInfo'&&/^[0-9a-f]{8}$/i.test(keys[2])&&type===1&&['FileDescription','ProductName'].includes(key)){
        const text=data.toString('utf16le',value,value+bytes).replace(/\0+$/,'').trim();
        if(text&&text.length<=256&&!/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(text)&&!fields.has(key))fields.set(key,text);
      }
      let child=align(value+bytes);while(child+6<=end)child=align(node(child,end,[...keys,key]));
      return end;
    }
    if(data.length>65536)return;node(0,data.length,[]);
    return fields.get('FileDescription')||fields.get('ProductName');
  }catch{return;}
}
export function peDisplayName(data: Buffer): string | undefined {
  try {
    const {roots,dir,blob}=peResources(data),type=roots.find(r=>r.id===16);if(!type)return;
    for(const name of dir(type.target).slice(0,16)){
      const languages=dir(name.target).sort((a,b)=>(a.id===0x409?-1:b.id===0x409?1:a.id-b.id));
      for(const lang of languages.slice(0,16)){const result=versionName(blob(lang.target));if(result)return result;}
    }
  }catch{return;}
}

// Read only headers and the resource section, not a potentially huge game file.
// Repack its file offsets for the bounded in-memory parser; RVAs stay unchanged.
export async function readPEResources(file: string): Promise<Buffer> {
  const f=await fs.open(file,'r');
  try {
    const before=await f.stat();if(!before.isFile())throw Error('Not a file');
    const header=Buffer.alloc(Math.min(before.size,65536));
    if((await f.read(header,0,header.length,0)).bytesRead!==header.length)throw Error('Short PE');
    if(header.toString('ascii',0,2)!=='MZ')throw Error('Not PE');
    const pe=header.readUInt32LE(60);if(header.readUInt32LE(pe)!==0x4550)throw Error('Not PE');
    const count=header.readUInt16LE(pe+6),size=header.readUInt16LE(pe+20),opt=pe+24,magic=header.readUInt16LE(opt),dirs=magic===0x10b?96:magic===0x20b?112:0;
    if(!dirs||!count||count>96||size<dirs+24||opt+size+count*40>header.length)throw Error('PE sections');
    const rva=header.readUInt32LE(opt+dirs+16),length=header.readUInt32LE(opt+dirs+20);let selected=-1;
    for(let i=0;i<count;i++){const s=opt+size+i*40,va=header.readUInt32LE(s+12),n=header.readUInt32LE(s+16);if(rva>=va&&rva+length<=va+n&&length>0){if(selected>=0)throw Error('Overlapping sections');selected=s;}}
    if(selected<0)throw Error('No resources');const bytes=header.readUInt32LE(selected+16),offset=header.readUInt32LE(selected+20);
    if(bytes>16*1024*1024||offset+bytes>before.size)throw Error('Resource size');
    const resources=Buffer.alloc(bytes);if((await f.read(resources,0,bytes,offset)).bytesRead!==bytes)throw Error('Short resource');
    const after=await f.stat();if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs)throw Error('PE changed');
    for(let i=0;i<count;i++){const s=opt+size+i*40;header.writeUInt32LE(s===selected?header.length:0,s+20);if(s!==selected)header.writeUInt32LE(0,s+16);}
    return Buffer.concat([header,resources]);
  }finally{await f.close();}
}
