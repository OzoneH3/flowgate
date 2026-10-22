/* Versioned owner-table helper for validated unmodified Wine/Proton builds.
 * Uses runtime APIs; never touches target socket handles or application memory. */
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
static unsigned char table[262144];
static char out[1048576];static unsigned used;static int failed;
static void ch(char c){if(used<sizeof(out)-1)out[used++]=c;else failed=1;}
static void str(const char *s){while(*s)ch(*s++);}
static void num(unsigned long long n){char b[32];unsigned i=0;do{b[i++]='0'+n%10;n/=10;}while(n);while(i)ch(b[--i]);}
static void quoted(const char *s){ch('"');while(*s){unsigned char c=*s++;if(c=='"'||c=='\\'){ch('\\');ch(c);}else if(c<32){str("?");}else ch(c);}ch('"');}
static void addr(DWORD n){unsigned char *b=(unsigned char*)&n;ch('"');for(int i=0;i<4;i++){if(i)ch('.');num(b[i]);}ch('"');}
static void addr6(const unsigned char *b){const char *hex="0123456789abcdef";ch('"');for(int i=0;i<16;i+=2){if(i)ch(':');ch(hex[b[i]>>4]);ch(hex[b[i]&15]);ch(hex[b[i+1]>>4]);ch(hex[b[i+1]&15]);}ch('"');}
static void scan(int udp,int family){
 used=0;failed=0;DWORD len=sizeof(table),err;const char *stage="table";
 typedef const char *(__cdecl *version_fn)(void);
 version_fn version=(version_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"),"wine_get_version");
 str("{\"schema\":3,\"version\":");quoted(version?version():"unknown");str(",\"family\":");num(family);str(",\"helper_pid\":");num(GetCurrentProcessId());str(",\"rows\":[");
 err=udp?GetExtendedUdpTable(table,&len,FALSE,family==6?AF_INET6:AF_INET,UDP_TABLE_OWNER_PID,0):GetExtendedTcpTable(table,&len,FALSE,family==6?AF_INET6:AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
 if(err)failed=1;
 PMIB_TCPTABLE_OWNER_PID t=(PMIB_TCPTABLE_OWNER_PID)table;
 if(!err&&t->dwNumEntries>4096)failed=1;
 if(!failed)for(DWORD i=0;i<t->dwNumEntries;i++){
  DWORD pid,port,state=0,scope=0,ip4=0,remote4=0,remoteport=0;unsigned char *ip6=0,*remote6=0;
  if(family==6){if(udp){MIB_UDP6ROW_OWNER_PID*r=&((PMIB_UDP6TABLE_OWNER_PID)table)->table[i];pid=r->dwOwningPid;port=r->dwLocalPort;scope=r->dwLocalScopeId;ip6=r->ucLocalAddr;}else{MIB_TCP6ROW_OWNER_PID*r=&((PMIB_TCP6TABLE_OWNER_PID)table)->table[i];pid=r->dwOwningPid;port=r->dwLocalPort;scope=r->dwLocalScopeId;ip6=r->ucLocalAddr;state=r->dwState;remote6=r->ucRemoteAddr;remoteport=r->dwRemotePort;}}
  else if(udp){MIB_UDPROW_OWNER_PID*r=&((PMIB_UDPTABLE_OWNER_PID)table)->table[i];pid=r->dwOwningPid;port=r->dwLocalPort;ip4=r->dwLocalAddr;}else{MIB_TCPROW_OWNER_PID*r=&t->table[i];pid=r->dwOwningPid;port=r->dwLocalPort;ip4=r->dwLocalAddr;state=r->dwState;remote4=r->dwRemoteAddr;remoteport=r->dwRemotePort;}
  HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);static WCHAR wide[2048];static char image[8192];DWORD count=2048;FILETIME created,exit,kernel,user;
  if(!p){err=GetLastError();stage="open_process";failed=1;break;}
  BOOL ok=QueryFullProcessImageNameW(p,0,wide,&count)&&GetProcessTimes(p,&created,&exit,&kernel,&user);
  if(ok)ok=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,count,image,sizeof(image)-1,0,0)>0;
  if(!ok){err=GetLastError();stage="process_details";CloseHandle(p);failed=1;break;}
  int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,count,image,sizeof(image)-1,0,0);image[bytes]=0;CloseHandle(p);
  if(i)ch(',');str("{\"pid\":");num(pid);str(",\"created\":");num(((unsigned long long)created.dwHighDateTime<<32)|created.dwLowDateTime);str(",\"image\":");quoted(image);str(",\"address\":");if(family==6)addr6(ip6);else addr(ip4);str(",\"port\":");num(ntohs((USHORT)port));str(",\"state\":");num(state);str(",\"remote_address\":");if(family==6){static unsigned char empty[16];addr6(remote6?remote6:empty);}else addr(remote4);str(",\"remote_port\":");num(ntohs((USHORT)remoteport));str(",\"family\":");num(family);str(",\"scope_id\":");num(scope);ch('}');
 }
 str("],\"error\":");num(err);str(",\"stage\":");quoted(stage);str(",\"complete\":");str(failed?"false":"true");str("}\n");DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),out,used,&done,0);if(done!=used)ExitProcess(3);
}
/* Read-only Wine server list_processes ABI. The request ordinal and the
 * fixed layouts below are validated against Wine 11.0 and 11.20 source. The daemon additionally
 * requires an exact validated wineserver SHA256 before sending this request.
 * Unknown contracts refuse this optional capability, retaining socket tables. */
typedef struct {LONGLONG started;DWORD name_len;int threads,priority;DWORD pid,parent,session;int handles,unix_pid;} FG_PROCESS;
typedef struct {LONGLONG started;DWORD tid;int base,current,unix_tid;ULONGLONG teb,entry;} FG_THREAD;
typedef struct {
 union {ULONGLONG alignment[8];struct{int request;DWORD size,reply_size;}req;struct{DWORD error,reply_size,info_size;int processes,threads;DWORD names;}reply;}u;
 DWORD data_count;void *reply_data;struct{const void *ptr;DWORD size;}data[5];
} FG_REQUEST;
static unsigned char process_data[1048576];
static DWORD process_ids[4096],process_names[4096],process_lengths[4096];
static ULONGLONG process_created[4096];
_Static_assert(sizeof(FG_PROCESS)==40,"Wine process ABI");
_Static_assert(sizeof(FG_THREAD)==40,"Wine thread ABI");
_Static_assert(__builtin_offsetof(FG_REQUEST,reply_data)==72,"Wine request ABI");
static int match_process(DWORD pid,ULONGLONG started,const WCHAR *name,unsigned length,char *image){
 HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);if(!p)return 0;
 static WCHAR wide[2048];DWORD size=2048;FILETIME created,exit,kernel,user;
 BOOL ok=QueryFullProcessImageNameW(p,0,wide,&size)&&GetProcessTimes(p,&created,&exit,&kernel,&user);
 CloseHandle(p);if(!ok||(((ULONGLONG)created.dwHighDateTime<<32)|created.dwLowDateTime)!=started)return 0;
 if(length>=4&&name[0]=='\\'&&name[1]=='?'&&name[2]=='?'&&name[3]=='\\'){name+=4;length-=4;}
 if(CompareStringOrdinal(name,length,wide,size,TRUE)!=CSTR_EQUAL)return 0;
 if(image){int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,size,image,8191,0,0);if(!bytes)return 0;image[bytes]=0;}
 return 1;
}
static void processes(void){
 used=0;failed=0;DWORD err=0;unsigned count=0,pos=0,total_threads=0,total_names=0;
 typedef const char *(__cdecl *version_fn)(void);
 typedef unsigned int (__cdecl *server_fn)(void*);
 HMODULE ntdll=GetModuleHandleA("ntdll.dll");
 version_fn version=(version_fn)GetProcAddress(ntdll,"wine_get_version");
 server_fn call=(server_fn)GetProcAddress(ntdll,"wine_server_call");
 version_fn build=(version_fn)GetProcAddress(ntdll,"wine_get_build_id");
 const char *build_id=build?build():"unknown";
 const char *v=version?version():"unknown";int request=-1;
 if(lstrcmpA(v,"11.0")==0&&lstrcmpA(build_id,"wine-11.0 (Staging)")==0)request=76;
 if(lstrcmpA(v,"11.20")==0&&lstrcmpA(build_id,"wine-11.20")==0)request=77;
 str("{\"schema\":3,\"kind\":\"process-images\",\"version\":");quoted(v);str(",\"build_id\":");quoted(build_id);str(",\"family\":4,\"rows\":[");
 static FG_REQUEST req;unsigned char *zero=(unsigned char*)&req;for(unsigned i=0;i<sizeof(req);i++)zero[i]=0;
 if(request<0||!call){err=ERROR_NOT_SUPPORTED;failed=1;}
 else {
  req.u.req.request=request;req.u.req.reply_size=sizeof(process_data);req.reply_data=process_data;
  err=call(&req);
  if(err||req.u.reply.processes<1||req.u.reply.processes>4096||req.u.reply.info_size!=req.u.reply.reply_size||req.u.reply.reply_size>sizeof(process_data))failed=1;
 }
 if(!failed)for(int i=0;i<req.u.reply.processes;i++){
  pos=(pos+7)&~7u;if(pos>req.u.reply.reply_size||sizeof(FG_PROCESS)>req.u.reply.reply_size-pos){failed=1;break;}
  FG_PROCESS *pinfo=(FG_PROCESS*)(process_data+pos);pos+=sizeof(*pinfo);
  if(!pinfo->pid||pinfo->unix_pid<=0||!pinfo->started||(pinfo->name_len&1)||pinfo->name_len>8192||pinfo->name_len>req.u.reply.reply_size-pos||pinfo->threads<0||pinfo->threads>65536){failed=1;break;}
  total_threads+=pinfo->threads;total_names+=pinfo->name_len;unsigned name_pos=pos;pos+=pinfo->name_len;pos=(pos+7)&~7u;
  if(pos>req.u.reply.reply_size||(unsigned)pinfo->threads>(req.u.reply.reply_size-pos)/sizeof(FG_THREAD)){failed=1;break;}
  pos+=pinfo->threads*sizeof(FG_THREAD);
  static char image[8192];
  if(!match_process(pinfo->pid,pinfo->started,(WCHAR*)(process_data+name_pos),pinfo->name_len/2,image)){err=ERROR_INVALID_DATA;failed=1;break;}
  for(unsigned j=0;j<count;j++)if(process_ids[j]==pinfo->pid){failed=1;break;}
  if(failed)break;
  process_ids[count]=pinfo->pid;process_created[count]=pinfo->started;process_names[count]=name_pos;process_lengths[count]=pinfo->name_len/2;
  if(count++)ch(',');str("{\"pid\":");num(pinfo->pid);str(",\"unix_pid\":");num(pinfo->unix_pid);str(",\"created\":");num(pinfo->started);str(",\"image\":");quoted(image);ch('}');
 }
 if(!failed&&(pos!=req.u.reply.reply_size||total_threads!=(unsigned)req.u.reply.threads||total_names!=req.u.reply.names))failed=1;
 // Independent public process enumeration must agree one-to-one.
 if(!failed){
  HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);PROCESSENTRY32W entry;entry.dwSize=sizeof(entry);unsigned seen=0;
  if(snap==INVALID_HANDLE_VALUE||!Process32FirstW(snap,&entry))failed=1;
  else do{
   if(!entry.th32ProcessID)continue;
   unsigned index=0;while(index<count&&process_ids[index]!=entry.th32ProcessID)index++;
   if(index==count||!match_process(entry.th32ProcessID,process_created[index],(WCHAR*)(process_data+process_names[index]),process_lengths[index],0)){failed=1;break;}
   seen++;
  }while(Process32NextW(snap,&entry));
  if(!failed&&(GetLastError()!=ERROR_NO_MORE_FILES||seen!=count))failed=1;
  if(snap!=INVALID_HANDLE_VALUE)CloseHandle(snap);
 }
 str("],\"error\":");num(err);str(",\"complete\":");str(failed?"false":"true");str("}\n");DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),out,used,&done,0);if(done!=used)ExitProcess(3);
}
void mainCRTStartup(void){char c;DWORD n;int mode=0,family=4;while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&c,1,&n,0)&&n){if(c=='u')mode=1;else if(c=='t')mode=0;else if(c=='p')mode=2;else if(c=='6')family=6;else if(c=='4')family=4;else if(c=='\n'){if(mode==2)processes();else scan(mode,family);}}ExitProcess(0);}
