/* Optional snapshot helper for the unmodified Wine 11.19 runtime.
 * Uses runtime APIs; never touches target socket handles or application memory. */
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
static unsigned char table[262144];
static char out[1048576];static unsigned used;static int failed;
static void ch(char c){if(used<sizeof(out)-1)out[used++]=c;else failed=1;}
static void str(const char *s){while(*s)ch(*s++);}
static void num(unsigned long long n){char b[32];unsigned i=0;do{b[i++]='0'+n%10;n/=10;}while(n);while(i)ch(b[--i]);}
static void quoted(const char *s){ch('"');while(*s){unsigned char c=*s++;if(c=='"'||c=='\\'){ch('\\');ch(c);}else if(c<32){str("?");}else ch(c);}ch('"');}
static void addr(DWORD n){unsigned char *b=(unsigned char*)&n;ch('"');for(int i=0;i<4;i++){if(i)ch('.');num(b[i]);}ch('"');}
static void scan(int udp){
 used=0;failed=0;DWORD len=sizeof(table),err;const char *stage="table";
 typedef const char *(__cdecl *version_fn)(void);
 version_fn version=(version_fn)GetProcAddress(GetModuleHandleA("ntdll.dll"),"wine_get_version");
 str("{\"version\":");quoted(version?version():"unknown");str(",\"helper_pid\":");num(GetCurrentProcessId());str(",\"rows\":[");
 err=udp?GetExtendedUdpTable(table,&len,FALSE,AF_INET,UDP_TABLE_OWNER_PID,0):GetExtendedTcpTable(table,&len,FALSE,AF_INET,TCP_TABLE_OWNER_PID_LISTENER,0);
 if(err)failed=1;
 PMIB_TCPTABLE_OWNER_PID t=(PMIB_TCPTABLE_OWNER_PID)table;
 if(!err&&t->dwNumEntries>4096)failed=1;
 if(!failed)for(DWORD i=0;i<t->dwNumEntries;i++){
  MIB_TCPROW_OWNER_PID row,*r=&t->table[i];if(udp){MIB_UDPROW_OWNER_PID *u=&((PMIB_UDPTABLE_OWNER_PID)table)->table[i];row.dwLocalAddr=u->dwLocalAddr;row.dwLocalPort=u->dwLocalPort;row.dwOwningPid=u->dwOwningPid;row.dwState=0;r=&row;}HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,r->dwOwningPid);static WCHAR wide[2048];static char image[8192];DWORD count=2048;FILETIME created,exit,kernel,user;
  if(!p){err=GetLastError();stage="open_process";failed=1;break;}
  BOOL ok=QueryFullProcessImageNameW(p,0,wide,&count)&&GetProcessTimes(p,&created,&exit,&kernel,&user);
  if(ok)ok=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,count,image,sizeof(image)-1,0,0)>0;
  if(!ok){err=GetLastError();stage="process_details";CloseHandle(p);failed=1;break;}
  int bytes=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,wide,count,image,sizeof(image)-1,0,0);image[bytes]=0;CloseHandle(p);
  if(i)ch(',');str("{\"pid\":");num(r->dwOwningPid);str(",\"created\":");num(((unsigned long long)created.dwHighDateTime<<32)|created.dwLowDateTime);str(",\"image\":");quoted(image);str(",\"address\":");addr(r->dwLocalAddr);str(",\"port\":");num(ntohs((USHORT)r->dwLocalPort));str(",\"state\":");num(r->dwState);ch('}');
 }
 str("],\"error\":");num(err);str(",\"stage\":");quoted(stage);str(",\"complete\":");str(failed?"false":"true");str("}\n");DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),out,used,&done,0);if(done!=used)ExitProcess(3);
}
void mainCRTStartup(void){char c;DWORD n;int udp=0;while(ReadFile(GetStdHandle(STD_INPUT_HANDLE),&c,1,&n,0)&&n){if(c=='u')udp=1;else if(c=='t')udp=0;else if(c=='\n')scan(udp);}ExitProcess(0);}
