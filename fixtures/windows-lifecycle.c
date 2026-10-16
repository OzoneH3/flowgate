/* Workspace-only WSADuplicateSocket/reuse fixture. No runtime instrumentation. */
#include <winsock2.h>
#include <windows.h>
static char dir[2048];
static void say(const char *s){DWORD n;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,lstrlenA(s),&n,0);}
static void number(const char *label,unsigned long long v){char b[32];int n=0;say(label);do{b[n++]='0'+v%10;v/=10;}while(v);while(n){char c[2]={b[--n],0};say(c);}say("\n");}
static void zero(void*p,unsigned n){char*c=p;while(n--)*c++=0;}
static void path(char *out,const char *name){lstrcpyA(out,dir);lstrcatA(out,"\\");lstrcatA(out,name);}
static void waitfile(const char *name){char p[2200];path(p,name);while(GetFileAttributesA(p)==INVALID_FILE_ATTRIBUTES)Sleep(10);}
static SOCKET bound(unsigned port,int tcp){SOCKET s=socket(AF_INET,tcp?SOCK_STREAM:SOCK_DGRAM,0);struct sockaddr_in a;zero(&a,sizeof(a));a.sin_family=AF_INET;a.sin_port=htons(port);a.sin_addr.s_addr=htonl(0x7f000001);if(bind(s,(void*)&a,sizeof(a)))ExitProcess(3);if(tcp&&listen(s,8))ExitProcess(4);return s;}
void mainCRTStartup(void){
 WSADATA w;char *a=GetCommandLineA();if(*a=='"'){a++;while(*a&&*a!='"')a++;if(*a)a++;}else while(*a&&*a!=' ')a++;while(*a==' ')a++;char mode=*a;while(*a&&*a!=' ')a++;while(*a==' ')a++;unsigned port=0;while(*a>='0'&&*a<='9')port=port*10+*a++-'0';
 if(!port||WSAStartup(0x202,&w)||!GetEnvironmentVariableA("FLOWGATE_FIXTURE_DIR",dir,sizeof(dir)))ExitProcess(2);
 SOCKET s;WSAPROTOCOL_INFOW info;static char file[2200];path(file,"info.bin");DWORD done;
 if(mode=='c'){
  say("CHILD_READY\n");waitfile("materialize");HANDLE f=CreateFileA(file,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);if(f==INVALID_HANDLE_VALUE||!ReadFile(f,&info,sizeof(info),&done,0)||done!=sizeof(info))ExitProcess(5);CloseHandle(f);
  s=WSASocketW(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,&info,0,0);if(s==INVALID_SOCKET)ExitProcess(6);number("CONSTRUCTED ",s);
  waitfile("receive");char b[128];if(recv(s,b,sizeof(b),0)>0)say("RECEIVED\n");waitfile("close-child");closesocket(s);say("FINAL_CLOSED\n");ExitProcess(0);
 }
 s=bound(port,mode=='a');number("ORIGINAL ",s);say("READY\n");
 if(mode=='r'){
  waitfile("close-parent");SOCKET old=s;closesocket(s);say("CLOSED\n");
  s=INVALID_SOCKET;for(int i=0;i<256;i++){SOCKET t=socket(AF_INET,SOCK_DGRAM,0);if(t==old){s=t;break;}closesocket(t);}
  if(s==INVALID_SOCKET){say("REUSE_NOT_OBSERVED\n");ExitProcess(7);}number("REUSED ",s);
  struct sockaddr_in b;zero(&b,sizeof(b));b.sin_family=AF_INET;b.sin_port=htons(port);b.sin_addr.s_addr=htonl(0x7f000001);if(bind(s,(void*)&b,sizeof(b)))ExitProcess(8);say("REBOUND\n");char data[128];if(recv(s,data,sizeof(data),0)>0)say("RECEIVED\n");Sleep(INFINITE);
 }
 if(mode=='a'){SOCKET listener=s;s=accept(listener,0,0);if(s==INVALID_SOCKET)ExitProcess(9);say("ACCEPTED\n");}
 static char exe[2048],cmd[2200];GetModuleFileNameA(0,exe,sizeof(exe));int i=lstrlenA(exe);while(i&&exe[i-1]!='\\'&&exe[i-1]!='/')i--;exe[i]=0;lstrcatA(exe,"beta-dup.exe");lstrcpyA(cmd,"\"");lstrcatA(cmd,exe);lstrcatA(cmd,"\" c 1");
 STARTUPINFOA si;PROCESS_INFORMATION pi;zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);if(!CreateProcessA(exe,cmd,0,0,FALSE,0,0,0,&si,&pi))ExitProcess(10);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
 waitfile("prepare");if(WSADuplicateSocketW(s,pi.dwProcessId,&info))ExitProcess(11);
 HANDLE f=CreateFileA(file,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);if(f==INVALID_HANDLE_VALUE||!WriteFile(f,&info,sizeof(info),&done,0))ExitProcess(12);CloseHandle(f);say("PREPARED\n");
 waitfile("close-parent");closesocket(s);say("PARENT_CLOSED\n");Sleep(INFINITE);
}
