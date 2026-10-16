/* Freestanding PE fixture. Modes: u UDP, t plain TCP, p polling TCP,
 * s UDP with inherited beta handle, d UDP with a dormant inherited beta handle.
 * h/j are child modes. No existing prefix or installed runtime is modified. */
#include <winsock2.h>
#include <windows.h>
static void say(const char *s,DWORD n){DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,n,&done,0);}
static void zero(void *p,unsigned n){char *c=p;while(n--)*c++=0;}
static void spawn(SOCKET s,int dormant){
 char path[1024],cmd[1100],digits[32];unsigned n=GetModuleFileNameA(0,path,sizeof(path)),i=n,k=0,j=0;
 while(i&&path[i-1]!='\\'&&path[i-1]!='/')i--;const char *name="beta.exe";while(*name)path[i++]=*name++;path[i]=0;
 cmd[j++]='"';for(i=0;path[i];i++)cmd[j++]=path[i];cmd[j++]='"';cmd[j++]=' ';cmd[j++]=dormant?'j':'h';cmd[j++]=' ';
 unsigned long long v=s;do{digits[k++]='0'+v%10;v/=10;}while(v);while(k)cmd[j++]=digits[--k];cmd[j]=0;
 STARTUPINFOA si;PROCESS_INFORMATION pi;zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);
 SetHandleInformation((HANDLE)s,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT);
 if(!CreateProcessA(path,cmd,0,0,TRUE,0,0,0,&si,&pi))ExitProcess(5);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
}
void mainCRTStartup(void){
 WSADATA w;char *arg=GetCommandLineA();unsigned long long value=0;char mode;
 if(*arg=='"'){arg++;while(*arg&&*arg!='"')arg++;if(*arg)arg++;}else{while(*arg&&*arg!=' ')arg++;}
 while(*arg==' ')arg++;mode=*arg;while(*arg&&*arg!=' ')arg++;while(*arg==' ')arg++;while(*arg>='0'&&*arg<='9'){value=value*10+*arg-'0';arg++;}
 if(!value||WSAStartup(0x202,&w))ExitProcess(2);
 int child=mode=='h'||mode=='j',udp=mode!='t'&&mode!='p';SOCKET s;
 if(child){s=(SOCKET)value;if(mode=='j'){char release[2048];GetEnvironmentVariableA("FLOWGATE_FIXTURE_RELEASE",release,sizeof(release));say("DORMANT\n",8);while(GetFileAttributesA(release)==INVALID_FILE_ATTRIBUTES)Sleep(25);}}
 else {s=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);struct sockaddr_in a;zero(&a,sizeof(a));a.sin_family=AF_INET;a.sin_port=htons((unsigned short)value);a.sin_addr.s_addr=htonl(0x7f000001);if(bind(s,(struct sockaddr*)&a,sizeof(a)))ExitProcess(3);if(!udp&&listen(s,8))ExitProcess(4);}
 if(mode=='p'||child||mode=='s'||mode=='d'){u_long available;if(ioctlsocket(s,FIONREAD,&available))ExitProcess(6);}
 if(mode=='s'||mode=='d')spawn(s,mode=='d');
 if(child)say("MATERIALIZED\n",13);say("READY\n",6);
 for(;;){char b[128];int n;if(udp){n=recv(s,b,sizeof(b),0);}else{SOCKET c=accept(s,0,0);n=recv(c,b,sizeof(b),0);closesocket(c);}if(n>0)say("RECEIVED\n",9);}
}
