/* Real Winsock connect fixture. No product/game names or runtime hooks. */
#include <winsock2.h>
#include <windows.h>
static void say(const char*s){DWORD n;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,lstrlenA(s),&n,0);}
static void zero(void*p,unsigned n){char*c=p;while(n--)*c++=0;}
void mainCRTStartup(void){
 WSADATA w;char*a=GetCommandLineA();if(*a=='"'){a++;while(*a&&*a!='"')a++;if(*a)a++;}else while(*a&&*a!=' ')a++;while(*a==' ')a++;
 int child=*a=='h';if(child){a++;while(*a==' ')a++;}
 unsigned port=0;while(*a>='0'&&*a<='9')port=port*10+*a++-'0';if(!port||WSAStartup(0x202,&w))ExitProcess(2);
 if(child){say("DORMANT\n");Sleep(INFINITE);ExitProcess(0);}
 while(*a==' ')a++;int duplicate=*a=='d',reuse=*a=='r',pollfd=*a=='q';
 SOCKET s=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in peer;zero(&peer,sizeof(peer));peer.sin_family=AF_INET;peer.sin_addr.s_addr=htonl(0x7f000001);peer.sin_port=htons(port);
 if(duplicate){
 static char exe[2048],cmd[2200],digits[32];GetModuleFileNameA(0,exe,sizeof(exe));int i=lstrlenA(exe),j=0,k=0;while(i&&exe[i-1]!='\\'&&exe[i-1]!='/')i--;exe[i]=0;lstrcatA(exe,"connect-beta.exe");cmd[j++]='"';for(i=0;exe[i];i++)cmd[j++]=exe[i];cmd[j++]='"';cmd[j++]=' ';cmd[j++]='h';cmd[j++]=' ';unsigned long long v=s;do{digits[k++]='0'+v%10;v/=10;}while(v);while(k)cmd[j++]=digits[--k];cmd[j]=0;
 STARTUPINFOA si;PROCESS_INFORMATION pi;zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);SetHandleInformation((HANDLE)s,HANDLE_FLAG_INHERIT,HANDLE_FLAG_INHERIT);if(!CreateProcessA(exe,cmd,0,0,TRUE,0,0,0,&si,&pi))ExitProcess(7);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);Sleep(100);
 }
 if(pollfd){u_long one=1;ioctlsocket(s,FIONBIO,&one);int r=connect(s,(void*)&peer,sizeof(peer));if(r&&WSAGetLastError()!=WSAEWOULDBLOCK)ExitProcess(15);u_long n;if(ioctlsocket(s,FIONREAD,&n))ExitProcess(16);say("POLLED\n");fd_set ready;FD_ZERO(&ready);FD_SET(s,&ready);struct timeval timeout={20,0};if(select(0,0,&ready,0,&timeout)<=0)ExitProcess(17);if(send(s,"wine-polled",11,0)!=11)ExitProcess(18);say("SENT\n");Sleep(5000);ExitProcess(0);}
 if(reuse){
 u_long one=1;ioctlsocket(s,FIONBIO,&one);int result=connect(s,(void*)&peer,sizeof(peer));if(result&&WSAGetLastError()!=WSAEWOULDBLOCK)ExitProcess(8);
 struct sockaddr_in local;int len=sizeof(local);getsockname(s,(void*)&local,&len);say("WAITING_REUSE\n");static char release[2048];if(!GetEnvironmentVariableA("FLOWGATE_FIXTURE_RELEASE",release,sizeof(release)))ExitProcess(9);while(GetFileAttributesA(release)==INVALID_FILE_ATTRIBUTES)Sleep(10);
 SOCKET old=s;closesocket(s);s=socket(AF_INET,SOCK_STREAM,0);if(s!=old){say("REUSE_NOT_OBSERVED\n");ExitProcess(10);}int yes=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(void*)&yes,sizeof(yes));if(bind(s,(void*)&local,sizeof(local)))ExitProcess(11);ioctlsocket(s,FIONBIO,&one);result=connect(s,(void*)&peer,sizeof(peer));if(result&&WSAGetLastError()!=WSAEWOULDBLOCK)ExitProcess(12);say("REUSED\n");fd_set ready;FD_ZERO(&ready);FD_SET(s,&ready);struct timeval timeout={20,0};if(select(0,0,&ready,0,&timeout)<=0)ExitProcess(13);if(send(s,"wine-reused",11,0)!=11)ExitProcess(14);say("SENT\n");Sleep(5000);ExitProcess(0);
 }
 say("CONNECTING\n");if(connect(s,(void*)&peer,sizeof(peer))){say("CONNECT_FAILED\n");Sleep(3000);ExitProcess(3);}say("CONNECTED\n");if(send(s,"wine-receiver",13,0)!=13)ExitProcess(4);say("SENT\n");Sleep(15000);closesocket(s);ExitProcess(0);
}
