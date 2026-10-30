/* Isolated outgoing UDP WSADuplicateSocket fixture. Environment supplies all
 * endpoints, paths and identities. No application-specific behavior. */
#include <winsock2.h>
#include <windows.h>
static char folder[2048];
static void zero(void *p,unsigned n){char *s=p;while(n--)*s++=0;}
static void path(char *p,const char *n){lstrcpyA(p,folder);lstrcatA(p,"\\");lstrcatA(p,n);}
static int exists(const char *n){char p[2200];path(p,n);return GetFileAttributesA(p)!=INVALID_FILE_ATTRIBUTES;}
static void say(const char *s){DWORD n;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,lstrlenA(s),&n,0);}
static void sendone(SOCKET s,struct sockaddr_in *peer,int child){const char *b=child?"TRANSFER_BETA":"TRANSFER_ALPHA";sendto(s,b,lstrlenA(b),0,(void*)peer,sizeof(*peer));Sleep(8);}
void mainCRTStartup(void){
 WSADATA w;static char text[2048];unsigned port=0;
 if(WSAStartup(0x202,&w)||!GetEnvironmentVariableA("FLOWGATE_TRANSFER_DIR",folder,sizeof(folder)))ExitProcess(2);
 GetEnvironmentVariableA("FLOWGATE_TEST_PORT",text,sizeof(text));for(int i=0;text[i]>='0'&&text[i]<='9';i++)port=port*10+text[i]-'0';if(!port)ExitProcess(3);
 struct sockaddr_in peer;zero(&peer,sizeof(peer));peer.sin_family=AF_INET;peer.sin_addr.s_addr=htonl(0x7f000001);peer.sin_port=htons(port);
 int child=GetEnvironmentVariableA("FLOWGATE_TRANSFER_CHILD",text,sizeof(text))!=0;
 WSAPROTOCOL_INFOW info;DWORD n;static char file[2200];path(file,"info.bin");SOCKET s;
 if(child){
  while(!exists("info.bin"))Sleep(1);
  HANDLE f=CreateFileA(file,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
  if(f==INVALID_HANDLE_VALUE||!ReadFile(f,&info,sizeof(info),&n,0)||n!=sizeof(info))ExitProcess(4);CloseHandle(f);
  s=WSASocketW(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,&info,0,0);if(s==INVALID_SOCKET)ExitProcess(5);
  path(file,"constructed");HANDLE marker=CreateFileA(file,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);if(marker!=INVALID_HANDLE_VALUE){FILETIME at;GetSystemTimeAsFileTime(&at);WriteFile(marker,&at,sizeof(at),&n,0);CloseHandle(marker);}say("CHILD_CONSTRUCTED\n");for(int i=0;i<2500;i++)sendone(s,&peer,1);closesocket(s);ExitProcess(0);
 }
 s=socket(AF_INET,SOCK_DGRAM,0);if(s==INVALID_SOCKET)ExitProcess(6);
 say("PARENT_READY\n");while(!exists("transfer")&&!exists("stop"))sendone(s,&peer,0);
 if(exists("stop")){closesocket(s);ExitProcess(0);}
 static char exe[2048],cmd[2200];if(!GetEnvironmentVariableA("FLOWGATE_TRANSFER_CHILD_EXE",exe,sizeof(exe)))ExitProcess(7);
 lstrcpyA(cmd,"\"");lstrcatA(cmd,exe);lstrcatA(cmd,"\"");SetEnvironmentVariableA("FLOWGATE_TRANSFER_CHILD","1");
 STARTUPINFOA si;PROCESS_INFORMATION pi;zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);
 if(!CreateProcessA(exe,cmd,0,0,FALSE,0,0,0,&si,&pi))ExitProcess(8);
 if(WSADuplicateSocketW(s,pi.dwProcessId,&info))ExitProcess(9);
 HANDLE f=CreateFileA(file,GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);if(f==INVALID_HANDLE_VALUE||!WriteFile(f,&info,sizeof(info),&n,0))ExitProcess(10);CloseHandle(f);
 say("PREPARED\n");while(!exists("close-parent"))sendone(s,&peer,0);
 closesocket(s);say("PARENT_CLOSED\n");Sleep(25000);ExitProcess(0);
}
