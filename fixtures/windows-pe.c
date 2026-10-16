/* Freestanding PE fixture: no Windows SDK or downloaded game required. */
#include <winsock2.h>
#include <windows.h>
static void say(const char *s,DWORD n){DWORD done;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,n,&done,0);}
void mainCRTStartup(void){
 WSADATA w;char *arg=GetCommandLineA();int port=0,udp=0;
 /* Arguments: executable [u|t] PORT. Executable path may be quoted. */
 if(*arg=='"'){arg++;while(*arg&&*arg!='"')arg++;if(*arg)arg++;}else{while(*arg&&*arg!=' ')arg++;}
 while(*arg==' ')arg++;udp=*arg=='u';while(*arg&&*arg!=' ')arg++;while(*arg==' ')arg++;while(*arg>='0'&&*arg<='9'){port=port*10+*arg-'0';arg++;}
 if(!port||WSAStartup(0x202,&w))ExitProcess(2);
 SOCKET s=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);
 struct sockaddr_in a;char *z=(char*)&a;for(unsigned i=0;i<sizeof(a);i++)z[i]=0;
 a.sin_family=AF_INET;a.sin_port=htons((unsigned short)port);a.sin_addr.s_addr=htonl(0x7f000001);
 if(bind(s,(struct sockaddr*)&a,sizeof(a)))ExitProcess(3);
 if(!udp&&listen(s,8))ExitProcess(4);say("READY\n",6);
 for(;;){char b[128];int n;if(udp){n=recv(s,b,sizeof(b),0);}else{SOCKET c=accept(s,0,0);n=recv(c,b,sizeof(b),0);closesocket(c);}if(n>0)say("RECEIVED\n",9);}
}
