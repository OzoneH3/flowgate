/* Labelled outgoing TCP/UDP client for the real UMU/Proton launcher regression.
 * No game names, service addresses, or prefix assumptions. */
#include <winsock2.h>
#include <windows.h>
static void say(const char *s) { DWORD n, len=0; while(s[len])len++; WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,len,&n,0); char path[2048]; if(GetEnvironmentVariableA("FLOWGATE_TEST_TRACE",path,sizeof(path))) { HANDLE f=CreateFileA(path,FILE_APPEND_DATA,FILE_SHARE_READ|FILE_SHARE_WRITE,0,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,0); if(f!=INVALID_HANDLE_VALUE){WriteFile(f,s,len,&n,0);CloseHandle(f);} } }
static DWORD WINAPI client(void *unused) {
    (void)unused;
    say("CLIENT_ENTRY\n");
    char portText[16], token[128];
    GetEnvironmentVariableA("FLOWGATE_TEST_PORT",portText,sizeof(portText));
    GetEnvironmentVariableA("FLOWGATE_TEST_TOKEN",token,sizeof(token));
    unsigned port=0, len=0; for(unsigned i=0;portText[i]>='0'&&portText[i]<='9';i++)port=port*10+portText[i]-'0';
    while(token[len])len++;
    if(!port || port>65535 || !len)return 2;
    WSADATA w; if(WSAStartup(0x202,&w))return 3;
    char protocol[8]; int udp=GetEnvironmentVariableA("FLOWGATE_TEST_PROTOCOL",protocol,sizeof(protocol)) && protocol[0]=='u';
    SOCKET s=socket(AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0);
    struct sockaddr_in a; for(unsigned i=0;i<sizeof(a);i++)((volatile char*)&a)[i]=0; a.sin_family=AF_INET; a.sin_port=htons((unsigned short)port); a.sin_addr.s_addr=htonl(0x7f000001);
    say("SYNTHETIC_CLIENT_READY\n"); Sleep(1500); say("CONNECT_BEGIN\n");
    if(!udp && connect(s,(struct sockaddr*)&a,sizeof(a))) {say("CONNECT_FAILED\n");return 4;}
    if((udp?sendto(s,token,len,0,(struct sockaddr*)&a,sizeof(a)):send(s,token,len,0))!=(int)len)return 5;
    say("RECEIVER_PAYLOAD_SENT\n"); Sleep(15000); closesocket(s); return 0;
}

void mainCRTStartup(void) {
 char value[8]; unsigned count=1;
 if(GetEnvironmentVariableA("FLOWGATE_TEST_CONNECTIONS",value,sizeof(value)) && value[0]>='1' && value[0]<='8')count=value[0]-'0';
 HANDLE threads[8];
 for(unsigned i=0;i<count;i++){threads[i]=CreateThread(0,0,client,0,0,0);if(!threads[i])ExitProcess(6);}
 WaitForMultipleObjects(count,threads,TRUE,INFINITE);
 ExitProcess(0);
}
