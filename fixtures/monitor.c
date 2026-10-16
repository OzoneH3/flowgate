// Controlled, unprivileged host loopback sockets. No payload/metadata logging.
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
static int make(int family,int type) {
 int fd=socket(family,type,0);if(fd<0){perror("socket");exit(1);}
 struct sockaddr_storage storage={0};socklen_t size;
 if(family==AF_INET){struct sockaddr_in *a=(void*)&storage;a->sin_family=AF_INET;inet_pton(AF_INET,"127.0.0.1",&a->sin_addr);size=sizeof(*a);}
 else {struct sockaddr_in6 *a=(void*)&storage;a->sin6_family=AF_INET6;inet_pton(AF_INET6,"::1",&a->sin6_addr);size=sizeof(*a);}
 if(bind(fd,(void*)&storage,size)<0){perror("bind");exit(1);}return fd;
}
static unsigned port(int fd) {struct sockaddr_storage a;socklen_t n=sizeof(a);getsockname(fd,(void*)&a,&n);return ntohs(a.ss_family==AF_INET?((struct sockaddr_in*)&a)->sin_port:((struct sockaddr_in6*)&a)->sin6_port);}
static void connect_to(int fd,int target) {struct sockaddr_storage a;socklen_t n=sizeof(a);getsockname(target,(void*)&a,&n);if(connect(fd,(void*)&a,n)<0 && errno!=EINPROGRESS){perror("connect");exit(1);}}
int main(int argc,char**argv) {
 if(argc>1 && !strcmp(argv[1],"holder")){puts("HOLDER");fflush(stdout);while(getchar()!=EOF){}return 0;}
 int tcp=make(AF_INET,SOCK_STREAM),tcp6=make(AF_INET6,SOCK_STREAM),udp=make(AF_INET,SOCK_DGRAM),udp6=make(AF_INET6,SOCK_DGRAM),connected=make(AF_INET,SOCK_DGRAM);
 listen(tcp,4);listen(tcp6,4);connect_to(connected,udp);
 int client=make(AF_INET,SOCK_STREAM);connect_to(client,tcp);int accepted=accept(tcp,NULL,NULL);
 send(client,"fixture",7,0);char b[8];recv(accepted,b,sizeof(b),0);
 int saturated=make(AF_INET,SOCK_STREAM);listen(saturated,0);int fillers[3];
 for(int i=0;i<3;i++){fillers[i]=make(AF_INET,SOCK_STREAM);fcntl(fillers[i],F_SETFL,O_NONBLOCK);connect_to(fillers[i],saturated);}
 int child=-1;
 if(argc>1 && !strcmp(argv[1],"shared")) {
   child=fork();if(child==0){close(tcp6);close(udp);close(udp6);close(connected);close(client);close(accepted);close(saturated);for(int i=0;i<3;i++)close(fillers[i]);execl(argv[2],argv[2],"holder",NULL);_exit(2);}
 }
 printf("{\"pid\":%d,\"child\":%d,\"tcp\":%u,\"tcp6\":%u,\"udp\":%u,\"udp6\":%u,\"connected_udp\":%u,\"tcp_client\":%u,\"connecting\":%u}\n",getpid(),child,port(tcp),port(tcp6),port(udp),port(udp6),port(connected),port(client),port(fillers[2]));fflush(stdout);
 while(getchar()!=EOF){}
 if(child>0){kill(child,SIGTERM);waitpid(child,NULL,0);}return 0;
}
