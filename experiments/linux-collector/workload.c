/* Controlled test workload only. No arbitrary package execution. */
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
int main(void) {
 int fd=open("controlled.txt",O_CREAT|O_RDWR,0600);char buf[8];
 if(fd>=0){write(fd,"sample",6);lseek(fd,0,SEEK_SET);read(fd,buf,6);close(fd);}
 int forbidden=open("/restricted/forbidden.txt",O_RDONLY);if(forbidden>=0)close(forbidden);
 read(-1,buf,1);unlink("controlled.txt");unlink("missing-controlled.txt");
 int s=socket(AF_INET,SOCK_STREAM,0);
 struct sockaddr_in a;memset(&a,0,sizeof(a));a.sin_family=AF_INET;a.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
 a.sin_port=htons(12345);if(s>=0){bind(s,(void*)&a,sizeof(a));a.sin_port=htons(9);connect(s,(void*)&a,sizeof(a));close(s);}
 return 0;
}
