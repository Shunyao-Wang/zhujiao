#include <stdio.h>
#include <sys/socket.h> /* for socket(), bind(), sendto() and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <fcntl.h>

#define SERPORT 5000
#define BAK ".copy"

int main(int argc, char *argv[])
{
    int sockfd, AddrLen;
    int sendsize;
    int fd;
    //char buf[100];
    char *newflie;
    char buffer[1000] = {0};
    char *SerIP;
    struct sockaddr_in serv_addr;
    sockfd = socket(PF_INET, SOCK_STREAM, 0); // Setup the socket
    memset(&serv_addr, 0, sizeof(serv_addr));
    SerIP = argv[1];
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SerIP);
    serv_addr.sin_port = htons(SERPORT);
    AddrLen = sizeof(serv_addr);

    connect(sockfd, (struct sockaddr *)&serv_addr, AddrLen); // Connect

    sendsize = send(sockfd, argv[2], sizeof(argv[2]), 0); //  send the filename indicated by argv to server
    printf("File name:'%s', send:%d\n", argv[2], sendsize);
    newflie = argv[2];
    strcat(newflie, BAK);
    if ((fd = open(newflie, O_RDWR | O_CREAT, 0664)) == -1)
    {
        printf("open file failed.\n");
        exit(1);
    }
    int re = 0;
    int re_total = 0;
    int wr = 0;
    while ((re = recv(sockfd, buffer, sizeof(buffer), 0)) > 0)
    {
        //printf("%s\n", buffer);
        wr += write(fd, buffer, re); //  write content
        memset(buffer, 0, sizeof(buffer));
        re_total += re;
    }
    close(fd);
    printf("Total receive: %d, Total write: %d\n", re_total, wr);
}
