#include <stdio.h>
#include <sys/socket.h> /* for socket(), bind(), sendto() and recvfrom() */
#include <arpa/inet.h>  /* for sockaddr_in and inet_ntoa() */
#include <stdlib.h>     /* for atoi() and exit() */
#include <string.h>     /* for memset() */
#include <unistd.h>     /* for close() */
#include <fcntl.h>

#define SERPORT 5000

int main(int argc, char *argv[])
{
      int sockfd, newsockfd;
      int fd;
      int recvbytes;
      char filename[1000];
      char buffer[1000] = {0};
      struct sockaddr_in SerAddr;
      socklen_t AddrLen;
      memset(&SerAddr, 0, sizeof(SerAddr));
      SerAddr.sin_family = AF_INET;
      SerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
      SerAddr.sin_port = htons(SERPORT);
      AddrLen = sizeof(SerAddr);
      if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
            printf("socket() failed.\n"); // create the socket
      if ((bind(sockfd, (struct sockaddr *)&SerAddr, sizeof(SerAddr))) < 0)
      {
            printf("bind() failed.\n"); // bind
            exit(1);
      }
      if ((listen(sockfd, 10)) == -1)
      {
            printf("listen() failed.\n"); //listen
            exit(1);
      }
      for (;;)
      {                                                                        // Loop forever
            newsockfd = accept(sockfd, (struct sockaddr *)&SerAddr, &AddrLen); //create a new socket
            if ((recvbytes = recv(newsockfd, filename, sizeof(filename), 0)) == -1)
            { // receive the file name
                  printf("receive() failed.\n");
                  exit(1);
            }
            printf("receive:%dbytes, Flie name:%s\n", recvbytes, filename);
            if ((fd = open(filename, O_RDONLY)) < 0)
            {
                  printf("open file failed.\n");
                  exit(1);
            }
            int p = 0;
            int rd = 0;
            int ww = 0;
            while ((rd = read(fd, buffer, 1000)) > 0)
            { //loop to read the file
                  //ww += w;
                  printf("%s\n", buffer);
                  p += send(newsockfd, buffer, rd, 0); //  send content
                  memset(buffer, 0, sizeof(buffer));
            }
            close(fd);
            close(newsockfd);
            printf("total send: %d bytes.\n", p);
      }
}
