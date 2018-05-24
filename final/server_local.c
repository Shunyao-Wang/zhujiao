#include <stdio.h>
#include "packet.h"

#define SERVADDR "127.1.1.1"
#define ROOTADDR "127.2.2.1"
#define SERVPORT 53
#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
    int sockfd, sock_up, clientfd;
    int recv_len, send_len, i, flag;
    unsigned short id_real;
    unsigned char buf[BUF_SIZE];
    unsigned char name[100] = {0};                       //转换成'.'的name
    unsigned char name_ns[50] = {0};                     //转换成'.'的ns name
    unsigned char buf_tcp[BUF_SIZE];                     //tcp报文头两个字节为长度
    unsigned short *len_tcp = (unsigned short *)buf_tcp; //TCP报文长度
    unsigned char buf_file[100] = {0};                   //文件读入缓存
    unsigned char tag_bit[16] = {0};                     //按位读tag
    struct sockaddr_in serv_addr, cli_addr, up_addr;
    int len_query, len_RR;
    DNS_Header *dnshdr = (DNS_Header *)buf;
    DNS_Query *dnsqer = (DNS_Query *)malloc(sizeof(DNS_Query *));
    DNS_RR *dnsrr = (DNS_RR *)malloc(sizeof(DNS_RR *));

    memset(buf, 0, sizeof(buf));
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVADDR);
    serv_addr.sin_port = htons(SERVPORT);

    FILE *fd;
    if ((fd = fopen("dns_local.txt", "r+")) == NULL)
    {
        printf("open file failed.\n");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        printf("socket() failed.\n");
        exit(1);
    }

    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1))
    {
        printf("bind() failed.\n");
        exit(1);
    }

    if (listen(sockfd, 10) == -1)
    {
        printf("listen() failed.\n");
        exit(1);
    }

    printf("Listen on %s:%d\n", SERVADDR, SERVPORT);

    while (1)
    {
        memset(buf, 0, sizeof(buf));
        memset(buf_tcp, 0, sizeof(buf_tcp));
        memset(&cli_addr, 0, sizeof(cli_addr));
        i = sizeof(cli_addr);
        if ((clientfd = accept(sockfd, (struct sockaddr *)&cli_addr, &i)) == -1)
        {
            printf("listen() failed.\n");
            continue;
        }
        recv_len = recv(clientfd, buf_tcp, BUF_SIZE, 0);
        memcpy(buf, buf_tcp + 2, recv_len - 2);
        printf("receive %s:%d %dbytes.\n", inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port, recv_len);
        id_real = ntohs(dnshdr->id); //记录初始报文id
        len_query = ReadQuery(dnsqer, buf + sizeof(DNS_Header));
        memset(name, 0, sizeof(name));
        memset(name_ns, 0, sizeof(name_ns));
        dnstodot(name_ns, dnsqer->name, strlen(dnsqer->name));
        flag = FindCache(buf_file, name_ns, fd);
        dnsrr->name = (unsigned char *)calloc(50, sizeof(unsigned char));
        dottodns(dnsrr->name, name_ns, strlen(name_ns));
        readcache(dnsrr, buf_file);
        if (flag == 1 && (dnsqer->qtype == htons(A) && dnsrr->type == htons(A) ||
                          dnsqer->qtype == htons(A) && dnsrr->type == htons(CNAME) ||
                          dnsqer->qtype == htons(CNAME) && dnsrr->type == htons(CNAME) ||
                          dnsqer->qtype == htons(MX) && dnsrr->type == htons(MX)))
        //在缓存中
        {
            dnshdr->tag = htons(0x8180);  //应答，请求递归，支持递归
            dnshdr->queryNum = htons(1);  //问题数1
            dnshdr->answerNum = htons(1); //回答数1
            dnshdr->authorNum = 0;
            dnshdr->addNum = htons(0);

            len_RR = AddRR(buf + sizeof(DNS_Header) + len_query, dnsrr);
            if ((dnsqer->qtype == htons(A) && dnsrr->type == htons(CNAME)) ||
                (dnsqer->qtype == htons(MX) && dnsrr->type == htons(MX))) //CNAME类 或 MX类
            {
                dnstodot(name_ns, dnsrr->rdata, strlen(dnsrr->rdata));
                flag = FindCache(buf_file, name_ns, fd);
                if (flag == 1)
                {
                    dottodns(dnsrr->name, name_ns, strlen(name_ns));
                    readcache(dnsrr, buf_file);
                    dnshdr->addNum = htons(1);
                    len_RR += AddRR(buf + sizeof(DNS_Header) + len_query + len_RR, dnsrr);
                }
            }
            *len_tcp = htons(sizeof(DNS_Header) + len_query + len_RR);
            memcpy(buf_tcp + 2, buf, sizeof(DNS_Header) + len_query + len_RR);
            send_len = send(clientfd, buf_tcp, sizeof(DNS_Header) + len_query + len_RR + 2, 0);
        }
        else //如果不在cache中
        {
            if ((sock_up = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
            {
                printf("sock_up failed.\n");
                exit(1);
            }
            serv_addr.sin_port = htons(0);
            if ((bind(sock_up, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1))
            {
                printf("bind() failed.\n");
                exit(1);
            }
            memset(&up_addr, 0, sizeof(up_addr));
            up_addr.sin_family = AF_INET;
            up_addr.sin_addr.s_addr = inet_addr(ROOTADDR);
            up_addr.sin_port = htons(SERVPORT);

            /*迭代查询*/
            /*如果返回报文不是无结果 或者 不是权威应答*/
            unsigned short iter = 1;
            unsigned short tag = ntohs(dnshdr->tag);
            while (1)
            {
                dnshdr->id = htons(id_real + iter++);
                dnshdr->tag = htons(0x0000); //请求报文,迭代查询
                dnshdr->queryNum = htons(1);
                dnshdr->answerNum = 0;
                dnshdr->authorNum = 0;
                dnshdr->addNum = 0;
                send_len = sendto(sock_up, buf, sizeof(DNS_Header) + len_query,
                                  0, (struct sockaddr *)&up_addr, sizeof(up_addr));
                printf("send %s:%d %d bytes.\n", inet_ntoa(up_addr.sin_addr),
                       up_addr.sin_port, send_len);
                i = sizeof(struct sockaddr_in);
                recv_len = recvfrom(sock_up, buf, BUF_SIZE, 0, (struct sockaddr *)&up_addr, &i);

                /*读取结果*/
                if (dnshdr->answerNum == htons(1))
                    len_RR = ReadRR(dnsrr, buf + sizeof(DNS_Header) + len_query); //读Answer
                if (dnshdr->addNum == htons(1))
                    len_RR += ReadRR(dnsrr, buf + sizeof(DNS_Header) + len_query + len_RR); //读Additional
                memcpy(&up_addr.sin_addr.s_addr, dnsrr->rdata, 4);
                /*printf("receive %s:%d %d bytes, Answer: %s %s.\n", inet_ntoa(up_addr.sin_addr),
                       up_addr.sin_port, recv_len, dnsrr->name, inet_ntoa(up_addr.sin_addr));*/
                memset(tag_bit, 0, sizeof(tag_bit));
                tag = ntohs(dnshdr->tag);
                for (i = 0; i < 16; i++) //按位读取tag
                {
                    tag_bit[i] = tag % 2;
                    tag = tag / 2;
                }
                if (tag_bit[0] == 1 && tag_bit[1] == 1 || tag_bit[10] == 1)
                    break;
            }
            close(sock_up);
            dnshdr->id = htons(id_real);
            if (tag_bit[0] == 1 && tag_bit[1] == 1) //查无结果
                dnshdr->tag = htons(0x8183);        //应答报文，递归查询，支持递归
            else
                dnshdr->tag = htons(0x8180);
            *len_tcp = htons(recv_len);
            memcpy(buf_tcp + 2, buf, recv_len);
            send_len = send(clientfd, buf_tcp, recv_len + 2, 0);
        }
        close(clientfd);
    }
    close(sockfd);
    return 0;
}
