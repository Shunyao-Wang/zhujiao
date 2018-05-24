#include <stdio.h>
#include "packet.h"

#define SERVADDR "127.5.5.1"
#define SERVPORT 53
#define BUF_SIZE 1024

int main(int argc, char *argv[])
{
    int sockfd;
    int recv_len, send_len, i, flag;
    unsigned char buf[BUF_SIZE];
    unsigned char name[100] = {0};     //转换成'.'的name
    unsigned char name_ns[50] = {0};   //转换成'.'的ns name
    unsigned char buf_file[100] = {0}; //文件读入缓存
    struct sockaddr_in serv_addr, cli_addr;
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
    if ((fd = fopen("dns_bupt.txt", "r+")) == NULL)
    {
        printf("open file failed.\n");
        exit(1);
    }

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("socket() failed.\n");
        exit(1);
    }

    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1))
    {
        printf("bind() failed.\n");
        exit(1);
    }

    printf("Listen on %s:%d\n", SERVADDR, SERVPORT);
    while (1)
    {
        memset(buf, 0, sizeof(buf));
        memset(&cli_addr, 0, sizeof(cli_addr));
        i = sizeof(cli_addr);
        recv_len = recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr *)&cli_addr, &i);
        printf("receivefrom:%s %d\n", inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
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
            dnshdr->tag = htons(0x8400);  //应答报文，迭代请求，权威应答，不支持递归
            dnshdr->queryNum = htons(1);  //问题数1
            dnshdr->answerNum = htons(1); //回答数1
            dnshdr->authorNum = 0;
            dnshdr->addNum = htons(0);
            /*dnsrr->name = (unsigned char *)calloc(50, sizeof(unsigned char));
            dottodns(dnsrr->name, name_ns, strlen(name_ns));
            readcache(dnsrr, buf_file);*/

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
        }
        else //如果不在cache中
        {
            dnshdr->tag = htons(0x8403); //应答报文，迭代请求，权威应答，名称不存在
            len_RR = 0;
        }
        send_len = sendto(sockfd, buf, sizeof(DNS_Header) + len_query + len_RR,
                          0, (struct sockaddr *)&cli_addr, sizeof(cli_addr));
    }
    close(sockfd);
    return 0;
}
