#include <stdio.h>
#include "packet.h"

#define SERVADDR "127.1.1.1"
#define SERVPORT 53
#define BUF_SIZE 1024

int PrintRR(DNS_RR *dnsrr);

int main(int argc, char *argv[])
{
    int sockfd;
    int send_len, recv_len;
    int i = 0;
    int len_query, len_rr;
    unsigned char buf[BUF_SIZE];
    unsigned char buf_tcp[BUF_SIZE];                     //tcp报文头两个字节为长度
    unsigned short *len_tcp = (unsigned short *)buf_tcp; //TCP报文长度
    unsigned char name_chs[100];
    unsigned short tag;
    unsigned char tag_bit[16] = {0}; //按位读tag
    DNS_Header *dnshdr = (DNS_Header *)buf;
    DNS_Query *dnsqer = (DNS_Query *)malloc(sizeof(DNS_Query *));
    DNS_RR *dnsrr = (DNS_RR *)malloc(sizeof(DNS_RR *));
    struct sockaddr_in serv_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) //STREAM TCP
    {
        printf("socket() failed.\n");
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(SERVADDR);
    serv_addr.sin_port = htons(SERVPORT);

    memset(buf_tcp, 0, BUF_SIZE);
    memset(buf, 0, BUF_SIZE);
    dnshdr->id = htons(0x0001);  //编号为1
    dnshdr->tag = htons(0x0100); //查询报文,递归查询
    dnshdr->queryNum = htons(1); //问题数1
    dnshdr->answerNum = 0;
    dnshdr->authorNum = 0;
    dnshdr->addNum = 0;

    dnsqer->name = (unsigned char *)calloc(50, sizeof(unsigned char));

    strcpy(name_chs, argv[1]);
    dottodns(dnsqer->name, name_chs, strlen(name_chs));
    if (strcmp(argv[2], "A") == 0)
        dnsqer->qtype = htons(A);
    else if (strcmp(argv[2], "CNAME") == 0)
        dnsqer->qtype = htons(CNAME);
    else if (strcmp(argv[2], "MX") == 0)
        dnsqer->qtype = htons(MX);
    dnsqer->qclass = htons(0x0001);
    len_query = AddQuery(buf + sizeof(DNS_Header), dnsqer);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1)
    {
        printf("connect() failed.\n");
        exit(1);
    }

    *len_tcp = htons(sizeof(DNS_Header) + len_query); //在报文前面加长度
    memcpy(buf_tcp + 2, buf, sizeof(DNS_Header) + len_query);
    send_len = send(sockfd, buf_tcp, sizeof(DNS_Header) + len_query + 2, 0);
    printf("send: %d bytes.\nAsk: %s\n", send_len, argv[1]);

    recv_len = recv(sockfd, buf_tcp, BUF_SIZE, 0);
    memcpy(buf, buf_tcp + 2, recv_len - 2);
    printf("receive: %d bytes.\n", recv_len);

    tag = ntohs(dnshdr->tag);
    for (i = 0; i < 16; i++) //按位读取tag
    {
        tag_bit[i] = tag % 2;
        tag = tag / 2;
    }
    if (tag_bit[0] == 1 && tag_bit[1] == 1)
        printf("NO FIND!\n");
    else
    {
        len_rr = ReadRR(dnsrr, buf + sizeof(DNS_Header) + len_query);
        PrintRR(dnsrr);
        if (dnshdr->addNum == htons(1))
        {
            len_rr = ReadRR(dnsrr, buf + sizeof(DNS_Header) + len_query + len_rr);
            PrintRR(dnsrr);
        }
    }
    close(sockfd);
    return 0;
}

int PrintRR(DNS_RR *dnsrr)
{
    unsigned char buf[50] = {0};
    dnstodot(buf, dnsrr->name, strlen(dnsrr->name));
    printf("%s ", buf);
    if (dnsrr->type == htons(A))
    {
        printf("A ");
        printf("%u.%u.%u.%u ", dnsrr->rdata[0],
               dnsrr->rdata[1], dnsrr->rdata[2], dnsrr->rdata[3]);
    }
    else if (dnsrr->type == htons(CNAME))
    {
        printf("CNAME ");
        dnstodot(buf, dnsrr->rdata, strlen(dnsrr->rdata));
        printf("%s ", buf);
    }
    else if (dnsrr->type == htons(MX))
    {
        printf("MX %d ", ntohs(dnsrr->perference));
        dnstodot(buf, dnsrr->rdata, strlen(dnsrr->rdata));
        printf("%s ", buf);
    }
    if (dnsrr->_class == htons(0x0001))
        printf("IN ");
    printf("%d\n", ntohl(dnsrr->ttl));
    return 0;
}
