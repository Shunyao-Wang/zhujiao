#ifndef PACKET_H
#define PACKET_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF_SIZE 1024
#define A 1
#define NS 2
#define CNAME 5
#define MX 15

typedef struct DNS_Header
{
    unsigned short id;
    unsigned short tag; //(包含QR到Rcode的定义)
    unsigned short queryNum;
    unsigned short answerNum;
    unsigned short authorNum;
    unsigned short addNum;
} DNS_Header;

typedef struct DNS_Query
{
    unsigned char *name;
    unsigned short qtype;
    unsigned short qclass;
} DNS_Query;

typedef struct DNS_RR
{
    unsigned char *name;
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
    unsigned short perference;
    unsigned char *rdata;
} DNS_RR;

int dottodns(unsigned char *dns, unsigned char *dot, int len);
int dnstodot(unsigned char *dot, unsigned char *dns, int len);
int readcache(DNS_RR *dnsrr, unsigned char *buf_file);
int FindCache(unsigned char *buf_file, unsigned char *name, FILE *fd);

int ReadQuery(DNS_Query *dnsqer, unsigned char *packet);
int ReadRR(DNS_RR *dnsrr, unsigned char *packet);
int AddQuery(unsigned char *packet, DNS_Query *dnsqer);
int AddRR(unsigned char *packet, DNS_RR *dnsrr);

#endif