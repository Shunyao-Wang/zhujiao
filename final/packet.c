#include "packet.h"

int dottodns(unsigned char *dns, unsigned char *dot, int len)
{
    unsigned char *p_chs, *p_dns;
    int i = 0;
    memset(dns, 0, sizeof(dns));
    p_chs = dot;
    p_dns = dns + 1;
    while (p_chs < (dot + len))
    {
        if (*p_chs == '.')
        {
            *(p_dns - i - 1) = i;
            i = 0;
        }
        else
        {
            *p_dns = *p_chs;
            i++;
        }
        p_dns++;
        p_chs++;
    }
    *(p_dns - i - 1) = i;
    return 0;
}

int dnstodot(unsigned char *dot, unsigned char *dns, int len)
{
    unsigned char *p_1, *p_2;
    int i, num;
    memset(dot, 0, sizeof(dot));
    p_1 = dns;
    p_2 = dot;
    while (p_1 < (dns + len))
    {
        num = *(p_1);
        p_1++;
        for (i = 0; i < num; i++)
        {
            *(p_2++) = *(p_1++);
        }
        if (*(p_1) != 0)
        {
            *(p_2) = '.';
            p_2++;
        }
    }
    return 0;
}

int readcache(DNS_RR *dnsrr, unsigned char *buf_file)
{
    unsigned char *p = buf_file;
    unsigned char buf[6] = {0};
    int len = 0;
    int len_per = 0;
    while (*p != ',')
    {
        p++;
    }
    p++;
    for (int i = 0; *p != ','; i++)
    {
        buf[i] = *(p++);
    }
    dnsrr->ttl = htonl(atoi(buf));
    p++;
    if (*p == 'I' && *(p + 1) == 'N')
    {
        dnsrr->_class = htons(0x0001);
    }
    while (*p != ',')
    {
        p++;
    }
    p++;
    if (*p == 'A')
    {
        dnsrr->type = htons(A);
        dnsrr->data_len = htons(0x0004);
        p += 2;
        dnsrr->rdata = (unsigned char *)calloc(4, sizeof(unsigned char));
        int i = 0;
        int j = 0;
        memset(buf, 0, sizeof(buf));
        while (*p != '\n')
        {
            if (*p != '.')
            {
                buf[i] = *p;
                i++;
            }
            else
            {
                *(dnsrr->rdata + j) = atoi(buf);
                j++;
                memset(buf, 0, sizeof(buf));
                i = 0;
            }
            p++;
        }
        *(dnsrr->rdata + j) = atoi(buf);
    }
    else
    {
        if (*p == 'N' && *(p + 1) == 'S')
        {
            dnsrr->type = htons(NS);
            p += 3;
        }
        else if (*p == 'C' && *(p + 1) == 'N' && *(p + 2) == 'A' && *(p + 3) == 'M' && *(p + 4) == 'E')
        {
            dnsrr->type = htons(CNAME);
            p += 6;
        }
        else if (*p == 'M' && *(p + 1) == 'X')
        {
            dnsrr->type = htons(MX);
            p += 3;
            int i = 0;
            memset(buf, 0, sizeof(buf));
            while (*p != ',')
            {
                buf[i++] = *(p++);
            }
            dnsrr->perference = htons(atoi(buf));
            p++;
            len_per = 2;
        }
        for (len = 1; *(p + len) != '\n'; len++)
            ;
        dnsrr->rdata = (unsigned char *)calloc(50, sizeof(unsigned char));
        dottodns(dnsrr->rdata, p, len);
        dnsrr->data_len = htons(len + 2 + len_per);
    }
    return 0;
}

int ReadQuery(DNS_Query *dnsqer, unsigned char *packet)
{
    int name_len = 0;
    unsigned char *p = packet;
    dnsqer->name = (unsigned char *)calloc(50, sizeof(unsigned char));
    while (*p != 0)
    {
        dnsqer->name[name_len++] = *(p++);
    }
    name_len++;
    p++;
    memcpy(&dnsqer->qtype, p, 2);
    p += 2;
    memcmp(&dnsqer->qclass, p, 2);
    return name_len + 4;
}

int ReadRR(DNS_RR *dnsrr, unsigned char *packet)
{
    int name_len = 0;
    int len_per = 0;
    unsigned char *p = packet;
    dnsrr->name = (unsigned char *)calloc(50, sizeof(unsigned char));
    dnsrr->rdata = (unsigned char *)calloc(50, sizeof(unsigned char));
    while (*p != 0)
    {
        dnsrr->name[name_len++] = *(p++);
    }
    name_len++;
    p++;
    memcpy(&dnsrr->type, p, 2);
    p += 2;
    memcpy(&dnsrr->_class, p, 2);
    p += 2;
    memcpy(&dnsrr->ttl, p, 4);
    p += 4;
    memcpy(&dnsrr->data_len, p, 2);
    p += 2;
    if (dnsrr->type == htons(MX))
    {
        memcpy(&dnsrr->perference, p, 2);
        p += 2;
        len_per = 2;
    }
    memcpy(dnsrr->rdata, p, ntohs(dnsrr->data_len) - len_per);
    return name_len + 10 + ntohs(dnsrr->data_len);
}

int AddQuery(unsigned char *packet, DNS_Query *dnsqer)
{
    int name_len;
    unsigned char *p = packet;
    name_len = strlen(dnsqer->name) + 1;
    memcpy(p, dnsqer->name, name_len);
    p += name_len;
    memcpy(p, &dnsqer->qtype, 2);
    p += 2;
    memcpy(p, &dnsqer->qclass, 2);
    return name_len + 4;
}

int AddRR(unsigned char *packet, DNS_RR *dnsrr)
{
    int name_len = 0;
    int len_per = 0;
    unsigned char *p = packet;
    while (dnsrr->name[name_len] != 0)
    {
        *(p++) = dnsrr->name[name_len++];
    }
    name_len++;
    p++;
    memcpy(p, &dnsrr->type, 2);
    p += 2;
    memcpy(p, &dnsrr->_class, 2);
    p += 2;
    memcpy(p, &dnsrr->ttl, 4);
    p += 4;
    memcpy(p, &dnsrr->data_len, 2);
    p += 2;
    if (dnsrr->type == htons(MX))
    {
        memcpy(p, &dnsrr->perference, 2);
        p += 2;
        len_per = 2;
    }
    memcpy(p, dnsrr->rdata, ntohs(dnsrr->data_len) - len_per);
    return name_len + 10 + ntohs(dnsrr->data_len);
}

int FindCache(unsigned char *buf_file, unsigned char *name, FILE *fd)
{
    int flag = 0;
    int j;
    char a[100];
    fseek(fd, 0, SEEK_SET);
    memset(buf_file, 0, sizeof(buf_file));
    while (fgets(buf_file, BUF_SIZE, fd) != NULL)
    {
        j = 0;
        memset(a, 0, sizeof(a));
        while (buf_file[j] != ',')
        {
            a[j] = buf_file[j];
            j++;
        }
        if (strcmp(a, name) == 0)
        {
            flag = 1;
            break;
        }
        memset(buf_file, 0, sizeof(buf_file));
    }
    return flag;
}