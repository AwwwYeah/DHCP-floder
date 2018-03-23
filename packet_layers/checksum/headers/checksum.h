#ifndef __IP_CHECKSUM_H__
#define __IP_CHECKSUM_H__

#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

struct pseudoheader
{
    u_int src_ip;
    u_int dst_ip;
    u_char reserved;
    u_char protocol;
    u_short tcp_length;
};

u_short Checksum(u_short *addr, int len);

u_short TCPChecksum(struct iphdr *ip, struct tcphdr *tcp, u_char *data);

#endif