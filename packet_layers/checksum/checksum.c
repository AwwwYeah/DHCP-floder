#include "headers/checksum.h"

u_short Checksum(u_short *addr, int len)
{
	int sum = 0;
	u_short answer = 0;
	u_short *w = addr;
	int nleft = len;

	while(nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if(nleft == 1)
	{
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;
}

u_short TCPChecksum(struct iphdr *ip, struct tcphdr *tcp, u_char *data)
{
	int segment_len = htons(ip->tot_len) - ip->ihl*4;         // size of tcp segment
	int all_len  = segment_len + sizeof(struct pseudoheader); // size of segment + pseudoheader
    static u_char hdr[128];                                   // memory for full segment
    u_short tcp_check;                                        // checksum

    struct pseudoheader *pshdr = (struct pseudoheader *)hdr;

    pshdr->src_ip     = ip->saddr;
    pshdr->dst_ip     = ip->daddr;
    pshdr->reserved   = 0;
    pshdr->protocol   = ip->protocol;
    pshdr->tcp_length = htons(segment_len);

    memcpy(hdr + sizeof(struct pseudoheader), tcp, tcp->th_off * 4);

    if(data != NULL)
    	memcpy(hdr + sizeof(struct pseudoheader) + tcp->th_off * 4, data, strlen(data));

    tcp_check = Checksum((u_short *)hdr, all_len);

    return tcp_check;

}