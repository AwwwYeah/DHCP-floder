#include "headers/create_ip_layer.h"

struct iphdr *CreateIPLayer(u_char hl, u_char vers, u_char tos, u_short id, 
							u_short off, u_char ttl, u_char prot,
							u_int src, u_int dst, u_short prot_len)
{
	struct iphdr *ip = (struct iphdr *)malloc(IP_HLEN);

	ip->ihl 	 = hl;
	ip->version  = vers;
	ip->tos		 = tos;
	ip->tot_len  = htons(IP_HLEN + prot_len);
	ip->id       = htons(id);
	ip->frag_off = htons(off);
	ip->ttl 	 = ttl;
	ip->protocol = prot;
	ip->check    = 0;
	ip->saddr 	 = src;
	ip->daddr	 = dst;

	/* Checksum will be later */

	return ip;
}