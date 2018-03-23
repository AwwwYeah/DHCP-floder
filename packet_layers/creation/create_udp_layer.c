#include "headers/create_udp_layer.h"

struct udphdr *CreateUDPLayer(u_short source, u_short dest, u_short prot_len)
{
	struct udphdr *udp = (struct udphdr *)malloc(UDP_HLEN);

	udp->uh_sport = htons(source);
	udp->uh_dport = htons(dest);
	udp->uh_ulen  = htons(UDP_HLEN + prot_len);
	udp->uh_sum   = 0;

	return udp;

	/* Checksum will be later */
}