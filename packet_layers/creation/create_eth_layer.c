#include "headers/create_eth_layer.h"

struct ethhdr *CreateEthLayer(u_char *dst, u_char *src, u_short prot)
{
	struct ethhdr *eth = (struct ethhdr *)malloc(ETH_HLEN);

	memcpy(eth->h_dest, dst, ETH_ALEN);
	memcpy(eth->h_source, src, ETH_ALEN);
	eth->h_proto = htons(prot);

    return eth;
}