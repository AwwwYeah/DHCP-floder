#ifndef __CR_ETH_LAYER_H__
#define __CR_ETH_LAYER_H__

#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

struct ethhdr *CreateEthLayer(u_char *dst, u_char *src, u_short prot);

#endif