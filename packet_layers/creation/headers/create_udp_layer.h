#ifndef __CR_UDP_LAYER_H__
#define __CR_UDP_LAYER_H__

#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/udp.h>

#define UDP_HLEN 8

struct udphdr *CreateUDPLayer(u_short source, u_short dest, u_short prot_len);

#endif