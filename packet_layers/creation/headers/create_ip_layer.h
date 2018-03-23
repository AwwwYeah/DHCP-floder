#ifndef __CR_IP_LAYER_H__
#define __CR_IP_LAYER_H__

#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define IP_HLEN 20

struct iphdr *CreateIPLayer(u_char hl, u_char vers, u_char tos, u_short id, 
							u_short off, u_char ttl, u_char prot, u_int src,
						    u_int dst, u_short prot_len);

#endif