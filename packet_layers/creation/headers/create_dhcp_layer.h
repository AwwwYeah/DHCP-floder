#ifndef __CR_DHCP_LAYER_H__
#define __CR_DHCP_LAYER_H__

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../../protocols/dhcp.h"

u_char *CreateStandartDiscover(u_int ls_time, u_int rn_time, u_int rb_time);

u_char *CreateStandartRequest(u_int req_addr, u_int ls_time, u_int rn_time,
							  u_int rb_time, u_int srv_addr);

u_char *CreateStandartRelease(u_int srv_addr);

#endif