#ifndef __SOCKET_H__
#define __SOCKET_H__

#include "interface.h"
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* Create a raw socket */
int CreateRawSock(const struct if_data *md, u_short protocol, u_char *err);

#endif