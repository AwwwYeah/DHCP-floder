#ifndef __ATTACKS_H__
#define __ATTACKS_H__

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "../settings/headers/set_settings.h"
#include "../settings/headers/program_data.h"
#include "../interface_socket/headers/interface.h"
#include "../interface_socket/headers/socket.h"
#include "../packet_layers/creation/headers/create_eth_layer.h"
#include "../packet_layers/creation/headers/create_ip_layer.h"
#include "../packet_layers/checksum/headers/checksum.h"
#include "../packet_layers/creation/headers/create_udp_layer.h"
#include "../packet_layers/creation/headers/create_bootp_layer.h"
#include "../packet_layers/creation/headers/create_dhcp_layer.h"

struct messg_data
{
	u_int xid;  	      /* transaction id */
	u_int offer_addr;     /* offered address */
	u_char client_mac[6]; /* client mac */
	u_int srv_addr;       /* server address */
	u_int ls_time;        /* lease time */
	u_char messg_type;    /* message type */
};

#define STAND_DISCOVER_LEN 304
#define STAND_REQUEST_LEN 316
#define STAND_RELEASE_LEN 292

#define PATH_TO_FILE "addrs.txt" 
int BREAK; // Cycle variable

/* Standart discover flood */
void DHCPFlood(int sock, struct user_opt *uopt);

/* Starvation attack */
void DHCPStarvation(int sock, struct user_opt *uopt);

/* Free all reserved addresses from file(addrs.txt) */
int FreeAddrs(int sock);

void RecvMessg(void *channel);

/* Signal SIGINT handler */
void SigHandler(int arg);

#endif

