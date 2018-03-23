#ifndef __PROGRAM_DATA_H__
#define __PROGRAM_DATA_H__

#include <arpa/inet.h>

/* user settings */

struct user_opt
{
	u_char if_name[24];   /* interface name */
	u_char mode[24];      /* mode */
	u_int relay_ip;       /* relay agent IP address */
	u_char relay_mac[6];  /* relay agent MAC address */
	int timeout;          /* time-out between messages */
	u_short pack_am;      /* amount of discover packets that will be sent(flood) */
	float lease_time;     /* ip lease time */
	float renewal_time;   /* ip renewal time */
	float rebinding_time; /* ip rebinding time */
};

#endif