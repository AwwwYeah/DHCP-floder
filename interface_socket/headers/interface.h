#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <linux/if_ether.h>

struct if_data
{
    u_char if_mac[ETH_ALEN];
    u_char if_ip[4];
    u_int if_index;
};

/* initialization of first free interface */
u_char *InitInterface(void);

/* get information about interface */
struct if_data *GetIfData(const u_char *if_name, u_char *err);

#endif