#include "headers/interface.h"

u_char *InitInterface(void)
{
	struct ifaddrs *ifdr, *ifa;
	int family;
	static u_char if_name[24];

    /* Get info about interfaces */
	if(getifaddrs(&ifdr) == -1)
	{
		printf("[ERROR] getifaddrs(): %s\n", strerror(errno));

		return NULL;
	}

    /* Find first active interface */
	for(ifa = ifdr; ifa != NULL; ifa = ifa->ifa_next)
	{
		family = ifa->ifa_addr->sa_family;

		if(family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK))
			strncpy(if_name, ifa->ifa_name, strlen(ifa->ifa_name));

	}

	freeifaddrs(ifdr);

	if(if_name[0] == 0)
	  return NULL;

	return if_name;
}

struct if_data *GetIfData(const u_char *if_name, u_char *err)
{
	int sock;
	static struct if_data ifd;
    struct ifreq interface;

    strncpy(interface.ifr_name, if_name, strlen(if_name) + 1);

    sock = socket(PF_INET, SOCK_DGRAM, 0);

    if(ioctl(sock, SIOCGIFHWADDR, &interface) < 0)
    {
    	snprintf(err, 256, "GetIfData() error(mac address): %s", strerror(errno));

    	return NULL;
    }

    memcpy(ifd.if_mac, interface.ifr_hwaddr.sa_data, 6);

    if(ioctl(sock, SIOCGIFADDR, &interface) < 0)
    {
    	snprintf(err, 256, "GetIfData() error(ip address): %s", strerror(errno));

        return NULL;
    }

    memcpy(ifd.if_ip, interface.ifr_addr.sa_data + 2, 4);

    if(ioctl(sock, SIOCGIFINDEX, &interface) < 0)
    {
    	snprintf(err, 256, "GetIfData() error(index): %s", strerror(errno));
    	
    	return NULL;
    }

    ifd.if_index = interface.ifr_ifindex;

    close(sock);

    return &ifd;
}