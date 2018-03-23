#include "headers/socket.h"

int CreateRawSock(const struct if_data *ifd, u_short protocol, u_char *err)
{
	int sock;
	struct sockaddr_ll sll;

	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		snprintf(err, 256, "CreateRawSock() error(open): %s", strerror(errno));

		return -1;
	}

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(protocol);
	sll.sll_halen = ETH_ALEN;
	sll.sll_ifindex = ifd->if_index;

	memcpy(sll.sll_addr, ifd->if_mac, ETH_ALEN);

	if(bind(sock, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) < 0)
	{
		snprintf(err, 256, "CreateRawSock() error(bind): %s", strerror(errno));

		return -1;
	}

    return sock;
}