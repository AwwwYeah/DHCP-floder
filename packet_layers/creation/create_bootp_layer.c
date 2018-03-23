#include "headers/create_bootp_layer.h"

struct bootphdr *CreateBootpLayer(u_char type, u_char htype, u_char hlen, u_char hops,
					   u_int xid, u_short secs, u_short flags, u_int ciaddr,
					   u_int yaddr, u_int siaddr, u_int giaddr, u_char *chaddr,
					   u_char *sname, u_char *file, u_int cookie)
{
	struct bootphdr *bootp = (struct bootphdr *)malloc(BOOTP_HLEN);

	memset(bootp, 0x0, BOOTP_HLEN);

	bootp->type  = type;
	bootp->htype = htype;
	bootp->hlen  = hlen;
	bootp->hops  = hops;
	bootp->xid   = htonl(xid);
	bootp->secs	 = htons(secs);
	bootp->flags = htons(flags);
	bootp->ciaddr = ciaddr;
	bootp->yaddr  = yaddr;
	bootp->siaddr = siaddr;
	bootp->giaddr = giaddr;
	memcpy(bootp->chaddr, chaddr, 6);

	if(sname != 0)
		memcpy(bootp->sname, sname, 64);

	if(file != 0)
		memcpy(bootp->file, file, 128);
	
	bootp->dhcp_cookie = htonl(cookie);

	return bootp;
}