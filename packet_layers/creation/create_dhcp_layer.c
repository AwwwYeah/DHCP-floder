#include "headers/create_dhcp_layer.h"

u_char *CreateStandartDiscover(u_int ls_time, u_int rn_time, u_int rb_time)
{
	u_char *stand_disc = (u_char *)malloc(22);

	stand_disc[0] = DHCP_OPT_TYPE;
	stand_disc[1] = 0x01;
	stand_disc[2] = DHCP_DISCOVER;
	stand_disc[3] = DHCP_OPT_ADDR_LS_TIME;
	stand_disc[4] = 0x04;
	memcpy(&stand_disc[5], (void *)&ls_time, 4);
	stand_disc[9] = DHCP_OPT_ADDR_RN_TIME;
	stand_disc[10] = 0x04;
	memcpy(&stand_disc[11], (void *)&rn_time, 4);
	stand_disc[15] = DHCP_OPT_ADDR_RB_TIME;
	stand_disc[16] = 0x04;
	memcpy(&stand_disc[17], (void *)&rb_time, 4);
	stand_disc[21] = DHCP_OPT_END;

	return stand_disc;
}

u_char *CreateStandartRequest(u_int req_addr, u_int ls_time, u_int rn_time, 
							  u_int rb_time, u_int srv_addr)
{
	u_char *stand_req = (u_char *)malloc(34);

	stand_req[0] = DHCP_OPT_TYPE;
	stand_req[1] = 0x01;
	stand_req[2] = DHCP_REQUEST;
	stand_req[3] = DHCP_OPT_SRV_IDENT;
	stand_req[4] = 0x04;
	memcpy(&stand_req[5], &srv_addr, 4);
	stand_req[9] = DHCP_OPT_REQ_ADDR;
	stand_req[10] = 0x04;
	memcpy(&stand_req[11], &req_addr, 4);
	stand_req[15] = DHCP_OPT_ADDR_LS_TIME;
	stand_req[16] = 0x04;
	memcpy(&stand_req[17], &ls_time, 4);
	stand_req[21] = DHCP_OPT_ADDR_RN_TIME;
	stand_req[22] = 0x04;
	memcpy(&stand_req[23], &rn_time, 4);
	stand_req[27] = DHCP_OPT_ADDR_RB_TIME;
	stand_req[28] = 0x04;
	memcpy(&stand_req[29], &rb_time, 4);
	stand_req[33] = DHCP_OPT_END;

	return stand_req;
}

u_char *CreateStandartRelease(u_int srv_addr)
{
	u_char *stand_dec = (u_char *)malloc(10);

	stand_dec[0] = DHCP_OPT_TYPE;
	stand_dec[1] = 0x01;
	stand_dec[2] = DHCP_RELEASE;
	stand_dec[3] = DHCP_OPT_SRV_IDENT;
	stand_dec[4] = 0x04;
	memcpy(&stand_dec[5], &srv_addr, 4);
	stand_dec[9] = DHCP_OPT_END;

	return stand_dec;
}