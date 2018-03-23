#ifndef __DHCP__
#define __DHCP__

#define BOOTP_HLEN 240

/* Types of BOOTP-messages */
#define BOOTP_REQUEST 1
#define BOOTP_REPLY 2

/* Hardware address type */
#define BOOTP_HTYPE_ETHER 1

/* DHCP-options codes */
#define DHCP_OPT_SUB_MASK 1
#define DHCP_OPT_TIME_OFF 2
#define DHCP_OPT_ROUTER 3
#define DHCP_OPT_HOST_NAME 12
#define DHCP_OPT_DOMAIN_NAME 15
#define DHCP_OPT_DNS 6
#define DHCP_OPT_INF_MTU 26
#define DHCP_OPT_BROAD_ADDR 28
#define DHCP_OPT_STAT_ROUTE 33
#define DHCP_OPT_NTP_SRV 42
#define DHCP_OPT_VENDOR_INF 43
#define DHCP_OPT_NETB_NS 44
#define DHCP_OPT_NETB_SC 47
#define DHCP_OPT_ADDR_LS_TIME 51
#define DHCP_OPT_TYPE 53      
#define DHCP_OPT_SRV_IDENT 54 
#define DHCP_OPT_PARAM_LIST 55
#define DHCP_OPT_MSG 56
#define DHCP_OPT_MAX_SIZE 57
#define DHCP_OPT_ADDR_RN_TIME 58
#define DHCP_OPT_ADDR_RB_TIME 59
#define DHCP_OPT_REQ_ADDR 50 
#define DHCP_OPT_DOMAIN_SEARCH 119
#define DHCP_OPT_CLASS_STAT_ROUTE 121
#define DHCP_OPT_PRIV_CLASS_STAT_ROUTE 249
#define DHCP_OPT_PRIV_PROX_AUTODISC 252
#define DHCP_OPT_END 255

/* Types of DHCP-messages */
#define DHCP_DISCOVER 1       
#define DHCP_OFFER 2          
#define DHCP_REQUEST 3        
#define DHCP_DECLINE 4
#define DHCP_ACK 5 
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

#define DHCP_COOKIE 0x63825363

struct bootphdr
{
  u_char type;          /* Type of BOOTP-message */ 
  u_char htype;         /* Hardware address type */
  u_char hlen;          /* Hardware address length */
  u_char hops;          /* Amount of agents */
  u_int xid;            /* Session ID */
  u_short secs;         /* Amount of seconds from the start of operation */
  u_short flags;        /* Unicast/multicast flag */
  u_int ciaddr;         /* Client address */
  u_int yaddr;          /* Issued address by server */
  u_int siaddr;         /* Next server address */
  u_int giaddr;         /* Agent address */
  u_char chaddr[16];    /* Client MAC address */
  u_char sname[64];     /* Serer name */
  u_char file[128];     /* File that will be save any settings */
  u_int dhcp_cookie;    
};

#endif
