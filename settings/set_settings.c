#include "headers/set_settings.h"

struct user_opt *OptParser(char **main_arg, int arg_count, u_char *err)
{
	short i;
	static struct user_opt u_opt;

	memset(&u_opt, 0x0, sizeof(struct user_opt));
	memset(err, 0x0, 256);

	for(i = 1; i < arg_count; i++)
	{
		if(!strcmp("-i", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: interface name isn't set");

				return NULL;
			}

			strncpy(u_opt.if_name, main_arg[i], strlen(main_arg[i]));

			continue;
		}

		if(!strcmp("-m", main_arg[i]) || !strcmp("--mode", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: mode isn't set");

				return NULL;
			}

			if(!strcmp("starvation", main_arg[i]))
				strncpy(u_opt.mode, main_arg[i], 24);

			else if(!strcmp("flood", main_arg[i]))
				strncpy(u_opt.mode, main_arg[i], 24);

			else if(!strcmp("free", main_arg[i]))
				strncpy(u_opt.mode, main_arg[i], 24);

			else
			{
				snprintf(err, 256, "OptParser() error: unknown mode \"%s\"", main_arg[i]);

				return NULL;
			}

			continue;
		}

		if(!strcmp("-t", main_arg[i]) || !strcmp("--time-out", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: time-out isn't set");

				return NULL;
			}

			u_opt.timeout = atoi(main_arg[i]);

			continue;
		}

		if(!strcmp("-c", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: amount of discover packets isn't set");

				return NULL;
			}

			u_opt.pack_am = atoi(main_arg[i]);

			continue;
		}

		if(!strcmp("--relay-ip", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: spoof ip address isn't set");

				return NULL;
			}

			u_opt.relay_ip = inet_addr(main_arg[i]);

			continue;
		}

		if(!strcmp("--relay-mac", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: spoof mac address isn't set");

				return NULL;
			}

			u_char temp_mac[6];

			StrToMac(main_arg[i], u_opt.relay_mac);

			continue;
		}

		if(!strcmp("--lease-time", main_arg[i]) || !strcmp("-lt", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: lease time isn't set");

				return NULL;
			}

			u_opt.lease_time = atoi(main_arg[i]);
			u_opt.lease_time = htonl(u_opt.lease_time);

			continue;
		}

		if(!strcmp("--renewal-time", main_arg[i]) || !strcmp("-rt", main_arg[i])) 
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: renewal time isn't set");

				return NULL;
			}

			u_opt.renewal_time = atoi(main_arg[i]);
			u_opt.renewal_time = htonl(u_opt.renewal_time);

			continue;
		}

		if(!strcmp("--rebinding-time", main_arg[i]) || !strcmp("-rbt", main_arg[i]))
		{
			i++;

			if(main_arg[i] == 0)
			{
				snprintf(err, 256, "OptParser() error: rebinding time isn't set");

				return NULL;
			}

			u_opt.rebinding_time = atoi(main_arg[i]);
			u_opt.rebinding_time = htonl(u_opt.rebinding_time);

			continue;
		}

		if(!strcmp("-h", main_arg[i]) || !strcmp("--help", main_arg[i]) )
		{
			help();

			return NULL;
		}

		if(!strcmp("--default", main_arg[i]))
		{
			ShowDefSet();

			return NULL;
		}

		snprintf(err, 256, "OptParser() error: unknown argument \"%s\"", main_arg[i]);

		return NULL;
	}

	if(u_opt.mode[0] == '\0')
	{
		snprintf(err, 256, "Mode isn't set(starvation/flood)");

		return NULL;
	}

	return &u_opt;
}

void StrToMac(const u_char *string, u_char *mac)
{
	int byte_count = 0, char_count = 0;

	while(byte_count < 6)
	{
		mac[byte_count] = strtol(&string[char_count], NULL, 16);

		byte_count++;
		char_count += 3;
	}

	return;
}

void InitSettings(struct user_opt *u_opt, u_int s_ip, u_char *s_mac)
{
	if(u_opt->pack_am == 0)
		u_opt->pack_am = 10;

	if(u_opt->timeout == 0)
		u_opt->timeout = 1;

	if(u_opt->lease_time == 0)
		u_opt->lease_time = htonl(60); // Default lease time

	/* If renewal time isn't set, calculate 
	   percentage of lease time and put it in 
	   renewal time. It's %50 of lease time (RFC-1034) */
	if(u_opt->renewal_time == 0)
	    u_opt->renewal_time = u_opt->lease_time / 100 * 50;
	
	/* Anology situation. Calculate percentage of lease time
	   and put it in rebinding time. It's %90 of lease time (RFC-1034) */
	if(u_opt->rebinding_time == 0)
		u_opt->rebinding_time = u_opt->lease_time / 100 * 90;
	
	return;
}

void help(void)
{
	printf("\n*****DHCP flooder by Valentine4567******\n\n");
	
	printf("General settings\n");
	printf("-i             - Interface\n");
	printf("-m(--mode)     - Starvation/flood/free mode(starvation/flood/free)\n");
	printf("-h(--help)     - Show this note and finish the program\n");
	printf("--default      - Show default settings that program will use\n\n");

	printf("Flood settings:\n");
	printf("-t(--time-out)         - Time out between messages\n");
	printf("-c                     - Amount of packets that will be sent in (--time-out) interval\n\n");
	
	printf("Starvation settings:\n");
	printf("-lt (--lease-time)     - Address lease time(seconds)\n");
	printf("-rt (--renewal-time)   - Address renewal time(seconds)\n");
	printf("-rbt(--rebinding-time) - Address rebinding time(seconds)\n");
	printf("--relay-ip             - Relay agent IP address\n");
	printf("--relay-mac            - Relay agent MAC address\n");
	printf("After using of this mode you can free reserved addresses, just run \"free mode\"\n");
	printf("Options \"--relay-ip\" and \"--relay-mac\" must be set as your address\n\n");

	printf("Flood:\n");
	printf("./dhcpkiller -i wlan0 -m flood\n\n");

	printf("Starvation:\n");
	printf("./dhcpkiller -m starvation --relay-mac 58:a1:ff:66:85:51 --relay-ip 192.168.0.2 -lt 1200\n\n");

	printf("Free addresses:\n");
	printf("./dhcpkiller -m free\n");
}

void ShowDefSet(void)
{
	printf("\nGeneral settings:\n");
	printf("Interface:   first active\n");
	printf("File:  		\"addrs.txt\"\n\n");

	printf("Flood settings:\n");
	printf("Time-out:   		1 seconds\n");
	printf("Packets amount:     10 packets in (time-out)\n");	
	printf("Sender MAC address: randomized\n\n");

    printf("Starvation settings:\n");
	printf("Lease time:     60 seconds\n");
	printf("Renewal time:   30 seconds\n");
	printf("Rebinding time: 54 seconds\n\n");
	printf("Relay agent IP address:  must be set with an option\n");
	printf("Relay agent MAC address: must be set with an option\n");

	return;
}