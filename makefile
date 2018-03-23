dhcp_flooder.o: dhcp_flooder.c
	gcc -g -c dhcp_flooder.c

set_settings.o: settings/set_settings.c
	gcc -g -c settings/set_settings.c

interface.o: interface_socket/interface.c
	gcc -g -c interface_socket/interface.c

socket.o: interface_socket/socket.c
	gcc -g -c interface_socket/socket.c

eth_layer.o: packet_layers/creation/create_eth_layer.c
	gcc -g -c packet_layers/creation/create_eth_layer.c

ip_layer.o: packet_layers/creation/create_ip_layer.c
	gcc -g -c packet_layers/creation/create_ip_layer.c

checksum.o: packet_layers/checksum/checksum.c
	gcc -g -c packet_layers/checksum/checksum.c

udp_layer.o: packet_layers/creation/create_udp_layer.c
	gcc -g -c packet_layers/creation/create_udp_layer.c

bootp_layer.o: packet_layers/creation/create_bootp_layer.c
	gcc -g -c packet_layers/creation/create_bootp_layer.c

dhcp_layer.o: packet_layers/creation/create_dhcp_layer.c
	gcc -g -c packet_layers/creation/create_dhcp_layer.c

attacks.o: attacks/attacks.c
	gcc -g -c attacks/attacks.c -pthread

install: dhcp_flooder.o set_settings.o interface.o socket.o eth_layer.o \
ip_layer.o checksum.o udp_layer.o bootp_layer.o dhcp_layer.o attacks.o 
	gcc -g -o dhcpkiller *.o -pthread
	${MAKE} clean

clean:
	rm -f *.o
