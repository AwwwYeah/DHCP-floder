# DHCP-flooder
Attacks on DHCP server(flood and starvation)

This program was made for Man-In-The-Middle attack's first step.
That have two modules: "Discover flood" and "Addresses pool starvation"

*MODES*

        -Flood
        -Starvation

*SETTINGS*

        General settings:
        -i - interface will be used
        -m(--mode) - Flood/starvation mode
        -h(--help) - Show help note and exit from the program
        --default  - Show default messages' settings and exit from the program
        
        Flood settings:
        -t(--time-out) - Time-out between sending of messages
        -c             - Amount of packets that will be sent in (--time-out)
        
        Starvation settings:
        -lt(--lease-time)     - Address lease time(seconds)
        -rt(--renewal-time)   - Address renewal time(seconds)
        -rbt(--rebindng-time) - Address rebinding time(seconds)
        --relay-ip  - Relay agent IP address
        --relay-mac - Relay agent MAC address
        
*INSTALL*
        
        make install
        
*USING*
    
        ./dhcpkiller -i eth0 -m flood --relay-ip 192.168.60.2 --relay-mac a1:b2:c3:d4:e5:f6 --time-out 1

        ./dhcpkiller -m starvation --lease-time 1200

        ./dhcpkiller -m free
