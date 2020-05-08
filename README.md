# Iptables Log Analyzer

A tool for the identificaction and detection of network attacks has been developed. The tool was developed in the python programming language and leverages iptables logs to provide further insights about what is happening on a network. The logs produced by the tool can assist the system administrator in the detection of malicious activities conducted by attackers and can be useful within incident handling operations.

# Network interface configuration

## Debian
The network interface configuration file is located in
    
	/etc/network/interfaces
    
To assign a static IP address to an interface you need to modify the file as follows:
    
	auto eth0
	iface eth0 inet static
	address 192.168.1.13
	netmask 255.255.255.0
	network 192.168.1.0
	broadcast 192.168.1.255
	gateway 192.168.1.1 
    
If you want to assign an IP address to the interface using the DHCP protocol, just specify *dhcp* instead of *static*, as follows:
    	 
	auto eth0
	iface eth0 inet dhcp
	address 192.168.1.13
	netmask 255.255.255.0
	network 192.168.1.0
	broadcast 192.168.1.255
	gateway 192.168.1.1
    

NOTE: Once the file has been modified, restart the operating system or simply restart the network service through the command
    
	service networking restart
    
## CentOS
Interface configurations are located in the directory
    
	/etc/sysconfig/network-scripts
    
There are many files in this directory, but those relating to interfaces start with *ifcg*. For example, if we need to modify the file related to the *eth0* interface, the file of interest will be *ifcfg-eth0*. A possible modification of the file, which allows the interface to be assigned a static IP address, is as follows:
     
	DEVICE=eth0
	ONBOOT=yes
	BOOTPROTO=none
	IPADDR=192.168.1.13
	NETMASK=255.255.255.0
	NETWORK=192.168.1.0
	BROADCAST=192.168.1.255
	GATEWAY=192.168.1.1
    
If you want to assign an IP address to the interface using the DHCP protocol, just specify *dhcp* instead of *none* in the BOOTPROTO section, as follows:
    
	DEVICE=eth0
	ONBOOT=yes
	BOOTPROTO=dhcp
	IPADDR=192.168.1.13
	NETMASK=255.255.255.0
	NETWORK=192.168.1.0
	BROADCAST=192.168.1.255
	GATEWAY=192.168.1.1
    
NOTE: Once the file has been modified, restart the operating system or simply restart the network service through the command
    
	/etc/init.d/network restart
    
