#!/bin/bash

python3 setup.py install
echo "Searching for attacks ..."
iptla
echo "Search completed! You can find the attacks of today and past days in the file \"attacks\"

while true: do
	read-p "Do you want to install a preconfigured package of iptables? " yn
	case $yn in
		[Yy]* ) echo "Installation in progress ...";
			iptables -A OUTPUT -p udp --dport 5353 -j DROP	# mDNS
			iptables -A OUTPUT -p udp --dport 1900 -j DROP	# SSDP
			iptables -A OUTPUT -p tcp --dport 135 -j DROP	# Microsoft RPC
			iptables -A OUTPUT -p udp --dport 123 -j DROP	# NTP
			echo "Installation completed!";
			break;;
		[Nn]* ) break;;
		* ) echo "Answer yes or no";;
	esac
done

while true; do
	read -p "Do you want to block communication with other ports? " yn
	case $yn in
		[Yy]* ) read -p "Indicate the chain (PREROUTING, INPUT, FORWARD, POSTROUTING, OUTPUT): " chain
			read -p "Indicate the protcol: " proto
			read -p "Indicate the port: " port
			iptables -A ${chain^^} -p $proto --dport $port -j DROP
			;;
		[Nn]* ) exit;;
		* ) echo "Answer yes or no"
	esac
done