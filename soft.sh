#!/bin/bash

echo "Ricerca attacchi in corso .."
python3 ids.py
echo "Ricerca completata! Puoi trovare gli attacchi di oggi e dei giorni passati nel file \"attacks\"

while true: do
	read-p "Vuoi installare un pacchetto preconfigurato di iptables? " sn
	case $sn in
		[Ss]* ) echo "Installazione in corso ...";
			iptables -A OUTPUT -p udp --dport 5353 -j DROP # mDNS
			iptables -A OUTPUT -p udp --dport 1900 -j DROP # SSDP
			iptables -A OUTPUT -p tcp --dport 135 -j DROP # Microsoft RPC
			iptables -A OUTPUT -p udp --dport 123 -j DROP # NTP
			echo "Installazione completata!";
			break;;
		[Nn]* ) break;;
		* ) echo "Rsipondere si o no";;
	esac
done

while true; do
	read -p "Vuoi bloccare la comunicazione con altre porte? " sn
	case $sn in
		[Ss]* ) read -p "Indicare catena (PREROUTING, INPUT, FORWARD, POSTROUTING, OUTPUT): " chain
			read -p "Indicare protocollo: " proto
			read -p "Indicare porta: " port
			iptables -A ${chain^^} -p $proto --dport $port -j DROP
			;;
		[Nn]* ) exit;;
		* ) echo "Rispondere si o no"
	esac
done