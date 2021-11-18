import re
import os

from datetime import date

from iptla.utils.support_functions import check_path, write_to_txt, write_to_csv, write_to_json
from iptla.seekers.icmp import find_icmp_attacks
from iptla.seekers.udp import find_udp_attacks
from iptla.seekers.tcp import find_tcp_attacks


def find_attacks():
    """ Find possible attacks """
    # current date in the format month (short versione) and day, e.g., Dec 13
    today = date.today().strftime("%b %d")

    # regex used to select logs
    re_iptables = re.compile(r"IPTABLES")
    re_today = re.compile(today)
    re_loopback = re.compile("IN=[^lo]")

    regex = [re_iptables, re_today, re_loopback]

    path = os.path.join(os.path.abspath('var'), 'log', 'messages')
    check_path(path)

    null_packets, xmas_packets, fin_packets, ack_packets, syn_flood_packets, syn_connect_packets, syn_half_open_packets = find_tcp_attacks(path, regex)
    udp_packets = find_udp_attacks(path, regex)
    smurf_packets, icmp_packets = find_icmp_attacks(path, regex)

    write_to_txt(today==today, attack="TCP NULL SCAN", protocol="tcp", array=null_packets)
    write_to_txt(today==today, attack="TCP XMAS SCAN", protocol="tcp", array=xmas_packets)
    write_to_txt(today==today, attack="TCP FIN SCAN", protocol="tcp", array=fin_packets)
    write_to_txt(today==today, attack="TCP ACK SCAN", protocol="tcp", array=ack_packets)
    write_to_txt(today==today, attack="TCP SYN FLOOD", protocol="tcp", array=syn_flood_packets)
    write_to_txt(today==today, attack="TCP CONNECT SCAN", protocol="tcp", array=syn_connect_packets)
    write_to_txt(today==today, attack="TCP HALF-OPEN SCAN", protocol="tcp", array=syn_half_open_packets)
    write_to_txt(today=today, attack="UDP SCAN", protocol="udp", array=udp_packets)
    write_to_txt(today=today, attack="SMURF ATTACK", protocol="icmp", array=smurf_packets)
    write_to_txt(today=today, attack="ICMP PING SCAN", protocol="icmp", array=icmp_packets)
    
    write_to_csv(today==today, attack="TCP NULL SCAN", protocol="tcp", array=null_packets)
    write_to_csv(today==today, attack="TCP XMAS SCAN", protocol="tcp", array=xmas_packets)
    write_to_csv(today==today, attack="TCP FIN SCAN", protocol="tcp", array=fin_packets)
    write_to_csv(today==today, attack="TCP ACK SCAN", protocol="tcp", array=ack_packets)
    write_to_csv(today==today, attack="TCP SYN FLOOD", protocol="tcp", array=syn_flood_packets)
    write_to_csv(today==today, attack="TCP CONNECT SCAN", protocol="tcp", array=syn_connect_packets)
    write_to_csv(today==today, attack="TCP HALF-OPEN SCAN", protocol="tcp", array=syn_half_open_packets)
    write_to_csv(today=today, attack="UDP SCAN", protocol="udp", array=udp_packets)
    write_to_csv(today=today, attack="SMURF ATTACK", protocol="icmp", array=smurf_packets)
    write_to_csv(today=today, attack="ICMP PING SCAN", protocol="icmp", array=icmp_packets)

    write_to_json(today==today, attack="TCP NULL SCAN", protocol="tcp", array=null_packets)
    write_to_json(today==today, attack="TCP XMAS SCAN", protocol="tcp", array=xmas_packets)
    write_to_json(today==today, attack="TCP FIN SCAN", protocol="tcp", array=fin_packets)
    write_to_json(today==today, attack="TCP ACK SCAN", protocol="tcp", array=ack_packets)
    write_to_json(today==today, attack="TCP SYN FLOOD", protocol="tcp", array=syn_flood_packets)
    write_to_json(today==today, attack="TCP CONNECT SCAN", protocol="tcp", array=syn_connect_packets)
    write_to_json(today==today, attack="TCP HALF-OPEN SCAN", protocol="tcp", array=syn_half_open_packets)
    write_to_json(today=today, attack="UDP SCAN", protocol="udp", array=udp_packets)
    write_to_json(today=today, attack="SMURF ATTACK", protocol="icmp", array=smurf_packets)
    write_to_json(today=today, attack="ICMP PING SCAN", protocol="icmp", array=icmp_packets)
