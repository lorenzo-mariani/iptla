import re


def find_tcp_attacks(path, regex):
    """
    Checks if there are attacks that exploit the UDP protocol

    Args:
        path (str)   -- the path to the file containing the logs,
                        which is used to search for attacks
        regex (list) -- a list of regex used to select logs

    Returns:
        null_packets (list)          -- a list of packets that perform a TCP NULL scan
        xmas_packets (list)          -- a list of packets that perform a TCP XMAS scan
        fin_packets (list)           -- a list of packets that perform a TCP FIN scan
        ack_packets (list)           -- a list of packets that perform a TCP ACK scan
        syn_flood_packets (list)     -- a list of packets that perform a TCP SYN flood
        syn_connect_packets (list)   -- a list of packets that perform a TCP connect scan
        syn_half_open_packets (list) -- a list of packets that perform a TCP HALF-OPEN scan
    """
    null_packets = []
    xmas_packets = []
    fin_packets = []
    ack_packets = []
    syn_flood_packets = []
    syn_connect_packets = []
    syn_half_open_packets = []

    # regex to distinguish SYN flood from TCP connect() scan and 
    # TCP half-open scan. SYN flood has no "options" field, unlike
    # the other two attacks
    re_opt = re.compile(r"(OPT [(](\w+)[)]")

    with open(path, 'r') as f:
        for line in f:
            if regex[0].search(line) and regex[1].search(line) and regex[2].search(line):
                if re.search("PROTO=TCP", line):
                    # NULL Scan (flag -> none)
                    if not re.search(" ACK ",line) and \
                       not re.search(" SYN ",line) and \
                       not re.search(" FIN ",line) and \
                       not re.search(" URG ",line) and \
                       not re.search(" PSH ",line) and \
                       not re.search(" RST ",line):
                        null_packets.append(line)
                    
                    # XMAS Scan (flag -> URG, PSH, FIN)
                    elif re.search(" URG ",line) and \
                         re.search(" PSH ",line) and \
                         re.search(" FIN ",line) and not \
                         re.search(" ACK ",line) and not \
                         re.search(" SYN ",line) and not \
                         re.search(" RST ",line):
                        xmas_packets.append(line)
                    
                    # FIN Scan (flag -> FIN)
                    elif re.search(" FIN ",line) and not \
                         re.search(" SYN ",line) and not \
                         re.search(" ACK ",line) and not \
                         re.search(" URG ",line) and not \
                         re.search(" PSH ",line) and not \
                         re.search(" RST ",line):
                        fin_packets.append(line)
                    
                    # ACK Scan (flag -> ACK)
                    elif re.search(" ACK ",line) and not \
                         re.search(" SYN ",line) and not \
                         re.search(" FIN ",line) and not \
                         re.search(" URG ",line) and not \
                         re.search(" PSH ",line) and not \
                         re.search(" RST ",line):
                        ack_packets.append(line)
                    
                    # SYN flood (flag -> SYN) (many packets)
                    # Connect() Scan (flag -> SYN) (very long OPT)
                    # HALF-OPEN Scan (flag -> SYN) (very short OPT)
                    elif re.search(" SYN ",line) and not \
                         re.search(" ACK ",line) and not \
                         re.search(" FIN ",line) and not \
                         re.search(" URG ",line) and not \
                         re.search(" PSH ",line) and not \
                         re.search(" RST ",line):
                        if re.search(re_opt,line):
                            opt = (re.search(re_opt,line)).group(2)
                            if len(opt) > 10:
                                syn_connect_packets.append(line)
                            else:
                                syn_half_open_packets.append(line)
                        elif re.search("DPT=0",line):
                            syn_flood_packets.append(line)

    return null_packets, xmas_packets, fin_packets, ack_packets, syn_flood_packets, syn_connect_packets, syn_half_open_packets
