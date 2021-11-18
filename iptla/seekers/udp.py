import re


def find_udp_attacks(path, regex):
    """
    Checks if there are attacks that exploit the UDP protocol

    Args:
        path (str)   -- the path to the file containing the logs,
                        which is used to search for attacks
        regex (list) -- a list of regex used to select logs

    Returns:
        udp_packets (list) -- a list of packets that perform a UDP scan
    """
    udp_packets = []

    with open(path, 'r') as f:
        for line in f:
            if regex[0].search(line) and regex[1].search(line) and regex[2].search(line):
                if re.search("PROTO=UDP", line):
                    if re.search(" LEN=8 ",line) and not re.search("PROTO=ICMP",line):
                        udp_packets.append(line)
    
    return udp_packets
