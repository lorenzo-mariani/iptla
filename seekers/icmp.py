import re


def find_icmp_attacks(path, regex):
    """
    Checks if there are attacks that exploit the ICMP protocol

    Args:
        path (str)   -- the path to the file containing the logs,
                        which is used to search for attacks
        regex (list) -- a list of regex used to select logs

    Returns:
        smurf_packets (list) -- a list of packets that perform a smurf attack
        icmp_packets (list)  -- a list of packets that perform an ICMP ping scan 
    """
    smurf_packets = []
    icmp_packets = []

    with open(path, 'r') as f:
        for line in f:
            if regex[0].search(line) and regex[1].search(line) and regex[2].search(line):
                if re.search("PROTO=ICMP", line):
                    if re.search("DST=192.168.1.255", line):
                        smurf_packets.append(line)
                    elif (re.search(" LEN=28 ", line)):
                        icmp_packets.append(line)
        
    return smurf_packets, icmp_packets