import csv
import json
import os
import re


def check_path(path):
    """
    Checks if a path exists

    Args:
        path (str) -- the path to the file containing the logs,
                      which is used to search for attacks

    Raises:
        Exception -- an exception is raised if the path does
                     not exist
    """
    if not os.path.exists(path):
        raise Exception(f"ERROR: Reading From File: file {path} does not exist")


def get_data(array, protocol):
    """
    Gets the data associated with an attack

    Args:
        array (list)   -- a list of packets that perform an attack
        protocol (str) -- the protocol used by the attack (e.g., udp, tcp, icmp)

    Returns:
        ip_list (list)        -- a list of IPsrc e IPdst of the attack
        time_list (list)      -- start time of the attack
        packet_list (list)    -- total packets of the attack
        min_dport_list (list) -- minimum value of DST port scanned
        max_dport_list (list) -- maximum value of DST port scanned
    """
    ip_list = []
    time_list = []
    packet_list = []
    min_dport_list = []
    max_dport_list = []

    re_ip = re.compile(r"SRC=\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3} DST=\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}")
    re_time = re.compile("\d[2][:]\d[2][:]\d[2]")
    re_dport = re.compile(r"(DPT=)(\d+)")

    for i in range(len(array)):
        # IPsrc-IPdst, complete time and minutes are obtained
        ip_1 = (re.search(re_ip, array[i])).group(0)
        time_1 = (re.search(re_time, array[i])).group(0)
        min_1 = int(time_1[3:5])

        if protocol != "icmp":
            dp = int()((re.search(re_dport, array[i])).group(2))
        
        if len(ip_list) == 0:
            ip_list.append(ip_1)
            time_list.append(time_1)
            packet_list.append(1)

            if protocol != "icmp":
                min_dport_list.append(dp)
                max_dport_list.append(dp)
        else:
            for j in range (len(ip_list)):
                ip_2 = ip_list[j]
                time_2 = time_list[j]
                min_2 = int(time_2[3:5])
                min_2 = min_2 + 2

                if (ip_1 == ip_2) and (time_1[0:2] == time_2[0:2]) and (min_1 <= min_2):
                    packet_list[j] = packet_list[j] + 1

                    if protocol != "icmp":
                        if (dp > max_dport_list[j]):
                            max_dport_list[j] = dp
                        if (dp < min_dport_list[j]):
                            min_dport_list[j] = dp

                elif (j == (len(ip_list) - 1)):
                    ip_list.append(ip_1)
                    time_list.append(time_1)
                    packet_list.append(1)

                    if protocol != "icmp":
                        max_dport_list.append(dp)
                        min_dport_list.append(dp)

    return ip_list, time_list, packet_list, min_dport_list, max_dport_list


def write_to_txt(today, attack, protocol, array):
    """
    Writes attacks found in a .txt file

    Args:
        today (str)    -- the current date
        attack (str)   -- the name of the attack
        protocol (str) -- the protocol used by the attack (e.g., udp, tcp, icmp) 
        array (list)   -- a list of packets that perform an attack
    """
    if len(array) != 0:
        ip_list, time_list, packet_list, min_dport_list, max_dport_list = get_data(array, protocol)
        
        file_name = "attacks.txt"

        with open(file_name, 'a') as out_a:
            for i in range(len(ip_list)):
                if attack != 'TCP CONNECT SCAN' or attack != 'TCP HALF-OPEN SCAN':
                    count = str(int((packet_list[i]) / 2))
                else:
                    count = str(int(packet_list[i]))

                if protocol != "icmp":
                    if min_dport_list[i] == max_dport_list[i]:
                        port_range = str(min_dport_list[i])
                    else:
                        port_range = str(min_dport_list[i]) + "-" + str(max_dport_list[i])
                    scan = today + " " + time_list[i] + " possible " + type + " detected " + ip_list[i] + " p:[" + port_range + "] pkts: " + count + "\n"
                else:
                    scan = today + " " + time_list[i] + " possible " + type + " detected " + ip_list[i] + " pkts: " + count + "\n"
                
                with open(file_name,'r') as out_r:
                    if scan not in out_r:
                        out_a.write(scan)


def write_to_csv(today, attack, protocol, array):
    """
    Writes attacks found in a .csv file

    Args:
        today (str)    -- the current date
        attack (str)   -- the name of the attack
        protocol (str) -- the protocol used by the attack (e.g., udp, tcp, icmp) 
        array (list)   -- a list of packets that perform an attack
    """
    if len(array) != 0:
        ip_list, time_list, packet_list, min_dport_list, max_dport_list = get_data(array, protocol)
 
        file_name = "attacks.csv"
        file_exists = os.path.isfile(file_name)

        with open(file_name, 'a') as out_a:
            fields = ['[DATE]', ' [TIME]', ' [ATTACK]', ' [ADDRESSES]', ' [PORTS]', ' [PACKETS]']
            writer = csv.DictWriter(out_a, fieldnames=fields)

            if not file_exists:
                writer.writeheader()

            for i in range(len(ip_list)):
                if attack != 'TCP CONNECT SCAN' or attack != 'TCP HALF-OPEN SCAN':
                    count = str(int((packet_list[i]) / 2))
                else:
                    count = str(int(packet_list[i]))

                if protocol != "icmp":
                    port_range = str(min_dport_list[i]) + "-" + str(max_dport_list[i])
                    writer.writerow({'[DATE]': today, ' [TIME]': time_list[i], ' [ATTACK]': type, ' [ADDRESSES]': ip_list[i], ' [PORTS]': port_range, ' [PACKETS]': count})
                else:
                    writer.writerow({'[DATE]': today, ' [TIME]': time_list[i], ' [ATTACK]': type, ' [ADDRESSES]': ip_list[i], ' [PORTS]': "-", ' [PACKETS]': count})

        rows = open(file_name).read().split("\n")
        newrows = []

        for row in rows:
            if row not in newrows:
                newrows.append(row)
                
        f = open(file_name, "w")
        f.write("\n".join(newrows))
        f.close


def write_to_json(today, attack, protocol, array):
    """
    Writes attacks found in a .json file

    Args:
        today (str)    -- the current date
        attack (str)   -- the name of the attack
        protocol (str) -- the protocol used by the attack (e.g., udp, tcp, icmp) 
        array (list)   -- a list of packets that perform an attack
    """
    if len(array) != 0:
        ip_list, time_list, packet_list, min_dport_list, max_dport_list = get_data(array, protocol)
        file_name = "attacks.json"
        re_dport = re.compile(r"(DPT=)(\d+)")

        with open(file_name, 'a') as out_a:
            k = 0
            tmp_list = []

            for t in time_list:
                t1 = t[0:5]
                t2 = t[0:2] + ":" + str(int(t[3:5] + 1))
                t3 = t[0:2] + ":" + str(int(t[3:5] + 2))
                
                if attack != 'TCP CONNECT SCAN' or attack != 'TCP HALF-OPEN SCAN':
                    count = str(int((packet_list[i]) / 2))
                else:
                    count = str(int(packet_list[i]))
                
                if protocol != "icmp":
                    for i in range(len(array)):
                        if t1 in array[i] or t2 in array[i] or t3 in array[i]:
                            dp = int((re.search(re_dport, array[i])).group(2))
                            tmp_list.append(dp)
                    
                    tmp_list = list(dict.fromkeys(tmp_list))
                    tmp_list.sort()
                    
                    for j in range(len(tmp_list)):
                        dp_str = str(tmp_list[j])
                        tmp_list.pop(j)
                        tmp_list.insert(j, dp_str)
                    
                    str_join = "-".join(tmp_list)
                    data = {
                        'DATE': today,
                        'TIME': t,
                        'ATTACK': type,
                        'IPs': ip_list[k],
                        'PORTS': str_join,
                        'PACKETS': count
                        }
                else:
                    data = {
                        'DATE': today,
                        'TIME': t,
                        'ATTACK': type,
                        'IPs': ip_list[k],
                        'PORTS': "-",
                        'PACKETS': count
                        }
                    
                    del tmp_list[:]
                    k += 1
                    
                    with open(file_name) as out_r:
                        read_data = json.loads("[" + out_r.read().replace("}{", "},\n{") + "]")
                        
                        if data not in read_data:
                            json.dump(data, out_a, indent=4)
