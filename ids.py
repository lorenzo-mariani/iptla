import re
import pandas
import csv
import json
import os

# Ricerca della data corrente
today = (pandas.to_datetime("today")).strftime("%b %d")

class IDS:

	def search_for_attacks(self):

		# Regex per selezionare i log
		ipt_re = re.compile(r"IPTABLES")
		date_re = re.compile(today)
		lo_re = re.compile("IN=[^lo]")

		# Un vettore per ogni tipologia di attacco
		null_pkts = []
		xmas_pkts = []
		fin_pkts = []
		ack_pkts = []
		syn_f_pkts = []
		global syn_c_pkts
		global syn_ho_pkts
		syn_c_pkts = []
		syn_ho_pkts = []
		udp_pkts = []
		icmp_pkts = []
		smurf_pkts = []

		# Regex per distinguere SYN flood da TCP connect() sxan e TCP half-open scan
		# SYN flood non ha campo "options", a differenza degli altri due attacchi
		opt_re = re.compile(r"(OPT [(](\w+)[)]")

		# Lettura di "/var/log/messages" per la ricerca di possibili attacchi
		with open("/var/log/messages", "r") as f:
			for line in f:
				if (ipt_re.search(line) and date_re.search(line) and lo_re.search(line)):
					# Ricerca di TCP Scan
					if (re.search("PROTO=TCP",line)):
						# NULL Scan (flag -> none)
						if (not re.search(" ACK ",line) and not re.search(" SYN ",line) and not re.search(" FIN ",line) and not re.search(" URG ",line) and not re.search(" PSH ",line) and not re.search(" RST ",line)):
							null_pkts.append(line)
						# XMAS Scan (flag -> URG, PSH, FIN)
						elif (not re.search(" ACK ",line) and not re.search(" SYN ",line) and re.search(" FIN ",line) and re.search(" URG ",line) and re.search(" PSH ",line) and not re.search(" RST ",line)):
							xmas_pkts.append(line)
						# FIN Scan (flag -> FIN)
						elif (not re.search(" ACK ",line) and not re.search(" SYN ",line) and re.search(" FIN ",line) and not re.search(" URG ",line) and not re.search(" PSH ",line) and not re.search(" RST ",line)):
							fin_pkts.append(line)
						# ACK Scan (flag -> ACK)
						elif (re.search(" ACK ",line) and not re.search(" SYN ",line) and not re.search(" FIN ",line) and not re.search(" URG ",line) and not re.search(" PSH ",line) and not re.search(" RST ",line)):
							ack_pkts.append(line)
						# SYN flood (flag -> SYN) (molti pacchetti)
						# Connect() Scan (flag -> SYN) (OPT molto lungo)
						# HALF-OPEN Scan (flag -> SYN) (OPT molto corto)
						elif (not re.search(" ACK ",line) and re.search(" SYN ",line) and not re.search(" FIN ",line) and not re.search(" URG ",line) and not re.search(" PSH ",line) and not re.search(" RST ",line)):
							if (re.search(opt_re,line)):
								opt = ((re.search(opt_re,line)).group(2))
								if (len(opt) > 10):
									syn_c_pkts.append(line)
								else:
									syn_ho_pkts.append(line)
							elif (re.search("DPT=0",line)):
								syn_f_pkts.append(line)
					# Ricerca di UDP Scan
					elif (re.search("PROTO=UDP",line) and re.search(" LEN=8 ",line) and not re.search("PROTO=ICMP",line)):
						udp_pkts.append(line)
					# Ricerca di ICMP Ping Scan + attacco Smurf
					elif (re.search("PROTO=ICMP",line)):
						if(re.search("DST=192.168.1.255",line)):
							smurf_pkts.append(line)
						elif (re.search(" LEN=28 ",line)):
							icmp_pkts.append(line)

			self.write_attacks(null_pkts, "tcp", "TCP NULL SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP XMAS SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP FIN SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP ACK SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP CONNECT SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP HALF-OPEN SCAN")
			self.write_attacks(null_pkts, "tcp", "TCP SYN FLOOD")
			self.write_attacks(null_pkts, "udp", "UDP SCAN")
			self.write_attacks(null_pkts, "icmp", "ICMP PING SCAN")
			self.write_attacks(null_pkts, "icmp", "SMURF ATTACK")

	def write_attacks(self, array, proto, type):

		# Operazioni eseguite solo nei casi in cui e' stato rilevato un attacco
		if (len(array) != 0):

			ip_list = []		# IPsrc e IPdst dell'attacco
			time_list = []		# Orario di partenza dell'attacco
			pkt_list = []		# Pacchetti totali dell'attacco
			min_dport_list = []	# Valore minimo di porta DST scansionata
			max_dport_list = []	# Valore massimo di porta DST scansionata	

			dport_re = re.compile(r"(DPT=)(\d+)")

			# Lettura dei pacchetti presenti nel paramentro "array"
			for i in range(len(array)):

				# Vengono ricavati IPsrc-IPdst, orario completo e minuti
				ip_1 = (re.search(r"SRC=\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3} DST=\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}",array[i])).group(0)
				time_1 = (re.search("\d[2][:]\d[2][:]\d[2]",array[i])).group(0)
				min_1 = int(time_1[3:5])

				if proto != "icmp":
					dp = int()re.search(dport_re, array[i])).group(2))

				# Operazioni eseguite solo sul primo pacchetto di "array"
				if len(ip_list) == 0):
					ip_list.append(ip_1)
					time_list.append(time_1)
					pkt_list.append(1)
					if proto != "icmp":
						min_dport_list.append(dp)
						max_dport_list.append(dp)

				# Operazioni eseguite su tutti i pacchetti di "array" ad eccezione del primo
				else:
					for j in range (len(ip_list)):
						ip_2 = ip_list[j]
						time_2 = time_list[j]
						min_2 = int(time_2[3:5])
						min_2 = min_2 + 2
						if ((ip_1 == ip_2) and (time_1[0:2] == time_2[0:2]) and (min_1 <= min_2)):
							pkt_list[j] = pkt_list[j] + 1
							if proto != "icmp":
								if (dp > max_dport_list[j]):
									max_dport_list[j] = dp
								if (dp < min_dport_list[j]):
									min_dport_list[j] = dp

						elif (j == (len(ip_list) - 1)):
							ip_list.append(ip_1)
							time_list.append(time_1)
							pkt_list.append(1)
							if proto != "icmp":
								max_dport_list.append(dp)
								min_dport_list.append(dp)

			# Gli attacchi vengono riportati in un file "txt"
			with open("attacks.txt", "a") as out_a:
				for i in range(len(ip_list)):
					if (array != syn_c_pkts or array != syn_ho_pkts):
						count = str(int((pkt_list[i]) / 2))
					else:
						count = str(int(pkt_list[i]))
					if proto != "icmp":
						if (min_dport_list[i] == max_dport_list[i]):
							port_range = str(min_dport_list[i])
						else:
							port_range = str(min_dport_list[i]) + "-" + str(max_dport_list[i])
						scan = today + " " + time_list[i] + " possible " + type + " detected " + ip_list[i] + " p:[" + port_range + "] pkts: " + count + "\n"
					else:
						scan = today + " " + time_list[i] + " possible " + type + " detected " + ip_list[i] + " pkts: " + count + "\n"
					with open("attacks.txt", "r") as out_r:
						if scan not in out_r:
							out_a.write(scan)

			# Gli attacchi vengono riportati in un file "csv"
			file_exists = os.path.isfile("attacks.csv")
			with open("attacks.csv", a) as out_a:
				fields = ['[DATE]', ' [TIME]', ' [ATTACK]', ' [ADDRESSES]', ' [PORTS], ' [PACKETS]']
				writer = csv.DictWriter(out_a, fieldnames=fields)
				if (not file_exists):
					writer.writeheader()
				for i in range(len(ip_list)):
					if (array != syn_c_pkts or array != syn_ho_pkts):
						count = str(int((pkt_list[i]) / 2))
					else:
						count = str(int(pkt_list[i]))
					if proto != "icmp":
						port_range = str(min_dport_list[i]) + "-" + str(max_dport_list[i])
						writer.writerow({'[DATE]': today, ' [TIME]': time_list[i], ' [ATTACK]': type, ' [ADDRESSES]': ip_list[i], ' [PORTS]: port_range, ' [PACKETS]': count})
					else:
						writer.writerow({'[DATE]': today, ' [TIME]': time_list[i], ' [ATTACK]': type, ' [ADDRESSES]': ip_list[i], ' [PORTS]: "-", ' [PACKETS]': count})
			rows = open("attacks.csv").read().split("\n")
			newrows = []
			for row in rows:
				if row not in newrows:
					newrows.append(row)
			f = open("attacks.csv", "w")
			f.write("\n".join(newrows))
			f.close

			# Gli attacchi vengono riportati in un file "json"
			with open("attacks.json", "a") as out_a:
				k = 0
				tmp_list = []
				for t in time_list:
					t1 = t[0:5]
					t2 = t[0:2] + ":" + str(int(t[3:5] + 1)
					t3 = t[0:2] + ":" + str(int(t[3:5] + 2)
					if (array != syn_c_pkts or array != syn_ho_pkts):
						count = str(int((pkt_list[i]) / 2))
					else:
						count = str(int(pkt_list[i]))
					if proto != "icmp":
						for i in range(len(array)):
							if t1 in array[i] or t2 in array[i] or t3 in array[i]:
								dp = int((re.search(dport_re, array[i])).group(2))
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
						with open("attacks.json") as out_r:
							read_data = json.loads("[" + out_r.read().replace("}{", "},\n{") + "]")
							if data not in read_data:
								json.dump(data, out_a, indent=4)
check = IDS()
check.search_for_attacks()