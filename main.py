# fix ICMP 
#recurrent file 
#other type of request file example
#test with servers


import configparser
import subprocess
import json
from scapy.all import *
class Machine:
	def __init__(self, ip, ports_answers, recurrent_execute_path, reccurence, debug_mode):
		self.ip=ip
		self.ports_answers={port:path for port,path in ports_answers}
		self.reccurence=recurrence
		self.reccurent_execute_path=recurrent_execute_path
		self.debug_mode=debug_mode
def p2json(packet):
	packet_dict = {}
	for line in packet.show2(dump=True).split('\n'):
	    if '###' in line:
	        layer = line.strip('#[] ')
	        packet_dict[layer] = {}
	    elif '=' in line:
	        key, val = line.split('=', 1)
	        packet_dict[layer][key.strip()] = val.strip()
	return json.dumps(packet_dict)
def answer(packet,machine):
	print(p2json(packet))
	if packet.haslayer(TCP) or packet.haslayer(UDP):# if it is  tcp or udp
		dst_port = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport #take the port
		file=machine.ports_answers[dst_port]#take the associated file
	else: #it is icmp
		file="./icmp.sh"#take icmp default script and pass 
	print(file)
	if machine.debug_mode=="0":#
		subprocess.call(['bash', file,p2json(packet)])#execute file with packet as first argument
	else:
		print(subprocess.check_output([file,p2json(packet)]).decode())#execute file with output
nb=0
machines=[]
config = configparser.ConfigParser()
config.read('config.ini')
#taking the configuration for each machine
while config.has_section('machine_'+str(nb)):
	ip=config.get('machine_'+str(nb), 'ip'),
	ports_answers=[(el[0],el[1]) for couple in config.getint('machine_'+str(nb), 'ports_and_processes_answers_path').split('|') for el in couple.split(',')] if config.has_option('machine_'+str(nb),"ports_and_processes_answers_path") else []
	recurrence = config.get('machine_'+str(nb), 'recurrence_process_time_min')if config.has_option('machine_'+str(nb),"recurrence_process_time_min") else "0"
	recurrent_execute_path = config.get('machine_'+str(nb), 'recurrent_execute_path')if config.has_option('machine_'+str(nb),"recurrent_execute_path") else ""
	debug_mode = config.get('machine_'+str(nb),'debug_mode')if config.has_option('machine_'+str(nb),"debug_mode") else "0"
	machines.append(Machine(ip,ports_answers,recurrence,recurrent_execute_path,debug_mode))
	nb+=1
for machine in machines:# for all of the machine
	#if there is an icmp or a defined port packet (if we want to create a server) with as destination that ip execute the answer
	print(machine.ports_answers) 
	sniff(filter="ip dst "+machine.ip[0]+" and (icmp "+ "or dst port".join([str(port) for port in machine.ports_answers.keys()])+")",prn=lambda pkt: answer(pkt,machine))

