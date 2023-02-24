#!/bin/bash

dst=$(echo "$1" | jq -r '.IP.dst')
src=$(echo "$1" | jq -r '.IP.src')
id=$(echo "$1" | jq -r '.ICMP.id')
seq=$(echo "$1" | jq -r '.ICMP.seq')
load=$(echo "$1" | jq -r '.Raw.load'|sed 's/"/\\"/g; s/'\''/'\'\\\''/g')
#load=$(echo "$load" | sed 's/\\/\\\\/g')
#load="hello"
echo "dst: $dst, id: $id, seq: $seq, data: $data"
packet=$(echo "IP(dst='$src', src='$dst')/ICMP(type=0,code=0,id=$id,seq=$seq)/Raw(load='$load')" | sed 's/"/\\\"/g')
echo "Packet: $packet"

# Send the packet
sudo python -c "from scapy.all import *; send($packet, iface='eth0')"
