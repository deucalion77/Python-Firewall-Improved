#! /usr/bin/python

import socket
from struct import *
from sckt import create_receive_socket
from sniffer import IP

s_receive = create_receive_socket()

raw_packet = s_receive.recvfrom(65565)[0]
ip_header = IP(raw_packet[14:34])
source_ip = ip_header.src_address
dest_ip = ip_header.dst_address

# ip header fielss
ip_ihl = 5
ip_ver = 4
ip_tos = 0
ip_tos_len = 0 # Kernal will fill the correct total length
ip_id = 54321  # ID of this packet
ip_frag_off = 0
ip_ttl = 255
ip_proto = 50
ip_check = 0 # Kernal will fill the correct checksum
ip_saddr = socket.inet_aton ( source_ip ) # spoof the source ip if u want to
ip_daddr = socket.inet_aton ( dest_ip )

# ICMP header

ip_ihl_ver = (ip_ver << 4) + ip_ihl

# packing the ip header
# the ! in the pack format string means network order
#ip_header = pack("!BBHHHBBH4s4s" , ip_ihl_ver, ip_tos, ip_tos_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
#packet = ip_header
#sendsock.sendto(packet, (dest_ip , 0))
