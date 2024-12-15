#! /usr/bin/python

from sniffer import IP, TCP, UDP
from packet import pack, source_ip, dest_ip, ip_ihl_ver, ip_tos, ip_tos_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr
from sckt import create_receive_socket, create_icmp_send_socket
import socket
import redis
import threading

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

s_receive = create_receive_socket()
send_icmp = create_icmp_send_socket()

try:
    while True:
        keys = r.scan_iter("firewall:query:*")
        #print(keys)
        for key in keys:
            key_type = r.type(key)#.decode()  # Check key type
            if key_type != 'hash':
                print(f"Skipping key {key} as it is not a hash.")
                continue
            
            rule = r.hgetall(key)
            action = rule.get('action','').upper()
            s_ip = rule.get('source_ip','')
            d_ip = rule.get('destination_ip','')

                
            # Read a packet
            raw_packet = s_receive.recvfrom(65565)[0]
            ip_header = IP(raw_packet[14:34])
            print("Protocol: %s %s -> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                
            packet = raw_packet[14:]
            print(f"s_ip: {s_ip}, d_ip: {d_ip},dest_ip: {dest_ip}, source_ip: {source_ip}")
            if action == "ALLOW" and s_ip == source_ip and d_ip == dest_ip:
                send_icmp.sendto(packet, (dest_ip, 0))
                print("pass 1")

            if action == "ALLOW" and s_ip == dest_ip and d_ip == source_ip:
                send_icmp.sendto(packet, (source_ip, 0))
                print("pass 2")


except KeyboardInterrupt:
    pass
