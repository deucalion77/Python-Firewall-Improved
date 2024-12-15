import redis
from sniffer import IP, TCP, UDP
from packet import pack, dest_ip, ip_ihl_ver, ip_tos, ip_tos_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr
from sckt import create_receive_socket, create_icmp_send_socket
import socket

r = redis.Redis(host='localhost', port=6379, decode_responses=True)

def is_allowed(source_ip, destination_ip):
    keys = r.hgetall('firewall:query:3')
    for key in keys:
        rule = r.hgetall(key)
        # Check if rule matches the source and destination IPs and has "ALLOW" action
        if rule.get('action') == "ALLOW" and rule.get('source_ip') == source_ip and rule.get('destination_ip') == destination_ip:
            return True
    return False

s_receive = create_receive_socket()
send_icmp = create_icmp_send_socket()

try:
    while True:
        # Read a packet
        raw_packet = s_receive.recvfrom(65565)[0]
        r = raw_packet[34:]
        # Parse IP header
        ip_header = IP(raw_packet[14:34])
        print("Protocol: %s %s -> %s %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address, r))
    
        # Check if the packet is allowed based on Redis rules
        if is_allowed(ip_header.src_address, ip_header.dst_address):
            # Prepare packet to send
            sendpack = pack("!BBHHHBBH4s4s", ip_ihl_ver, ip_tos, ip_tos_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
            prevpk = sendpack
            restpk = raw_packet[34:]
            packet = prevpk + restpk
            # Send the packet if allowed
            send_icmp.sendto(packet, (dest_ip, 0))
            print(f"Packet sent to {ip_header.dst_address}")
        else:
            print(f"Packet from {ip_header.src_address} to {ip_header.dst_address} is not allowed. Dropping packet.")

except KeyboardInterrupt:
    pass
